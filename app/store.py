"""SQLite state: inventory, CVE findings (with first/last seen), malware hits, runs, alert log."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Optional

from common import iso, parse_iso, sev_rank, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(
  target TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  image_id TEXT,
  sbom_path TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  last_seen_at TEXT,
  last_scan_at TEXT,
  last_ok_at TEXT,
  last_db_fp TEXT,
  fail_count INTEGER NOT NULL DEFAULT 0,
  next_try_at TEXT,
  last_error TEXT
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  vuln_id TEXT NOT NULL,
  pkg TEXT NOT NULL,
  version TEXT NOT NULL,
  cve_ids TEXT NOT NULL DEFAULT '[]',
  severity TEXT,
  cvss REAL,
  epss REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  ransomware INTEGER NOT NULL DEFAULT 0,
  fix_versions TEXT NOT NULL DEFAULT '[]',
  description TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  resolved_at TEXT,
  alerted_level INTEGER NOT NULL DEFAULT 0,
  UNIQUE(target, vuln_id, pkg, version)
);
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(resolved_at, severity);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE TABLE IF NOT EXISTS components(
  target TEXT NOT NULL,
  purl TEXT NOT NULL,
  PRIMARY KEY(target, purl)
);
CREATE INDEX IF NOT EXISTS idx_components_purl ON components(purl);
CREATE TABLE IF NOT EXISTS osv_cache(
  purl TEXT PRIMARY KEY,
  checked_at TEXT NOT NULL,
  mal_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS malware_hits(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  osv_id TEXT NOT NULL,
  purl TEXT NOT NULL,
  summary TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  resolved_at TEXT,
  alerted INTEGER NOT NULL DEFAULT 0,
  UNIQUE(target, osv_id, purl)
);
CREATE TABLE IF NOT EXISTS scan_runs(
  scan_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  targets_scanned TEXT NOT NULL DEFAULT '[]',
  targets_failed TEXT NOT NULL DEFAULT '[]',
  report_paths TEXT NOT NULL DEFAULT '[]',
  error TEXT
);
CREATE TABLE IF NOT EXISTS alert_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL,
  subject TEXT,
  recipients TEXT,
  item_count INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 1,
  error TEXT
);
CREATE TABLE IF NOT EXISTS kv(
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

FINDING_JSON_COLS = ("cve_ids", "fix_versions")


def _row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for col in FINDING_JSON_COLS:
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except ValueError:
                d[col] = []
    for col in ("kev", "ransomware", "active"):
        if col in d and d[col] is not None:
            d[col] = bool(d[col])
    return d


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ── low level ─────────────────────────────────────────────────────────────
    def _all(self, sql: str, args: Iterable = ()) -> list[dict]:
        with self._lock:
            return [_row(r) for r in self._db.execute(sql, tuple(args)).fetchall()]

    def _one(self, sql: str, args: Iterable = ()) -> Optional[dict]:
        rows = self._all(sql, args)
        return rows[0] if rows else None

    def _exec(self, sql: str, args: Iterable = ()) -> None:
        with self._lock:
            self._db.execute(sql, tuple(args))
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ── key/value ─────────────────────────────────────────────────────────────
    def kv_get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._one("SELECT value FROM kv WHERE key=?", (key,))
        return row["value"] if row else default

    def kv_set(self, key: str, value: str) -> None:
        self._exec(
            "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def kv_age(self, key: str, now: Optional[datetime] = None) -> Optional[timedelta]:
        ts = parse_iso(self.kv_get(key))
        return ((now or utcnow()) - ts) if ts else None

    # ── targets / inventory ───────────────────────────────────────────────────
    def get_target(self, target: str) -> Optional[dict]:
        return self._one("SELECT * FROM targets WHERE target=?", (target,))

    def list_targets(self, active_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM targets" + (" WHERE active=1" if active_only else "") + " ORDER BY target"
        return self._all(sql)

    def mark_inventory(self, source: str, targets: dict[str, Optional[str]], now: Optional[str] = None) -> None:
        """Record which targets of `source` currently exist. Missing ones become inactive.

        An empty discovery result never deactivates anything (it is usually a transient API error).
        """
        now = now or iso()
        with self._lock:
            for target, image_id in targets.items():
                self._db.execute(
                    "INSERT INTO targets(target,source,image_id,active,last_seen_at) VALUES(?,?,NULL,1,?) "
                    "ON CONFLICT(target) DO UPDATE SET active=1,last_seen_at=excluded.last_seen_at,source=excluded.source",
                    (target, source, now),
                )
            if targets:
                marks = ",".join("?" * len(targets))
                self._db.execute(
                    f"UPDATE targets SET active=0 WHERE source=? AND target NOT IN ({marks})",
                    (source, *targets.keys()),
                )
            self._db.commit()

    def pick_due(
        self,
        candidates: dict[str, tuple[str, Optional[str]]],
        db_fp: Optional[str],
        rescan_hours: int,
        limit: int,
        now: Optional[datetime] = None,
    ) -> list[dict]:
        """Choose up to `limit` targets that need a scan, most urgent first.

        candidates: {target: (source, current_image_id)}
        reason ranks: 0 = never scanned / image changed, 1 = vulnerability DB changed, 2 = periodic rescan.
        Targets in failure back-off are skipped.
        """
        now = now or utcnow()
        due: list[tuple[int, str, dict]] = []
        for target, (source, image_id) in candidates.items():
            row = self.get_target(target)
            next_try = parse_iso((row or {}).get("next_try_at"))
            if next_try and next_try > now:
                continue  # failure back-off
            if row is None or not row.get("last_ok_at"):
                reason, rank = "new", 0
            elif image_id and row.get("image_id") and image_id != row["image_id"]:
                reason, rank = "image-changed", 0
            elif db_fp and row.get("last_db_fp") != db_fp:
                reason, rank = "db-updated", 1
            else:
                last_ok = parse_iso(row["last_ok_at"])
                if last_ok and now - last_ok >= timedelta(hours=rescan_hours):
                    reason, rank = "periodic", 2
                else:
                    continue
            last = (row or {}).get("last_ok_at") or ""
            due.append((rank, last, {"target": target, "source": source, "image_id": image_id, "reason": reason}))
        due.sort(key=lambda x: (x[0], x[1]))
        return [d[2] for d in due[:limit]]

    def set_sbom(self, target: str, source: str, image_id: Optional[str], sbom_path: Optional[str]) -> None:
        self._exec(
            "INSERT INTO targets(target,source,image_id,sbom_path,active) VALUES(?,?,?,?,?) "
            "ON CONFLICT(target) DO UPDATE SET image_id=excluded.image_id, sbom_path=excluded.sbom_path",
            (target, source, image_id, sbom_path, 0 if source == "single" else 1),
        )

    def record_success(self, target: str, source: str, image_id: Optional[str], db_fp: Optional[str]) -> None:
        now = iso()
        active = 0 if source == "single" else 1
        self._exec(
            "INSERT INTO targets(target,source,image_id,active,last_scan_at,last_ok_at,last_db_fp,fail_count) "
            "VALUES(?,?,?,?,?,?,?,0) ON CONFLICT(target) DO UPDATE SET "
            "image_id=COALESCE(excluded.image_id, targets.image_id), last_scan_at=excluded.last_scan_at, "
            "last_ok_at=excluded.last_ok_at, last_db_fp=excluded.last_db_fp, fail_count=0, "
            "next_try_at=NULL, last_error=NULL",
            (target, source, image_id, active, now, now, db_fp),
        )

    def record_failure(self, target: str, source: str, error: str, backoff_hours: int, max_hours: int = 24) -> None:
        now = utcnow()
        row = self.get_target(target)
        fails = (row["fail_count"] if row else 0) + 1
        delay = min(backoff_hours * (2 ** (fails - 1)), max_hours)
        self._exec(
            "INSERT INTO targets(target,source,active,last_scan_at,fail_count,next_try_at,last_error) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(target) DO UPDATE SET last_scan_at=excluded.last_scan_at, "
            "fail_count=excluded.fail_count, next_try_at=excluded.next_try_at, last_error=excluded.last_error",
            (target, source, 0 if source == "single" else 1, iso(now), fails,
             iso(now + timedelta(hours=delay)), error[:500]),
        )

    def purge_inactive(self, older_than_days: int) -> list[str]:
        """Forget targets that have not existed for a long time (findings, components, malware hits)."""
        cutoff = iso(utcnow() - timedelta(days=older_than_days))
        rows = self._all(
            "SELECT target FROM targets WHERE active=0 AND COALESCE(last_seen_at, last_scan_at, '') < ?", (cutoff,)
        )
        names = [r["target"] for r in rows]
        with self._lock:
            for t in names:
                for table in ("findings", "components", "malware_hits", "targets"):
                    self._db.execute(f"DELETE FROM {table} WHERE target=?", (t,))
            self._db.commit()
        return names

    # ── findings / delta tracking ─────────────────────────────────────────────
    def ingest_findings(
        self,
        target: str,
        findings: list[dict],
        priority_fn: Callable[[dict], int],
        baseline: bool,
        now: Optional[str] = None,
    ) -> dict:
        """Merge a fresh scan result into the tracked state.

        Returns {"new": [...], "reopened": [...], "resolved": int, "persisting": int}.
        `baseline=True` marks findings up to PRIO_SEVERITY as already announced (first scan of a target →
        goes to the digest instead of flooding the mailbox). Actively exploited ones still alert.
        """
        now = now or iso()
        new: list[dict] = []
        reopened: list[dict] = []
        persisting = 0
        seen_keys: set[tuple] = set()
        with self._lock:
            existing = {
                (r["vuln_id"], r["pkg"], r["version"]): r
                for r in (_row(x) for x in self._db.execute("SELECT * FROM findings WHERE target=?", (target,)))
            }
            for f in findings:
                key = (f["vuln_id"], f["pkg"], f["version"])
                seen_keys.add(key)
                fields = (
                    json.dumps(f.get("cve_ids", [])), f.get("severity"), f.get("cvss"), f.get("epss"),
                    int(bool(f.get("kev"))), int(bool(f.get("ransomware"))),
                    json.dumps(f.get("fix_versions", [])), (f.get("description") or "")[:600],
                )
                prio = priority_fn(f)
                if key not in existing:
                    level = min(prio, 2) if baseline else 0
                    self._db.execute(
                        "INSERT INTO findings(target,vuln_id,pkg,version,cve_ids,severity,cvss,epss,kev,ransomware,"
                        "fix_versions,description,first_seen,last_seen,alerted_level) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (target, *key, *fields, now, now, level),
                    )
                    new.append(f)
                    continue
                row = existing[key]
                if row["resolved_at"]:
                    self._db.execute(
                        "UPDATE findings SET cve_ids=?,severity=?,cvss=?,epss=?,kev=?,ransomware=?,fix_versions=?,"
                        "description=?,first_seen=?,last_seen=?,resolved_at=NULL,alerted_level=0 WHERE id=?",
                        (*fields, now, now, row["id"]),
                    )
                    reopened.append(f)
                else:
                    persisting += 1
                    self._db.execute(
                        "UPDATE findings SET cve_ids=?,severity=?,cvss=?,epss=?,kev=?,ransomware=?,fix_versions=?,"
                        "description=?,last_seen=? WHERE id=?",
                        (*fields, now, row["id"]),
                    )
            resolved = 0
            for key, row in existing.items():
                if key not in seen_keys and not row["resolved_at"]:
                    self._db.execute("UPDATE findings SET resolved_at=? WHERE id=?", (now, row["id"]))
                    resolved += 1
            self._db.commit()
        return {"new": new, "reopened": reopened, "resolved": resolved, "persisting": persisting}

    def apply_kev(self, kev_ids: set[str]) -> int:
        """Flag open findings whose CVE just appeared in the KEV catalog (no rescan needed)."""
        if not kev_ids:
            return 0
        updated = 0
        with self._lock:
            rows = [_row(r) for r in self._db.execute("SELECT id,vuln_id,cve_ids FROM findings WHERE resolved_at IS NULL AND kev=0")]
            for r in rows:
                ids = set(r["cve_ids"]) | {r["vuln_id"]}
                if ids & kev_ids:
                    self._db.execute("UPDATE findings SET kev=1 WHERE id=?", (r["id"],))
                    updated += 1
            self._db.commit()
        return updated

    _OPEN_SQL = (
        "SELECT f.* FROM findings f JOIN targets t ON t.target=f.target "
        "WHERE f.resolved_at IS NULL AND t.active=1"
    )

    def open_findings(self, min_severity: Optional[str] = None, kev_only: bool = False) -> list[dict]:
        rows = self._all(self._OPEN_SQL)
        if min_severity:
            rows = [r for r in rows if sev_rank(r["severity"]) >= sev_rank(min_severity)]
        if kev_only:
            rows = [r for r in rows if r["kev"]]
        rows.sort(key=lambda r: (not r["kev"], -sev_rank(r["severity"]), -(r["epss"] or 0)))
        return rows

    def alertable_findings(self, priority_fn: Callable[[dict], int]) -> list[tuple[dict, int]]:
        out = []
        for r in self._all(self._OPEN_SQL):
            prio = priority_fn(r)
            if prio > 0 and prio > r["alerted_level"]:
                out.append((r, prio))
        out.sort(key=lambda x: (-x[1], -sev_rank(x[0]["severity"]), -(x[0]["epss"] or 0)))
        return out

    def mark_alerted(self, items: list[tuple[int, int]]) -> None:
        with self._lock:
            for fid, level in items:
                self._db.execute("UPDATE findings SET alerted_level=? WHERE id=?", (level, fid))
            self._db.commit()

    def findings_changed_since(self, ts: str) -> dict:
        new = self._all(
            "SELECT f.* FROM findings f JOIN targets t ON t.target=f.target WHERE t.active=1 AND f.first_seen>?", (ts,)
        )
        resolved = self._all(
            "SELECT f.* FROM findings f JOIN targets t ON t.target=f.target "
            "WHERE t.active=1 AND f.resolved_at IS NOT NULL AND f.resolved_at>?", (ts,)
        )
        return {"new": new, "resolved": resolved}

    # ── components / malware ──────────────────────────────────────────────────
    def set_components(self, target: str, purls: Iterable[str]) -> None:
        with self._lock:
            self._db.execute("DELETE FROM components WHERE target=?", (target,))
            self._db.executemany("INSERT OR IGNORE INTO components(target,purl) VALUES(?,?)", [(target, p) for p in purls])
            self._db.commit()

    def components_by_purl(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in self._all("SELECT c.purl, c.target FROM components c JOIN targets t ON t.target=c.target WHERE t.active=1"):
            out.setdefault(r["purl"], []).append(r["target"])
        return out

    def osv_cache(self, purls: Iterable[str]) -> dict[str, dict]:
        purls = list(purls)
        out: dict[str, dict] = {}
        for i in range(0, len(purls), 500):
            chunk = purls[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for r in self._all(f"SELECT purl,checked_at,mal_ids FROM osv_cache WHERE purl IN ({marks})", chunk):
                out[r["purl"]] = {"checked_at": r["checked_at"], "mal_ids": json.loads(r["mal_ids"])}
        return out

    def osv_cache_put(self, entries: dict[str, list[str]]) -> None:
        now = iso()
        with self._lock:
            self._db.executemany(
                "INSERT INTO osv_cache(purl,checked_at,mal_ids) VALUES(?,?,?) "
                "ON CONFLICT(purl) DO UPDATE SET checked_at=excluded.checked_at, mal_ids=excluded.mal_ids",
                [(p, now, json.dumps(ids)) for p, ids in entries.items()],
            )
            self._db.commit()

    def sync_malware_hits(self, current: dict[tuple[str, str, str], str]) -> list[dict]:
        """current: {(target, osv_id, purl): summary}. Returns newly appeared hits."""
        now = iso()
        new: list[dict] = []
        with self._lock:
            rows = {(r["target"], r["osv_id"], r["purl"]): _row(r)
                    for r in self._db.execute("SELECT * FROM malware_hits")}
            for key, summary in current.items():
                if key not in rows:
                    self._db.execute(
                        "INSERT INTO malware_hits(target,osv_id,purl,summary,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                        (*key, summary, now, now),
                    )
                    new.append({"target": key[0], "osv_id": key[1], "purl": key[2], "summary": summary})
                else:
                    r = rows[key]
                    self._db.execute(
                        "UPDATE malware_hits SET last_seen=?, summary=COALESCE(?,summary), resolved_at=NULL, "
                        "alerted=CASE WHEN resolved_at IS NOT NULL THEN 0 ELSE alerted END WHERE id=?",
                        (now, summary, r["id"]),
                    )
            for key, r in rows.items():
                if key not in current and not r["resolved_at"]:
                    self._db.execute("UPDATE malware_hits SET resolved_at=? WHERE id=?", (now, r["id"]))
            self._db.commit()
        return new

    def open_malware_hits(self) -> list[dict]:
        return self._all(
            "SELECT m.* FROM malware_hits m JOIN targets t ON t.target=m.target "
            "WHERE m.resolved_at IS NULL AND t.active=1 ORDER BY m.first_seen DESC"
        )

    def unalerted_malware_hits(self) -> list[dict]:
        return [m for m in self.open_malware_hits() if not m["alerted"]]

    def mark_malware_alerted(self, ids: list[int]) -> None:
        with self._lock:
            for i in ids:
                self._db.execute("UPDATE malware_hits SET alerted=1 WHERE id=?", (i,))
            self._db.commit()

    # ── scan runs / alert log ─────────────────────────────────────────────────
    def save_scan_run(self, run: dict) -> None:
        self._exec(
            "INSERT INTO scan_runs(scan_id,status,started_at,finished_at,targets_scanned,targets_failed,report_paths,error) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET status=excluded.status, "
            "finished_at=excluded.finished_at, targets_scanned=excluded.targets_scanned, "
            "targets_failed=excluded.targets_failed, report_paths=excluded.report_paths, error=excluded.error",
            (run["scan_id"], run["status"], run["started_at"], run.get("finished_at"),
             json.dumps(run.get("targets_scanned", [])), json.dumps(run.get("targets_failed", [])),
             json.dumps(run.get("report_paths", [])), run.get("error")),
        )

    def get_scan_run(self, scan_id: str) -> Optional[dict]:
        r = self._one("SELECT * FROM scan_runs WHERE scan_id=?", (scan_id,))
        return self._decode_run(r) if r else None

    def list_scan_runs(self, limit: int = 50) -> list[dict]:
        return [self._decode_run(r) for r in self._all("SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,))]

    @staticmethod
    def _decode_run(r: dict) -> dict:
        for col in ("targets_scanned", "targets_failed", "report_paths"):
            r[col] = json.loads(r[col]) if isinstance(r[col], str) else r[col]
        return r

    def log_alert(self, kind: str, subject: str, recipients: list[str], item_count: int, ok: bool, error: str = "") -> None:
        self._exec(
            "INSERT INTO alert_log(created_at,kind,subject,recipients,item_count,ok,error) VALUES(?,?,?,?,?,?,?)",
            (iso(), kind, subject, ",".join(recipients), item_count, int(ok), error[:500]),
        )

    def list_alerts(self, limit: int = 50) -> list[dict]:
        return self._all("SELECT * FROM alert_log ORDER BY id DESC LIMIT ?", (limit,))

    # ── housekeeping ──────────────────────────────────────────────────────────
    def prune_history(self, days: int = 180) -> None:
        cutoff = iso(utcnow() - timedelta(days=days))
        with self._lock:
            self._db.execute("DELETE FROM scan_runs WHERE started_at<?", (cutoff,))
            self._db.execute("DELETE FROM alert_log WHERE created_at<?", (cutoff,))
            self._db.execute("DELETE FROM osv_cache WHERE checked_at<?", (iso(utcnow() - timedelta(days=14)),))
            self._db.execute("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at<?", (cutoff,))
            self._db.commit()
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def stats(self) -> dict:
        rows = self.open_findings()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
        for r in rows:
            sev = (r["severity"] or "Unknown").title()
            counts[sev if sev in counts else "Unknown"] += 1
        return {
            "targets_active": len(self.list_targets(active_only=True)),
            "open_findings": len(rows),
            "open_by_severity": counts,
            "open_kev": sum(1 for r in rows if r["kev"]),
            "open_malware_hits": len(self.open_malware_hits()),
        }
