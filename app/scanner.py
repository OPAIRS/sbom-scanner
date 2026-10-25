"""Syft/Grype pipeline with isolated temp dirs, SBOM archive and delta ingestion."""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from common import alert_priority, iso, safe_name, sev_rank
from config import Settings
from store import Store

logger = logging.getLogger(__name__)

SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible")


class ScanError(Exception):
    pass


@dataclass
class ScanOutcome:
    target: str
    source: str
    ok: bool
    error: Optional[str] = None
    summary: Optional[dict] = None
    report_path: Optional[str] = None
    delta: dict = field(default_factory=dict)
    reused_sbom: bool = False
    duration_s: float = 0.0


# ── temp isolation ────────────────────────────────────────────────────────────

@contextmanager
def run_dir(cfg: Settings) -> Iterator[tuple[Path, dict]]:
    """Per-run scratch dir. TMPDIR and Syft's cache point inside it and it is always removed afterwards,
    so image exports of killed/timed-out Syft runs can no longer pile up in the container layer."""
    cfg.work_dir.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="run_", dir=cfg.work_dir))
    (path / "tmp").mkdir()
    (path / "cache").mkdir()
    env = os.environ.copy()
    env["TMPDIR"] = str(path / "tmp")
    env["SYFT_CACHE_DIR"] = str(path / "cache")
    # Grype's DB is refreshed explicitly by the scheduler; scans must not block on the network.
    if cfg.scheduler_enabled or cfg.offline:
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
    try:
        yield path, env
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _cmd(cfg: Settings, args: list[str]) -> list[str]:
    if cfg.scan_nice > 0 and shutil.which("nice"):
        return ["nice", "-n", str(cfg.scan_nice), *args]
    return args


# ── tools ─────────────────────────────────────────────────────────────────────

def run_syft(cfg: Settings, target: str, output_path: Path, env: dict) -> None:
    cmd = _cmd(cfg, ["syft", target, "-o", f"cyclonedx-json={output_path}", "--quiet"])
    logger.info(f"syft → {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.syft_timeout, env=env)
    except subprocess.TimeoutExpired:
        raise ScanError(f"syft timeout ({cfg.syft_timeout}s)")
    if result.returncode != 0 or not output_path.exists():
        raise ScanError(f"syft failed (exit {result.returncode}{_oom_hint(result.returncode)}): "
                        f"{result.stderr.strip()[:300]}")


def _oom_hint(returncode: int) -> str:
    """Exit -9 means SIGKILL, in a container almost always the kernel's out-of-memory killer."""
    return ", killed - probably out of memory, raise the container memory limit" if returncode == -9 else ""


def run_grype(cfg: Settings, sbom_path: Path, env: dict) -> dict:
    """Run Grype on an SBOM. Raises ScanError instead of returning an empty (= 'clean') result."""
    cmd = _cmd(cfg, ["grype", f"sbom:{sbom_path}", "-o", "json", "--quiet"])
    logger.info("grype → %s", sbom_path.name)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.grype_timeout, env=env)
    except subprocess.TimeoutExpired:
        raise ScanError(f"grype timeout ({cfg.grype_timeout}s)")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ScanError(f"grype produced no JSON (exit {result.returncode}{_oom_hint(result.returncode)}): "
                        f"{result.stderr.strip()[:300]}")


def update_grype_db(cfg: Settings) -> tuple[bool, Optional[str]]:
    """Refresh Grype's vulnerability DB. Returns (updated_ok, fingerprint of the DB now in use)."""
    ok = False
    if not cfg.offline:
        try:
            r = subprocess.run(_cmd(cfg, ["grype", "db", "update"]), capture_output=True, text=True, timeout=900)
            ok = r.returncode == 0
            if not ok:
                logger.warning(f"grype db update failed: {(r.stderr or r.stdout).strip()[:300]}")
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"grype db update error: {e}")
    return ok, grype_db_fingerprint()


def grype_db_fingerprint() -> Optional[str]:
    """Hash of `grype db status`, which changes whenever a different DB build is installed."""
    try:
        r = subprocess.run(["grype", "db", "status"], capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0 or not out:
        return None
    return hashlib.sha1(out.encode()).hexdigest()[:16]


# ── Grype output → normalized findings ────────────────────────────────────────

def _max_cvss(vuln: dict) -> Optional[float]:
    scores = []
    for c in vuln.get("cvss") or []:
        s = (c.get("metrics") or {}).get("baseScore")
        if isinstance(s, (int, float)):
            scores.append(float(s))
    return max(scores) if scores else None


def normalize_matches(grype_json: dict, kev_ids: Optional[set[str]] = None) -> list[dict]:
    """Deduplicated findings with CVE aliases, KEV/EPSS/CVSS (Grype's own fields + optional KEV feed)."""
    kev_ids = kev_ids or set()
    findings: dict[tuple, dict] = {}
    for m in grype_json.get("matches", []):
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue

        cves = [vuln_id] if vuln_id.startswith("CVE-") else []
        cves += [r["id"] for r in related if str(r.get("id", "")).startswith("CVE-") and r["id"] not in cves]

        exploited = list(vuln.get("knownExploited") or [])
        epss_values = [e.get("epss") for e in (vuln.get("epss") or []) if isinstance(e.get("epss"), (int, float))]
        cvss = _max_cvss(vuln)
        for r in related:
            exploited += list(r.get("knownExploited") or [])
            epss_values += [e.get("epss") for e in (r.get("epss") or []) if isinstance(e.get("epss"), (int, float))]
            if cvss is None:
                cvss = _max_cvss(r)

        key = (vuln_id, art.get("name") or "?", art.get("version") or "?")
        sev = (vuln.get("severity") or "Unknown").title()
        finding = {
            "vuln_id": vuln_id,
            "pkg": key[1],
            "version": key[2],
            "cve_ids": cves,
            "severity": sev if sev in SEVERITIES else "Unknown",
            "cvss": cvss,
            "epss": max(epss_values) if epss_values else None,
            "kev": bool(exploited) or bool(set(cves) & kev_ids),
            "ransomware": any(str(e.get("knownRansomwareCampaignUse", "")).lower() == "known" for e in exploited),
            "fix_versions": (vuln.get("fix") or {}).get("versions") or [],
            "description": (vuln.get("description") or "")[:600],
        }
        if key in findings:  # same package found at several locations → keep the worst
            prev = findings[key]
            if sev_rank(finding["severity"]) <= sev_rank(prev["severity"]) and not (finding["kev"] and not prev["kev"]):
                continue
        findings[key] = finding
    return list(findings.values())


def severity_counts(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


# ── SBOM archive ──────────────────────────────────────────────────────────────

def _image_key(image_id: Optional[str]) -> str:
    return (image_id or "noid").replace(":", "_").replace("/", "_")[:80]


def archive_sbom(cfg: Settings, target: str, image_id: Optional[str], sbom_path: Path) -> Path:
    """Keep the SBOM gzip-compressed, one file per distinct image id, newest N per target."""
    tdir = cfg.sbom_store / safe_name(target)
    tdir.mkdir(parents=True, exist_ok=True)
    dest = tdir / f"{_image_key(image_id)}.cdx.json.gz"
    if image_id is None:
        dest = tdir / f"noid-{time.strftime('%Y%m%d%H%M%S')}.cdx.json.gz"
    with open(sbom_path, "rb") as src, gzip.open(dest, "wb", compresslevel=6) as out:
        shutil.copyfileobj(src, out)
    prune_sbom_archive(tdir, cfg.sbom_keep_per_target)
    return dest


def prune_sbom_archive(tdir: Path, keep: int) -> int:
    files = sorted(tdir.glob("*.cdx.json.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for old in files[keep:]:
        try:
            old.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def gunzip(src: Path, dest: Path) -> None:
    with gzip.open(src, "rb") as f, open(dest, "wb") as out:
        shutil.copyfileobj(f, out)


def extract_purls(sbom_path: Path) -> list[str]:
    try:
        data = json.loads(sbom_path.read_text())
    except (OSError, ValueError):
        return []
    return sorted({c["purl"] for c in data.get("components", []) if c.get("purl")})


# ── one target, end to end ────────────────────────────────────────────────────

def scan_target(
    cfg: Settings,
    store: Store,
    target: str,
    source: str,
    image_id: Optional[str],
    *,
    db_fp: Optional[str] = None,
    kev_ids: Optional[set[str]] = None,
    threshold: str = "medium",
    scan_dir: Optional[Path] = None,
    force_syft: bool = False,
) -> ScanOutcome:
    """SBOM (re-used when the image is unchanged) → Grype → delta tracking → optional report file."""
    t0 = time.monotonic()
    row = store.get_target(target)
    cached: Optional[Path] = None
    if (not force_syft and row and row.get("sbom_path") and image_id
            and row.get("image_id") == image_id and Path(row["sbom_path"]).exists()):
        cached = Path(row["sbom_path"])

    try:
        with run_dir(cfg) as (work, env):
            sbom = work / "sbom.cdx.json"
            if cached:
                gunzip(cached, sbom)
                sbom_archive = cached
            else:
                run_syft(cfg, target, sbom, env)
                sbom_archive = archive_sbom(cfg, target, image_id, sbom)
                store.set_sbom(target, source, image_id, str(sbom_archive))
            grype_json = run_grype(cfg, sbom, env)
            purls = extract_purls(sbom)
    except ScanError as e:
        store.record_failure(target, source, str(e), cfg.fail_backoff_hours)
        return ScanOutcome(target, source, False, error=str(e), duration_s=time.monotonic() - t0)
    except Exception as e:  # noqa: BLE001 - never let one target kill a batch
        logger.exception(f"scan of {target} crashed")
        store.record_failure(target, source, f"{type(e).__name__}: {e}", cfg.fail_backoff_hours)
        return ScanOutcome(target, source, False, error=str(e), duration_s=time.monotonic() - t0)

    findings = normalize_matches(grype_json, kev_ids)
    first_scan = not (row and row.get("last_ok_at"))
    delta = store.ingest_findings(
        target, findings,
        priority_fn=lambda f: alert_priority(f, cfg.alert_min_severity, cfg.alert_on_kev, cfg.alert_epss_threshold),
        baseline=first_scan and not cfg.alert_on_first_scan,
    )
    store.set_components(target, [p for p in purls if is_osv_purl(p)])
    store.record_success(target, source, image_id, db_fp)

    counts = severity_counts(findings)
    threshold_rank = sev_rank(threshold)
    summary = {
        "target": target,
        "source": source,
        "scanned_at": iso(),
        "image_id": image_id,
        "sbom": str(sbom_archive),
        "total_vulnerabilities": len(findings),
        "severity_counts": counts,
        "exceeds_threshold": sum(1 for f in findings if sev_rank(f["severity"]) >= threshold_rank),
        "known_exploited": sum(1 for f in findings if f["kev"]),
        "new_findings": len(delta["new"]) + len(delta["reopened"]),
        "resolved_findings": delta["resolved"],
        "vulnerabilities": [
            {
                "id": f["vuln_id"], "severity": f["severity"], "package": f["pkg"], "version": f["version"],
                "fix_versions": f["fix_versions"], "description": f["description"][:200],
                "cve_ids": f["cve_ids"], "kev": f["kev"], "epss": f["epss"], "cvss": f["cvss"],
            }
            for f in findings
        ],
    }
    report_path = None
    if scan_dir is not None:
        scan_dir.mkdir(parents=True, exist_ok=True)
        report = scan_dir / f"vulns_{source}_{safe_name(target)}.json"
        report.write_text(json.dumps(summary, indent=2))
        report_path = str(report)
    return ScanOutcome(target, source, True, summary=summary, report_path=report_path, delta=delta,
                       reused_sbom=bool(cached), duration_s=time.monotonic() - t0)


OSV_ECOSYSTEMS = ("pkg:npm/", "pkg:pypi/", "pkg:cargo/", "pkg:gem/", "pkg:golang/", "pkg:maven/", "pkg:nuget/")


def is_osv_purl(purl: str) -> bool:
    """Only versioned purls of ecosystems that OSV tracks malicious packages for."""
    return purl.startswith(OSV_ECOSYSTEMS) and "@" in purl
