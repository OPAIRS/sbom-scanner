"""External threat feeds: CISA KEV (actively exploited CVEs) and OSV malicious-package advisories.

Both are optional. With OFFLINE_MODE=true (or *_ENABLED=false) nothing leaves the host; the scanner then
relies on the KEV/EPSS data that is already inside Grype's vulnerability DB.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

from common import iso, utcnow
from config import Settings
from store import Store

logger = logging.getLogger(__name__)

USER_AGENT = "sbom-scanner/2 (+https://github.com/OPAIRS/sbom-scanner)"
OSV_BATCH = 1000


def _http_json(url: str, timeout: int, payload: Optional[dict] = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL comes from operator config
        return json.loads(resp.read().decode("utf-8"))


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def load_kev_ids(store: Store) -> set[str]:
    raw = store.kv_get("kev_ids")
    return set(json.loads(raw)) if raw else set()


def refresh_kev(cfg: Settings, store: Store) -> set[str]:
    """Download the KEV catalog (at most every KEV_REFRESH_HOURS) and flag matching open findings.

    Returns CVE ids that are new in the catalog since the last refresh.
    """
    if not cfg.kev_enabled:
        return set()
    age = store.kv_age("kev_refreshed_at")
    if age is not None and age.total_seconds() < cfg.kev_refresh_hours * 3600:
        return set()
    try:
        data = _http_json(cfg.kev_url, cfg.http_timeout)
        ids = {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        logger.warning(f"KEV refresh failed: {e}")
        return set()
    if not ids:
        return set()
    previous = load_kev_ids(store)
    store.kv_set("kev_ids", json.dumps(sorted(ids)))
    store.kv_set("kev_refreshed_at", iso())
    fresh = ids - previous if previous else set()
    flagged = store.apply_kev(ids)
    if flagged:
        logger.warning(f"{flagged} open finding(s) are now listed in CISA KEV")
    return fresh


# ── OSV malicious packages (supply-chain attacks) ─────────────────────────────

def _osv_query_batch(cfg: Settings, purls: list[str]) -> list[list[str]]:
    """MAL-* advisory ids per purl. Pagination is ignored: malware advisories are rare per package."""
    payload = {"queries": [{"package": {"purl": p}} for p in purls]}
    data = _http_json(f"{cfg.osv_url}/v1/querybatch", cfg.http_timeout, payload)
    results = data.get("results", [])
    if len(results) != len(purls):
        raise ValueError(f"OSV returned {len(results)} results for {len(purls)} queries")
    return [sorted({v["id"] for v in (r.get("vulns") or []) if str(v.get("id", "")).startswith("MAL-")}) for r in results]


def _osv_summary(cfg: Settings, store: Store, osv_id: str) -> str:
    cached = store.kv_get(f"osv:{osv_id}")
    if cached is not None:
        return cached
    try:
        data = _http_json(f"{cfg.osv_url}/v1/vulns/{osv_id}", cfg.http_timeout)
        summary = (data.get("summary") or (data.get("details") or "")[:300]).strip()
    except (urllib.error.URLError, OSError, ValueError):
        return ""
    store.kv_set(f"osv:{osv_id}", summary)
    return summary


def check_malicious_packages(cfg: Settings, store: Store) -> list[dict]:
    """Check all tracked npm/PyPI/crates/gem/Go/Maven/NuGet components against OSV's malware advisories.

    Runs independently of image scans, so a package that is reported malicious *after* the image was
    scanned is still caught within OSV_RECHECK_HOURS. Returns newly detected hits.
    """
    if not cfg.osv_enabled:
        return []
    by_purl = store.components_by_purl()
    if not by_purl:
        store.sync_malware_hits({})
        return []

    cache = store.osv_cache(by_purl.keys())
    cutoff = utcnow().timestamp() - cfg.osv_recheck_hours * 3600
    stale = [
        p for p in by_purl
        if p not in cache or _ts(cache[p]["checked_at"]) < cutoff
    ]
    try:
        for i in range(0, len(stale), OSV_BATCH):
            chunk = stale[i:i + OSV_BATCH]
            store.osv_cache_put(dict(zip(chunk, _osv_query_batch(cfg, chunk))))
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.warning(f"OSV check failed: {e}")
        return []  # keep previous hit state; try again next tick

    cache = store.osv_cache(by_purl.keys())
    current: dict[tuple[str, str, str], str] = {}
    for purl, entry in cache.items():
        for osv_id in entry["mal_ids"]:
            summary = _osv_summary(cfg, store, osv_id)
            for target in by_purl.get(purl, []):
                current[(target, osv_id, purl)] = summary
    new = store.sync_malware_hits(current)
    if new:
        logger.warning(f"{len(new)} new malicious-package hit(s) via OSV")
    return new


def _ts(value: str) -> float:
    from common import parse_iso

    dt = parse_iso(value)
    return dt.timestamp() if dt else 0.0
