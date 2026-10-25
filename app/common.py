"""Shared helpers: time handling, severity ranking, alert policy."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Negligible": 0, "Unknown": -1}

# Alert priority levels (higher = more urgent). Stored per finding as `alerted_level`
# so a finding is re-announced only when it escalates (e.g. High -> now in CISA KEV).
PRIO_NONE = 0
PRIO_EPSS = 1      # High severity + high exploit probability
PRIO_SEVERITY = 2  # severity >= ALERT_MIN_SEVERITY (default: Critical)
PRIO_KEV = 3       # Actively exploited (CISA KEV)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).replace(microsecond=0).isoformat()


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def sev_rank(severity: Optional[str]) -> int:
    return SEV_ORDER.get((severity or "Unknown").title(), -1)


def safe_name(target: str) -> str:
    """Filesystem-safe name for a scan target (stable, collision-resistant when truncated)."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"
    if len(name) > 100:
        name = name[:90] + "_" + hashlib.sha1(target.encode()).hexdigest()[:8]
    return name


def alert_priority(finding: dict, min_severity: str, on_kev: bool, epss_threshold: float) -> int:
    """Decide how urgent a finding is. 0 = not alert-worthy."""
    if on_kev and finding.get("kev"):
        return PRIO_KEV
    rank = sev_rank(finding.get("severity"))
    if rank >= sev_rank(min_severity):
        return PRIO_SEVERITY
    if epss_threshold > 0 and rank >= sev_rank("High") and (finding.get("epss") or 0) >= epss_threshold:
        return PRIO_EPSS
    return PRIO_NONE
