"""Configuration — environment variables only (see README for the full table)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _secret(name: str, default: str = "") -> str:
    """Value of NAME, or the content of the file named by NAME_FILE (Docker secrets)."""
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text().strip()
        except OSError:
            return default
    return os.getenv(name, default)


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    # ── paths ────────────────────────────────────────────────────────────────
    report_dir: Path = Path("/data/sbom-reports")
    data_dir: Path = Path("/data/sbom-data")          # state db, SBOM archive, temp work dirs

    # ── scanning (unchanged from v1.1) ───────────────────────────────────────
    scan_sources: list[str] = field(default_factory=list)
    syft_timeout: int = 900
    grype_timeout: int = 600
    kubeconfig: str = "/root/.kube/config"
    scan_nice: int = 10                               # run syft/grype at lower CPU priority

    # ── continuous operation ─────────────────────────────────────────────────
    scheduler_enabled: bool = True
    scheduler_targets: list[str] = field(default_factory=lambda: ["images", "filesystem", "k8s"])
    tick_seconds: int = 300
    batch_size: int = 2                               # targets per tick ("small patches")
    batch_pause_seconds: int = 30                     # pause after a tick that scanned something
    rescan_hours: int = 24
    db_update_hours: int = 6
    fail_backoff_hours: int = 1                       # doubles per consecutive failure, capped at 24h
    offline: bool = False                             # no outbound calls (DB update, KEV, OSV)

    # ── retention / disk ─────────────────────────────────────────────────────
    report_keep_days: int = 30
    report_max_scans: int = 100
    sbom_keep_per_target: int = 3
    data_budget_gb: float = 10.0                      # soft cap for reports + SBOM archive + work dir
    work_stale_minutes: int = 60

    # ── alert policy ─────────────────────────────────────────────────────────
    alert_min_severity: str = "Critical"
    alert_on_kev: bool = True
    alert_epss_threshold: float = 0.5                 # High + EPSS >= x also alerts; 0 disables
    alert_on_first_scan: bool = False                 # first scan of a target goes to the digest, not instant mail
    alert_min_interval_minutes: int = 30
    alert_max_items: int = 25

    # ── mail ─────────────────────────────────────────────────────────────────
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    mail_from: str = ""
    mail_to: list[str] = field(default_factory=list)
    report_lang: str = "de"
    report_tz: str = "UTC"
    report_host_label: str = ""
    digest_enabled: bool = True
    digest_hour: int = 7

    # ── external feeds ───────────────────────────────────────────────────────
    http_timeout: int = 30
    kev_enabled: bool = True
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_refresh_hours: int = 6
    osv_enabled: bool = True
    osv_url: str = "https://api.osv.dev"
    osv_recheck_hours: int = 6

    # ── local SLM (CPU, OpenAI-compatible server such as llama.cpp) ──────────
    slm_url: str = ""
    slm_model: str = "local"
    slm_timeout: int = 90
    slm_max_items: int = 5

    # ── API ──────────────────────────────────────────────────────────────────
    api_key: str = ""

    # derived paths --------------------------------------------------------
    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "sbom-scanner.db"

    @property
    def sbom_store(self) -> Path:
        return self.data_dir / "sbom-store"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def mail_configured(self) -> bool:
        return bool(self.smtp_host and self.mail_from and self.mail_to)

    def ensure_dirs(self) -> None:
        for p in (self.report_dir, self.state_dir, self.sbom_store, self.work_dir):
            p.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "Settings":
        offline = _bool("OFFLINE_MODE", False)
        smtp_ssl = _bool("SMTP_SSL", False)
        return cls(
            report_dir=Path(os.getenv("REPORT_DIR", "/data/sbom-reports")),
            data_dir=Path(os.getenv("DATA_DIR", "/data/sbom-data")),
            scan_sources=_list("SCAN_SOURCES"),
            syft_timeout=_int("SYFT_TIMEOUT", 900),
            grype_timeout=_int("GRYPE_TIMEOUT", 600),
            kubeconfig=os.getenv("KUBECONFIG", "/root/.kube/config"),
            scan_nice=_int("SCAN_NICE", 10),
            scheduler_enabled=_bool("SCHEDULER_ENABLED", True),
            scheduler_targets=_list("SCHEDULER_TARGETS", "images,filesystem,k8s"),
            tick_seconds=max(10, _int("TICK_SECONDS", 300)),
            batch_size=max(1, _int("BATCH_SIZE", 2)),
            batch_pause_seconds=max(0, _int("BATCH_PAUSE_SECONDS", 30)),
            rescan_hours=max(1, _int("RESCAN_HOURS", 24)),
            db_update_hours=max(1, _int("DB_UPDATE_HOURS", 6)),
            fail_backoff_hours=max(1, _int("FAIL_BACKOFF_HOURS", 1)),
            offline=offline,
            report_keep_days=max(1, _int("REPORT_KEEP_DAYS", 30)),
            report_max_scans=max(3, _int("REPORT_MAX_SCANS", 100)),
            sbom_keep_per_target=max(1, _int("SBOM_KEEP_PER_TARGET", 3)),
            data_budget_gb=_float("DATA_BUDGET_GB", 10.0),
            work_stale_minutes=max(5, _int("WORK_STALE_MINUTES", 60)),
            alert_min_severity=os.getenv("ALERT_MIN_SEVERITY", "Critical").strip().title(),
            alert_on_kev=_bool("ALERT_ON_KEV", True),
            alert_epss_threshold=_float("ALERT_EPSS_THRESHOLD", 0.5),
            alert_on_first_scan=_bool("ALERT_ON_FIRST_SCAN", False),
            alert_min_interval_minutes=max(1, _int("ALERT_MIN_INTERVAL_MINUTES", 30)),
            alert_max_items=max(5, _int("ALERT_MAX_ITEMS", 25)),
            smtp_host=os.getenv("SMTP_HOST", ""),
            smtp_port=_int("SMTP_PORT", 465 if smtp_ssl else 587),
            smtp_user=os.getenv("SMTP_USER", ""),
            smtp_password=_secret("SMTP_PASSWORD"),
            smtp_starttls=_bool("SMTP_STARTTLS", True),
            smtp_ssl=smtp_ssl,
            mail_from=os.getenv("MAIL_FROM", ""),
            mail_to=_list("MAIL_TO"),
            report_lang=os.getenv("REPORT_LANG", "de").strip().lower()[:2] or "de",
            report_tz=os.getenv("REPORT_TZ", "UTC"),
            report_host_label=os.getenv("REPORT_HOST_LABEL", ""),
            digest_enabled=_bool("DIGEST_ENABLED", True),
            digest_hour=min(23, max(0, _int("DIGEST_HOUR", 7))),
            http_timeout=_int("HTTP_TIMEOUT", 30),
            kev_enabled=_bool("KEV_ENABLED", True) and not offline,
            kev_url=os.getenv("KEV_URL", Settings.kev_url),
            kev_refresh_hours=max(1, _int("KEV_REFRESH_HOURS", 6)),
            osv_enabled=_bool("OSV_ENABLED", True) and not offline,
            osv_url=os.getenv("OSV_URL", Settings.osv_url).rstrip("/"),
            osv_recheck_hours=max(1, _int("OSV_RECHECK_HOURS", 6)),
            slm_url=os.getenv("SLM_URL", "").rstrip("/"),
            slm_model=os.getenv("SLM_MODEL", "local"),
            slm_timeout=_int("SLM_TIMEOUT", 90),
            slm_max_items=max(0, _int("SLM_MAX_ITEMS", 5)),
            api_key=_secret("API_KEY"),
        )
