import asyncio
import functools
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

import feeds
import inventory
import reporting
import retention
import scanner
from common import iso, utcnow
from config import Settings
from scheduler import Scheduler
from slm import SlmClient
from store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

VERSION = "2.0.0"

cfg = Settings.from_env()
cfg.ensure_dirs()
store = Store(cfg.db_path)
slm = SlmClient(cfg)
scan_lock = asyncio.Lock()          # one scan at a time (scheduler and manual jobs share it)
scheduler = Scheduler(cfg, store, scan_lock, slm)

running_scans: dict[str, dict] = {}
SCAN_ID_RE = re.compile(r"^scan_[A-Za-z0-9_]+$")


async def require_key(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optional API protection: set API_KEY and send it as X-API-Key. /health stays open for probes."""
    if not cfg.api_key or request.url.path == "/health":
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, cfg.api_key):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(scheduler.run_forever()) if cfg.scheduler_enabled else None
    yield
    if task:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    store.close()


app = FastAPI(
    title="SBOM Scanner",
    version=VERSION,
    description="On-premise SBOM generation (Syft) + CVE scanning (Grype) with REST API, continuous CVE tracking, "
                "mail alerts for actively exploited vulnerabilities and supply-chain malware. "
                "Supports Docker images, Kubernetes pods, and filesystem paths.",
    lifespan=lifespan,
    dependencies=[Depends(require_key)],
)


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    """
    What to scan:
    - "images"     — all running Docker container images
    - "filesystem" — paths defined in SCAN_SOURCES env var
    - "k8s"        — all Kubernetes pod images (requires KUBECONFIG)
    - "all"        — images + filesystem + k8s
    - "<image:tag>"   — a specific Docker image
    - "</path/to/dir>" — a specific filesystem path
    """
    severity_threshold: Optional[str] = "medium"
    """Reported in the summary as `exceeds_threshold`: low | medium | high | critical"""
    k8s_namespace: Optional[str] = None
    """Kubernetes namespace filter. None = all namespaces."""
    force: bool = False
    """Regenerate the SBOM even if the image is unchanged since the last scan."""


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    targets_scanned: list[str] = []
    targets_failed: list[str] = []
    report_paths: list[str] = []
    error: Optional[str] = None


# ── Manual scan job ───────────────────────────────────────────────────────────

def _persist(scan_id: str) -> None:
    store.save_scan_run(running_scans[scan_id])


def _new_scan_id() -> str:
    base = f"scan_{utcnow().strftime('%Y%m%d_%H%M%S')}"
    scan_id, n = base, 1
    while scan_id in running_scans or (cfg.report_dir / scan_id).exists():
        n += 1
        scan_id = f"{base}_{n}"
    return scan_id


def _plan_targets(request: ScanRequest, scan_dir: Path) -> list[tuple[str, str, Optional[str]]]:
    """[(target, source label, image id)] for a manual scan request."""
    plan: list[tuple[str, str, Optional[str]]] = []
    docker_tags: set[str] = set()

    if request.target in ("images", "all", "k8s"):
        try:
            docker_inv = inventory.get_running_docker_inventory()
        except Exception as e:  # noqa: BLE001
            logger.error(f"Docker API error: {e}")
            docker_inv = {}
        docker_tags = set(docker_inv)
        if request.target in ("images", "all"):
            plan += [(tag, "docker", image_id) for tag, image_id in docker_inv.items()]

    if request.target in ("k8s", "all"):
        ns_images = inventory.get_k8s_images(cfg.kubeconfig, request.k8s_namespace)
        if ns_images:
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "k8s_namespace_map.json").write_text(json.dumps(ns_images, indent=2))
            try:
                digests = inventory.get_k8s_inventory(cfg.kubeconfig, request.k8s_namespace)
            except Exception:  # noqa: BLE001 - digests are an optimisation only
                digests = {}
            unique = [img for img in inventory.flatten_k8s_images(ns_images) if img not in docker_tags]
            logger.info(f"K8s: {len(inventory.flatten_k8s_images(ns_images))} total, {len(unique)} unique (not in Docker)")
            plan += [(img, "k8s", digests.get(img)) for img in unique]
        else:
            logger.warning("K8s scan requested but no images found")

    if request.target in ("filesystem", "all"):
        plan += [(p, "filesystem", None) for p in cfg.scan_sources if Path(p).exists()]

    if request.target not in ("images", "filesystem", "k8s", "all"):
        image_id = None if request.target.startswith("/") else inventory.get_docker_image_id(request.target)
        plan.append((request.target, "single", image_id))
    return plan


async def run_scan_job(scan_id: str, request: ScanRequest):
    loop = asyncio.get_running_loop()
    run = running_scans[scan_id]
    async with scan_lock:
        run["status"] = "running"
        _persist(scan_id)
        results: list[dict] = []
        report_paths: list[str] = []
        failed: list[str] = []
        try:
            scan_dir = cfg.report_dir / scan_id
            scan_dir.mkdir(parents=True, exist_ok=True)
            plan = await loop.run_in_executor(None, _plan_targets, request, scan_dir)
            run["targets_scanned"] = [t for t, _, _ in plan]
            _persist(scan_id)

            if not plan:
                run.update(status="failed", error="No scan targets found", finished_at=iso())
                _persist(scan_id)
                return

            kev_ids = feeds.load_kev_ids(store)
            db_fp = store.kv_get("db_fp")
            for target, source, image_id in plan:
                outcome = await loop.run_in_executor(None, functools.partial(
                    scanner.scan_target, cfg, store, target, source, image_id,
                    db_fp=db_fp, kev_ids=kev_ids, threshold=request.severity_threshold or "medium",
                    scan_dir=scan_dir, force_syft=request.force,
                ))
                if outcome.ok:
                    results.append(outcome.summary)
                    report_paths.append(outcome.report_path)
                else:
                    failed.append(target)

            sources = sorted({r["source"] for r in results})

            def total(key: str, rows: list[dict]) -> int:
                return sum(r["severity_counts"].get(key, 0) for r in rows)

            consolidated = {
                "scan_id":        scan_id,
                "scanned_at":     utcnow().strftime("%Y%m%d_%H%M%S"),
                "targets_ok":     [t for t, _, _ in plan if t not in failed],
                "targets_failed": failed,
                "results":        results,
                "total_critical": total("Critical", results),
                "total_high":     total("High", results),
                "total_medium":   total("Medium", results),
                "total_known_exploited": sum(r["known_exploited"] for r in results),
                "total_new_findings":    sum(r["new_findings"] for r in results),
                "by_source": {
                    src: {
                        "total_critical": total("Critical", [r for r in results if r["source"] == src]),
                        "total_high":     total("High",     [r for r in results if r["source"] == src]),
                        "total_medium":   total("Medium",   [r for r in results if r["source"] == src]),
                    }
                    for src in sources
                },
            }
            summary_path = scan_dir / "summary.json"
            summary_path.write_text(json.dumps(consolidated, indent=2))
            report_paths.append(str(summary_path))

            run.update(status="completed", report_paths=report_paths, targets_failed=failed, finished_at=iso())
            _persist(scan_id)
            logger.info(f"Scan {scan_id} completed. Failed targets: {failed}")

        except Exception as e:  # noqa: BLE001
            logger.exception(f"Scan {scan_id} crashed: {e}")
            run.update(status="failed", error=str(e), finished_at=iso())
            _persist(scan_id)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "sbom-scanner", "version": VERSION}


@app.get("/status")
def status():
    """Operational overview: scheduler, vulnerability DB, open findings, disk, mail and SLM."""
    return {
        "version": VERSION,
        "scheduler": {"enabled": cfg.scheduler_enabled, **scheduler.state},
        "vulnerability_db": {
            "fingerprint": store.kv_get("db_fp"),
            "updated_at": store.kv_get("db_updated_at"),
            "kev_refreshed_at": store.kv_get("kev_refreshed_at"),
        },
        "findings": store.stats(),
        "disk": retention.disk_usage(cfg),
        "mail": {"configured": cfg.mail_configured, "recipients": len(cfg.mail_to),
                 "last_alert_at": store.kv_get("last_alert_sent_at"), "last_digest_at": store.kv_get("last_digest_at")},
        "slm": {"enabled": slm.enabled, "healthy": slm.healthy() if slm.enabled else False},
        "feeds": {"kev": cfg.kev_enabled, "osv_malware": cfg.osv_enabled, "offline": cfg.offline},
    }


@app.post("/scan", response_model=ScanStatus)
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new scan job (async background task).

    **target** options:
    - `images` — all running Docker containers
    - `filesystem` — paths in `SCAN_SOURCES` env var
    - `k8s` — all Kubernetes pod images
    - `all` — images + filesystem + k8s
    - `nginx:1.27` — specific image
    - `/opt/myapp` — specific path
    """
    scan_id = _new_scan_id()
    running_scans[scan_id] = {
        "scan_id":          scan_id,
        "status":           "queued",
        "started_at":       iso(),
        "finished_at":      None,
        "targets_scanned":  [],
        "targets_failed":   [],
        "report_paths":     [],
        "error":            None,
    }
    _persist(scan_id)
    background_tasks.add_task(run_scan_job, scan_id, request)
    return running_scans[scan_id]


@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    """Get the status of a scan job (also after a restart — runs are persisted)."""
    if scan_id in running_scans:
        return running_scans[scan_id]
    persisted = store.get_scan_run(scan_id)
    if persisted:
        return persisted
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/scans")
def list_scans():
    """List recent manual scan jobs."""
    merged = {r["scan_id"]: r for r in store.list_scan_runs(50)}
    merged.update(running_scans)
    return sorted(merged.values(), key=lambda r: r["started_at"], reverse=True)


@app.get("/reports")
def list_reports():
    """List all persisted report files from REPORT_DIR."""
    reports = []
    for p in sorted([*cfg.report_dir.rglob("*.json"), *cfg.report_dir.rglob("*.json.gz")]):
        st = p.stat()
        reports.append({
            "path":       str(p),
            "name":       p.name,
            "scan_id":    p.parent.name,
            "size_bytes": st.st_size,
            "created":    iso(datetime.fromtimestamp(st.st_ctime, timezone.utc)),
        })
    return reports


@app.get("/reports/{scan_id}/summary")
def get_report_summary(scan_id: str):
    """Return the consolidated summary.json for a completed scan."""
    summary_path = cfg.report_dir / scan_id / "summary.json"
    if not SCAN_ID_RE.match(scan_id) or not summary_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(summary_path.read_text())


@app.get("/images")
def list_scannable_images():
    """List all Docker images that would be scanned by target=images."""
    return {"images": inventory.get_running_docker_images()}


@app.get("/k8s/images")
def list_k8s_images(namespace: Optional[str] = None):
    """Preview which Kubernetes pod images would be scanned (requires k8s access)."""
    ns_images = inventory.get_k8s_images(cfg.kubeconfig, namespace)
    return {
        "namespaces":          ns_images,
        "total_unique":        len(inventory.flatten_k8s_images(ns_images)),
        "total_with_duplicates": sum(len(v) for v in ns_images.values()),
    }


# ── Continuous tracking, alerts, maintenance ──────────────────────────────────

@app.get("/targets")
def list_targets(active_only: bool = False):
    """Everything the scheduler tracks, with last scan, failure count and back-off."""
    return store.list_targets(active_only)


@app.get("/findings")
def list_findings(min_severity: Optional[str] = None, kev_only: bool = False, limit: int = 500):
    """Currently open findings of active targets (actively exploited first, then by severity and EPSS)."""
    return store.open_findings(min_severity, kev_only)[:max(1, min(limit, 5000))]


@app.get("/malware")
def list_malware_hits():
    """Open supply-chain malware hits (OSV MAL-* advisories matching components in scanned targets)."""
    return store.open_malware_hits()


@app.get("/alerts")
def list_alerts(limit: int = 50):
    """History of sent (or failed) alert and digest mails."""
    return store.list_alerts(max(1, min(limit, 500)))


@app.get("/disk")
def disk():
    return retention.disk_usage(cfg)


@app.post("/mail/test")
def mail_test():
    """Send a test mail with the configured SMTP settings."""
    if not cfg.mail_configured:
        raise HTTPException(status_code=400, detail="mail not configured (SMTP_HOST, MAIL_FROM, MAIL_TO)")
    try:
        return {"sent": True, "subject": reporting.send_test_mail(cfg)}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"send failed: {e}")


@app.post("/report/digest")
def send_digest_now():
    """Build and send the daily digest right now."""
    if not cfg.mail_configured:
        raise HTTPException(status_code=400, detail="mail not configured (SMTP_HOST, MAIL_FROM, MAIL_TO)")
    result = reporting.send_digest(cfg, store, slm, retention.disk_usage(cfg))
    if not result.get("sent"):
        raise HTTPException(status_code=502, detail=result.get("reason", "failed"))
    return result


@app.post("/maintenance/cleanup")
def cleanup_now():
    """Run the retention pass (old reports, SBOM archive, stale temp dirs) immediately."""
    return retention.run_retention(cfg, store)
