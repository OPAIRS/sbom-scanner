import os
import json
import subprocess
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import docker
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SBOM Scanner",
    version="1.1.0",
    description="On-premise SBOM generation (Syft) + CVE scanning (Grype) with REST API. "
                "Supports Docker images, Kubernetes pods, and filesystem paths.",
)

REPORT_DIR  = Path(os.getenv("REPORT_DIR", "/data/sbom-reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SCAN_SOURCES  = os.getenv("SCAN_SOURCES", "").split(",")        # comma-separated fs paths
SYFT_TIMEOUT  = int(os.getenv("SYFT_TIMEOUT", "900"))
GRYPE_TIMEOUT = int(os.getenv("GRYPE_TIMEOUT", "600"))
KUBECONFIG    = os.getenv("KUBECONFIG", "/root/.kube/config")

running_scans: dict[str, dict] = {}


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
    """Fail threshold reported in summary: low | medium | high | critical"""
    k8s_namespace: Optional[str] = None
    """Kubernetes namespace filter. None = all namespaces."""


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    targets_scanned: list[str] = []
    targets_failed: list[str] = []
    report_paths: list[str] = []
    error: Optional[str] = None


# ── Docker Helpers ────────────────────────────────────────────────────────────

def get_running_docker_images() -> list[str]:
    try:
        client = docker.from_env()
        images = []
        for container in client.containers.list():
            image_tag = (
                container.image.tags[0] if container.image.tags
                else container.image.short_id
            )
            if image_tag not in images:
                images.append(image_tag)
        return images
    except Exception as e:
        logger.error(f"Docker API error: {e}")
        return []


# ── Kubernetes Helpers ────────────────────────────────────────────────────────

def get_k8s_images(namespace: Optional[str] = None) -> dict[str, list[str]]:
    """
    Returns { "namespace/pod-name": ["image1", "image2"] }.
    Requires the kubernetes Python package and a valid KUBECONFIG.
    """
    try:
        from kubernetes import client as k8s_client, config as k8s_config
        k8s_config.load_kube_config(config_file=KUBECONFIG)
        v1 = k8s_client.CoreV1Api()

        pods = (
            v1.list_namespaced_pod(namespace)
            if namespace
            else v1.list_pod_for_all_namespaces()
        )

        ns_images: dict[str, list[str]] = {}
        for pod in pods.items:
            ns = pod.metadata.namespace
            ns_images.setdefault(ns, [])
            for c in (pod.spec.containers or []):
                if c.image and c.image not in ns_images[ns]:
                    ns_images[ns].append(c.image)
            for ic in (pod.spec.init_containers or []):
                if ic.image and ic.image not in ns_images[ns]:
                    ns_images[ns].append(ic.image)

        return ns_images

    except ImportError:
        logger.error("kubernetes package not installed — k8s scanning unavailable")
        return {}
    except Exception as e:
        logger.error(f"K8s API error: {e}")
        return {}


def flatten_k8s_images(ns_images: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for images in ns_images.values():
        for img in images:
            if img not in seen:
                seen.add(img)
                result.append(img)
    return result


# ── Scan Helpers ──────────────────────────────────────────────────────────────

def run_syft(target: str, output_path: Path) -> bool:
    cmd = ["syft", target, "-o", f"syft-json={output_path}", "--quiet"]
    logger.info(f"syft → {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SYFT_TIMEOUT)
        if result.returncode != 0:
            logger.error(f"syft failed [{target}]: {result.stderr[:300]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"syft timeout ({SYFT_TIMEOUT}s) for {target}")
        return False
    except Exception as e:
        logger.error(f"syft exception [{target}]: {e}")
        return False


def run_grype(sbom_path: Path, report_path: Path, severity: str = "medium") -> dict:
    cmd = [
        "grype", f"sbom:{sbom_path}",
        "-o", "json",
        "--fail-on", severity,
        "--quiet",
    ]
    logger.info(f"grype → {sbom_path.name}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GRYPE_TIMEOUT)
        grype_json = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        logger.error(f"grype timeout for {sbom_path}")
        grype_json = {"matches": []}
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"grype error [{sbom_path}]: {e}")
        grype_json = {"matches": []}

    matches = grype_json.get("matches", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity", "Unknown")
        if sev in severity_counts:
            severity_counts[sev] += 1

    summary = {
        "target": str(sbom_path),
        "scanned_at": datetime.utcnow().isoformat(),
        "total_vulnerabilities": len(matches),
        "severity_counts": severity_counts,
        "vulnerabilities": [
            {
                "id":           m.get("vulnerability", {}).get("id"),
                "severity":     m.get("vulnerability", {}).get("severity"),
                "package":      m.get("artifact", {}).get("name"),
                "version":      m.get("artifact", {}).get("version"),
                "fix_versions": m.get("vulnerability", {}).get("fix", {}).get("versions", []),
                "description":  (m.get("vulnerability", {}).get("description") or "")[:200],
            }
            for m in matches
        ],
    }

    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)

    return summary


async def scan_targets(
    scan_id: str,
    targets: list[str],
    scan_dir: Path,
    severity: str,
    source_label: str = "docker",
) -> tuple[list[dict], list[str], list[str]]:
    """Scan a list of targets. Returns (results, report_paths, failed_targets)."""
    all_vulns: list[dict] = []
    report_paths: list[str] = []
    failed_targets: list[str] = []

    for target in targets:
        safe_name = (
            target.replace("/", "_").replace(":", "_").replace("@", "_").lstrip("_")
        )
        sbom_path  = scan_dir / f"sbom_{source_label}_{safe_name}.json"
        grype_path = scan_dir / f"vulns_{source_label}_{safe_name}.json"

        loop = asyncio.get_event_loop()
        syft_ok = await loop.run_in_executor(None, run_syft, target, sbom_path)
        if not syft_ok:
            failed_targets.append(target)
            continue

        result = await loop.run_in_executor(None, run_grype, sbom_path, grype_path, severity)
        all_vulns.append({"target": target, "source": source_label, **result})
        report_paths.append(str(grype_path))

    return all_vulns, report_paths, failed_targets


# ── Background Job ────────────────────────────────────────────────────────────

async def run_scan_job(scan_id: str, request: ScanRequest):
    running_scans[scan_id]["status"] = "running"
    all_vulns: list[dict] = []
    report_paths: list[str] = []
    failed_targets: list[str] = []
    all_targets: list[str] = []

    try:
        scan_dir = REPORT_DIR / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        # ── Docker Images ──────────────────────────────────────────────────────
        if request.target in ("images", "all"):
            docker_images = get_running_docker_images()
            all_targets += docker_images
            running_scans[scan_id]["targets_scanned"] = list(all_targets)
            v, p, f = await scan_targets(
                scan_id, docker_images, scan_dir, request.severity_threshold, "docker"
            )
            all_vulns += v; report_paths += p; failed_targets += f

        # ── Kubernetes ─────────────────────────────────────────────────────────
        if request.target in ("k8s", "all"):
            ns_images = get_k8s_images(request.k8s_namespace)
            if ns_images:
                ns_map_path = scan_dir / "k8s_namespace_map.json"
                ns_map_path.write_text(json.dumps(ns_images, indent=2))

                k8s_images   = flatten_k8s_images(ns_images)
                docker_set   = set(get_running_docker_images())
                k8s_unique   = [img for img in k8s_images if img not in docker_set]

                logger.info(
                    f"K8s: {len(k8s_images)} total, {len(k8s_unique)} unique (not in Docker)"
                )
                all_targets += k8s_unique
                running_scans[scan_id]["targets_scanned"] = list(all_targets)
                v, p, f = await scan_targets(
                    scan_id, k8s_unique, scan_dir, request.severity_threshold, "k8s"
                )
                all_vulns += v; report_paths += p; failed_targets += f
            else:
                logger.warning("K8s scan requested but no images found")

        # ── Filesystem ─────────────────────────────────────────────────────────
        if request.target in ("filesystem", "all"):
            fs_targets = [s for s in SCAN_SOURCES if s and Path(s).exists()]
            all_targets += fs_targets
            running_scans[scan_id]["targets_scanned"] = list(all_targets)
            v, p, f = await scan_targets(
                scan_id, fs_targets, scan_dir, request.severity_threshold, "filesystem"
            )
            all_vulns += v; report_paths += p; failed_targets += f

        # ── Specific target ────────────────────────────────────────────────────
        if request.target not in ("images", "filesystem", "k8s", "all"):
            all_targets = [request.target]
            running_scans[scan_id]["targets_scanned"] = all_targets
            v, p, f = await scan_targets(
                scan_id, all_targets, scan_dir, request.severity_threshold, "single"
            )
            all_vulns += v; report_paths += p; failed_targets += f

        if not all_targets:
            running_scans[scan_id]["error"]  = "No scan targets found"
            running_scans[scan_id]["status"] = "failed"
            return

        # ── Consolidated Report ────────────────────────────────────────────────
        sources = set(r.get("source", "unknown") for r in all_vulns)
        consolidated = {
            "scan_id":        scan_id,
            "scanned_at":     datetime.utcnow().strftime("%Y%m%d_%H%M%S"),
            "targets_ok":     [t for t in all_targets if t not in failed_targets],
            "targets_failed": failed_targets,
            "results":        all_vulns,
            "total_critical": sum(r.get("severity_counts", {}).get("Critical", 0) for r in all_vulns),
            "total_high":     sum(r.get("severity_counts", {}).get("High",     0) for r in all_vulns),
            "total_medium":   sum(r.get("severity_counts", {}).get("Medium",   0) for r in all_vulns),
            "by_source": {
                src: {
                    "total_critical": sum(r.get("severity_counts", {}).get("Critical", 0) for r in all_vulns if r.get("source") == src),
                    "total_high":     sum(r.get("severity_counts", {}).get("High",     0) for r in all_vulns if r.get("source") == src),
                    "total_medium":   sum(r.get("severity_counts", {}).get("Medium",   0) for r in all_vulns if r.get("source") == src),
                }
                for src in sources
            },
        }
        summary_path = scan_dir / "summary.json"
        summary_path.write_text(json.dumps(consolidated, indent=2))
        report_paths.append(str(summary_path))

        running_scans[scan_id].update({
            "status":          "completed",
            "report_paths":    report_paths,
            "targets_failed":  failed_targets,
            "finished_at":     datetime.utcnow().isoformat(),
        })
        logger.info(f"Scan {scan_id} completed. Failed targets: {failed_targets}")

    except Exception as e:
        logger.exception(f"Scan {scan_id} crashed: {e}")
        running_scans[scan_id].update({
            "status":      "failed",
            "error":       str(e),
            "finished_at": datetime.utcnow().isoformat(),
        })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "sbom-scanner", "version": "1.1.0"}


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
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    running_scans[scan_id] = {
        "scan_id":          scan_id,
        "status":           "queued",
        "started_at":       datetime.utcnow().isoformat(),
        "finished_at":      None,
        "targets_scanned":  [],
        "targets_failed":   [],
        "report_paths":     [],
        "error":            None,
    }
    background_tasks.add_task(run_scan_job, scan_id, request)
    return running_scans[scan_id]


@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    """Get the current status of a scan job."""
    if scan_id not in running_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return running_scans[scan_id]


@app.get("/scans")
def list_scans():
    """List all scan jobs from the current session."""
    return list(running_scans.values())


@app.get("/reports")
def list_reports():
    """List all persisted report files from REPORT_DIR."""
    reports = []
    for p in sorted(REPORT_DIR.rglob("*.json")):
        reports.append({
            "path":       str(p),
            "name":       p.name,
            "scan_id":    p.parent.name,
            "size_bytes": p.stat().st_size,
            "created":    datetime.fromtimestamp(p.stat().st_ctime).isoformat(),
        })
    return reports


@app.get("/reports/{scan_id}/summary")
def get_report_summary(scan_id: str):
    """Return the consolidated summary.json for a completed scan."""
    summary_path = REPORT_DIR / scan_id / "summary.json"
    if not summary_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(summary_path.read_text())


@app.get("/images")
def list_scannable_images():
    """List all Docker images that would be scanned by target=images."""
    return {"images": get_running_docker_images()}


@app.get("/k8s/images")
def list_k8s_images(namespace: Optional[str] = None):
    """Preview which Kubernetes pod images would be scanned (requires k8s access)."""
    ns_images = get_k8s_images(namespace)
    return {
        "namespaces":          ns_images,
        "total_unique":        len(flatten_k8s_images(ns_images)),
        "total_with_duplicates": sum(len(v) for v in ns_images.values()),
    }
