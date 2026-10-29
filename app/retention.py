"""Disk hygiene: bounded reports, bounded SBOM archive, no leftover temp dirs."""
from __future__ import annotations

import gzip
import logging
import os
import shutil
import time
from pathlib import Path

from config import Settings
from scanner import prune_sbom_archive
from store import Store

logger = logging.getLogger(__name__)

DAY = 86400


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def grype_cache_dir() -> Path:
    return Path(os.getenv("GRYPE_DB_CACHE_DIR", str(Path.home() / ".cache" / "grype")))


def disk_usage(cfg: Settings) -> dict:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(cfg.data_dir)
    return {
        "reports_bytes": dir_size(cfg.report_dir),
        "sbom_store_bytes": dir_size(cfg.sbom_store),
        "work_bytes": dir_size(cfg.work_dir),
        "state_bytes": dir_size(cfg.state_dir),
        "grype_db_bytes": dir_size(grype_cache_dir()),
        "budget_bytes": int(cfg.data_budget_gb * 1024 ** 3),
        "disk_free_bytes": usage.free,
        "disk_total_bytes": usage.total,
    }


def _budgeted_bytes(d: dict) -> int:
    return d["reports_bytes"] + d["sbom_store_bytes"] + d["work_bytes"]


def cleanup_work(cfg: Settings, max_age_minutes: int | None = None) -> int:
    """Remove scratch dirs of finished or crashed runs. Returns bytes freed."""
    freed = 0
    limit = (max_age_minutes if max_age_minutes is not None else cfg.work_stale_minutes) * 60
    if not cfg.work_dir.exists():
        return 0
    for p in cfg.work_dir.iterdir():
        try:
            if p.is_dir() and time.time() - p.stat().st_mtime > limit:
                freed += dir_size(p)
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass
    return freed


def compress_legacy_sboms(cfg: Settings) -> int:
    """v1.x wrote an uncompressed sbom_*.json per image per scan. Gzip those (≈10× smaller). Returns bytes saved."""
    saved = 0
    for scan_dir in cfg.report_dir.glob("scan_*"):
        if not scan_dir.is_dir() or time.time() - scan_dir.stat().st_mtime < DAY:
            continue
        for f in scan_dir.glob("sbom_*.json"):
            try:
                before = f.stat().st_size
                gz = f.with_suffix(f.suffix + ".gz")
                with open(f, "rb") as src, gzip.open(gz, "wb", compresslevel=6) as out:
                    shutil.copyfileobj(src, out)
                f.unlink()
                saved += before - gz.stat().st_size
            except OSError as e:
                logger.warning(f"could not compress {f}: {e}")
    return saved


def _scan_dirs_oldest_first(cfg: Settings) -> list[Path]:
    dirs = [p for p in cfg.report_dir.glob("scan_*") if p.is_dir()]
    return sorted(dirs, key=lambda p: p.stat().st_mtime)


def cleanup_reports(cfg: Settings) -> tuple[int, int]:
    """Delete scan report dirs older than REPORT_KEEP_DAYS or beyond REPORT_MAX_SCANS. Returns (dirs, bytes)."""
    dirs = _scan_dirs_oldest_first(cfg)
    cutoff = time.time() - cfg.report_keep_days * DAY
    excess = max(0, len(dirs) - cfg.report_max_scans)
    removed = freed = 0
    for i, d in enumerate(dirs):
        if i < excess or d.stat().st_mtime < cutoff:
            freed += dir_size(d)
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    return removed, freed


def cleanup_sbom_store(cfg: Settings, store: Store) -> int:
    """Trim archived SBOMs to SBOM_KEEP_PER_TARGET per target; drop archives of long-gone targets."""
    before = dir_size(cfg.sbom_store)
    for tdir in cfg.sbom_store.iterdir() if cfg.sbom_store.exists() else []:
        if tdir.is_dir():
            prune_sbom_archive(tdir, cfg.sbom_keep_per_target)
    gone = store.purge_inactive(cfg.report_keep_days)
    if gone:
        from common import safe_name

        for target in gone:
            shutil.rmtree(cfg.sbom_store / safe_name(target), ignore_errors=True)
    return max(0, before - dir_size(cfg.sbom_store))


def enforce_budget(cfg: Settings) -> int:
    """If the data exceeds DATA_BUDGET_GB, delete the oldest reports first (always keep the newest 3)."""
    d = disk_usage(cfg)
    if _budgeted_bytes(d) <= d["budget_bytes"]:
        return 0
    target = int(d["budget_bytes"] * 0.8)
    freed = 0
    logger.warning(f"data budget exceeded ({_budgeted_bytes(d) // 2**20} MiB > {d['budget_bytes'] // 2**20} MiB) — pruning oldest reports")
    dirs = _scan_dirs_oldest_first(cfg)
    for scan_dir in dirs[:-3]:
        if _budgeted_bytes(d) - freed <= target:
            break
        freed += dir_size(scan_dir)
        shutil.rmtree(scan_dir, ignore_errors=True)
    if _budgeted_bytes(d) - freed > target:
        for tdir in cfg.sbom_store.iterdir() if cfg.sbom_store.exists() else []:
            if tdir.is_dir():
                before = dir_size(tdir)
                prune_sbom_archive(tdir, 1)
                freed += before - dir_size(tdir)
    return freed


def run_retention(cfg: Settings, store: Store) -> dict:
    """Full cleanup pass. Safe to run at any time (also from the API)."""
    result = {
        "work_freed_bytes": cleanup_work(cfg),
        "legacy_sbom_compressed_bytes_saved": compress_legacy_sboms(cfg),
    }
    dirs, freed = cleanup_reports(cfg)
    result["report_dirs_removed"] = dirs
    result["reports_freed_bytes"] = freed
    result["sbom_store_freed_bytes"] = cleanup_sbom_store(cfg, store)
    result["budget_freed_bytes"] = enforce_budget(cfg)
    store.prune_history()
    result["disk"] = disk_usage(cfg)
    logger.info(f"retention: {result}")
    return result
