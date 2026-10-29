import gzip
import os
import time

import retention

DAY = 86400


def make_scan(cfg, name, age_days, size=1000, sbom=False):
    d = cfg.report_dir / name
    d.mkdir(parents=True)
    (d / "summary.json").write_text("{}")
    (d / "vulns_docker_x.json").write_bytes(b"x" * size)
    if sbom:
        (d / "sbom_docker_x.json").write_text('{"components": []}' * 100)
    t = time.time() - age_days * DAY
    for p in [*d.iterdir(), d]:
        os.utime(p, (t, t))
    return d


def test_reports_removed_by_age_and_by_count(cfg):
    cfg.report_keep_days, cfg.report_max_scans = 30, 3
    make_scan(cfg, "scan_20260101_000000", 100)
    for i in range(5):
        make_scan(cfg, f"scan_2026100{i}_000000", 5 - i)
    dirs, freed = retention.cleanup_reports(cfg)
    left = sorted(p.name for p in cfg.report_dir.iterdir())
    assert dirs == 3 and freed > 0
    assert left == ["scan_20261002_000000", "scan_20261003_000000", "scan_20261004_000000"]


def test_legacy_sboms_are_compressed_not_deleted(cfg):
    old = make_scan(cfg, "scan_old", 3, sbom=True)
    new = make_scan(cfg, "scan_new", 0, sbom=True)
    saved = retention.compress_legacy_sboms(cfg)
    assert saved > 0
    assert not (old / "sbom_docker_x.json").exists()
    assert gzip.open(old / "sbom_docker_x.json.gz").read().startswith(b'{"components"')
    assert (new / "sbom_docker_x.json").exists()                     # today's scan untouched


def test_stale_work_dirs_are_removed(cfg):
    stale = cfg.work_dir / "run_old"
    fresh = cfg.work_dir / "run_new"
    for d in (stale, fresh):
        d.mkdir()
        (d / "image.tar").write_bytes(b"x" * 4096)
    old = time.time() - 3 * 3600
    os.utime(stale, (old, old))
    assert retention.cleanup_work(cfg) == 4096
    assert not stale.exists() and fresh.exists()


def test_budget_prunes_oldest_reports_first_and_keeps_newest_three(cfg):
    cfg.data_budget_gb = 40_000 / 1024 ** 3                         # ~40 kB budget
    for i in range(6):
        make_scan(cfg, f"scan_2026100{i}_000000", 6 - i, size=10_000)
    retention.enforce_budget(cfg)
    left = sorted(p.name for p in cfg.report_dir.iterdir())
    assert left[-3:] == ["scan_20261003_000000", "scan_20261004_000000", "scan_20261005_000000"]
    assert len(left) < 6


def test_run_retention_end_to_end(cfg, store):
    make_scan(cfg, "scan_ancient", 90)
    store.mark_inventory("docker", {"a:1": None})
    out = retention.run_retention(cfg, store)
    assert out["report_dirs_removed"] == 1
    assert out["disk"]["disk_free_bytes"] > 0
