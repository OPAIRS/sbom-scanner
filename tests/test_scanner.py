import gzip
import json
from pathlib import Path

import pytest

import scanner
from conftest import grype_match


def test_normalize_matches_aliases_kev_epss_and_dedupe():
    ghsa = grype_match("GHSA-xxxx-yyyy-zzzz", "Critical", "libfoo", "1.0")
    ghsa["relatedVulnerabilities"] = [{"id": "CVE-2025-1111"}]
    kev = grype_match("CVE-2025-2222", "High", "libbar", "2.0",
                      knownExploited=[{"cve": "CVE-2025-2222", "knownRansomwareCampaignUse": "Known"}],
                      epss=[{"cve": "CVE-2025-2222", "epss": 0.91}],
                      cvss=[{"metrics": {"baseScore": 8.1}}, {"metrics": {"baseScore": 7.0}}])
    dup_low = grype_match("CVE-2025-3333", "Low", "libbaz", "3.0")
    dup_high = grype_match("CVE-2025-3333", "High", "libbaz", "3.0")   # same package at another location
    via_feed = grype_match("CVE-2025-4444", "Medium", "libqux", "4.0")

    out = {f["vuln_id"]: f for f in scanner.normalize_matches(
        {"matches": [ghsa, kev, dup_low, dup_high, via_feed]}, kev_ids={"CVE-2025-4444"})}

    assert len(out) == 4
    assert out["GHSA-xxxx-yyyy-zzzz"]["cve_ids"] == ["CVE-2025-1111"]
    assert out["CVE-2025-2222"]["kev"] and out["CVE-2025-2222"]["ransomware"]
    assert out["CVE-2025-2222"]["epss"] == 0.91 and out["CVE-2025-2222"]["cvss"] == 8.1
    assert out["CVE-2025-3333"]["severity"] == "High"
    assert out["CVE-2025-4444"]["kev"] is True                      # flagged by the KEV feed only


def test_run_dir_is_removed_even_on_error(cfg):
    with pytest.raises(RuntimeError):
        with scanner.run_dir(cfg) as (path, env):
            (path / "tmp" / "image-export.tar").write_bytes(b"x" * 1024)
            assert env["TMPDIR"].startswith(str(cfg.work_dir))
            raise RuntimeError("syft crashed")
    assert list(cfg.work_dir.iterdir()) == []


def test_archive_keeps_newest_n_per_target_gzipped(cfg, tmp_path):
    cfg.sbom_keep_per_target = 2
    sbom = tmp_path / "s.json"
    sbom.write_text(json.dumps({"components": []}))
    import os, time
    for i, image_id in enumerate(["sha256:a", "sha256:b", "sha256:c"]):
        p = scanner.archive_sbom(cfg, "repo/app:1", image_id, sbom)
        os.utime(p, (time.time() + i, time.time() + i))
    files = sorted(f.name for f in (cfg.sbom_store / "repo_app_1").iterdir())
    assert files == ["sha256_b.cdx.json.gz", "sha256_c.cdx.json.gz"]
    assert json.loads(gzip.open(cfg.sbom_store / "repo_app_1" / files[0]).read()) == {"components": []}


@pytest.fixture
def fake_tools(monkeypatch):
    calls = {"syft": 0, "grype": 0}
    state = {"grype_json": {"matches": [grype_match("CVE-2024-1", "Critical")]}, "grype_error": None}

    def fake_syft(cfg, target, output_path, env):
        calls["syft"] += 1
        output_path.write_text(json.dumps({"components": [
            {"purl": "pkg:npm/left-pad@1.3.0"}, {"purl": "pkg:deb/debian/openssl@3.0.1"}]}))

    def fake_grype(cfg, sbom_path, env):
        calls["grype"] += 1
        assert sbom_path.exists()
        if state["grype_error"]:
            raise scanner.ScanError(state["grype_error"])
        return state["grype_json"]

    monkeypatch.setattr(scanner, "run_syft", fake_syft)
    monkeypatch.setattr(scanner, "run_grype", fake_grype)
    return calls, state


def test_scan_target_reuses_sbom_for_unchanged_image(cfg, store, fake_tools):
    calls, state = fake_tools
    store.mark_inventory("docker", {"app:1": "sha256:a"})

    first = scanner.scan_target(cfg, store, "app:1", "docker", "sha256:a", db_fp="fp1", scan_dir=cfg.report_dir / "scan_x")
    assert first.ok and not first.reused_sbom and calls == {"syft": 1, "grype": 1}
    assert Path(first.report_path).exists()
    assert first.summary["severity_counts"]["Critical"] == 1
    assert store.alertable_findings(lambda f: 0) == []              # baseline: first scan stays silent
    assert [p for p in store._all("SELECT purl FROM components")] == [{"purl": "pkg:npm/left-pad@1.3.0"}]

    second = scanner.scan_target(cfg, store, "app:1", "docker", "sha256:a", db_fp="fp2")
    assert second.ok and second.reused_sbom and calls == {"syft": 1, "grype": 2}   # Grype only, no new SBOM

    state["grype_json"] = {"matches": []}
    third = scanner.scan_target(cfg, store, "app:1", "docker", "sha256:b", db_fp="fp2")      # image changed
    assert third.ok and not third.reused_sbom and calls["syft"] == 2
    assert third.summary["resolved_findings"] == 1
    assert store.open_findings() == []
    assert list(cfg.work_dir.iterdir()) == []                        # no scratch dirs left behind


def test_grype_failure_is_a_failure_not_a_clean_result(cfg, store, fake_tools):
    calls, state = fake_tools
    store.mark_inventory("docker", {"app:1": "sha256:a"})
    scanner.scan_target(cfg, store, "app:1", "docker", "sha256:a", db_fp="fp1")
    assert len(store.open_findings()) == 1

    state["grype_error"] = "grype produced no JSON"
    out = scanner.scan_target(cfg, store, "app:1", "docker", "sha256:a", db_fp="fp2")
    assert not out.ok and "no JSON" in out.error
    assert len(store.open_findings()) == 1                           # findings are NOT silently resolved
    assert store.get_target("app:1")["fail_count"] == 1


def test_is_osv_purl():
    assert scanner.is_osv_purl("pkg:npm/left-pad@1.3.0")
    assert not scanner.is_osv_purl("pkg:npm/left-pad")               # unversioned would match every version
    assert not scanner.is_osv_purl("pkg:deb/debian/openssl@3.0.1")
