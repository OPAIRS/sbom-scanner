import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("SCAN_SOURCES", "")
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    with TestClient(main.app) as client:
        yield main, client
    sys.modules.pop("main", None)


def test_health_status_and_empty_lists(api):
    main, client = api
    assert client.get("/health").json()["version"] == "2.0.0"
    st = client.get("/status").json()
    assert st["scheduler"]["enabled"] is False and st["findings"]["open_findings"] == 0
    assert st["mail"]["configured"] is False and st["slm"]["enabled"] is False
    for path in ("/findings", "/malware", "/alerts", "/targets", "/scans", "/reports", "/disk"):
        assert client.get(path).status_code == 200


def test_manual_scan_flow_persists_status(api, monkeypatch):
    main, client = api
    monkeypatch.setattr(main.inventory, "get_running_docker_inventory", lambda: {"app:1": "sha256:a"})

    def fake_scan(cfg, store, target, source, image_id, **kw):
        store.mark_inventory("docker", {target: image_id})
        summary = {"target": target, "source": source, "severity_counts": {"Critical": 2, "High": 1, "Medium": 0},
                   "known_exploited": 1, "new_findings": 3, "resolved_findings": 0, "total_vulnerabilities": 3}
        return main.scanner.ScanOutcome(target, source, True, summary=summary, report_path=str(kw["scan_dir"] / "x.json"))

    monkeypatch.setattr(main.scanner, "scan_target", fake_scan)
    r = client.post("/scan", json={"target": "images"})
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]

    status = client.get(f"/scan/{scan_id}").json()
    assert status["status"] == "completed" and status["targets_scanned"] == ["app:1"]
    summary = client.get(f"/reports/{scan_id}/summary").json()
    assert summary["total_critical"] == 2 and summary["total_known_exploited"] == 1 and summary["by_source"]["docker"]["total_critical"] == 2

    main.running_scans.clear()                                          # simulate a container restart
    assert client.get(f"/scan/{scan_id}").json()["status"] == "completed"
    assert scan_id in {s["scan_id"] for s in client.get("/scans").json()}


def test_scan_without_targets_fails_cleanly(api, monkeypatch):
    main, client = api
    monkeypatch.setattr(main.inventory, "get_running_docker_inventory", lambda: {})
    scan_id = client.post("/scan", json={"target": "images"}).json()["scan_id"]
    status = client.get(f"/scan/{scan_id}").json()
    assert status["status"] == "failed" and status["error"] == "No scan targets found"


def test_summary_path_traversal_is_rejected(api):
    _main, client = api
    assert client.get("/reports/..%2F..%2Fetc/summary").status_code == 404
    assert client.get("/reports/../summary").status_code in (404, 405)


def test_mail_endpoints_require_configuration(api):
    _main, client = api
    assert client.post("/mail/test").status_code == 400
    assert client.post("/report/digest").status_code == 400


def test_api_key_protects_everything_except_health(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("API_KEY", "s3cret")
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/findings").status_code == 401
        assert client.get("/findings", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/findings", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert client.post("/maintenance/cleanup").status_code == 401
    sys.modules.pop("main", None)


def test_cleanup_endpoint(api):
    _main, client = api
    out = client.post("/maintenance/cleanup").json()
    assert "disk" in out and out["report_dirs_removed"] == 0
