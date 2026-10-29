import asyncio

import pytest

import feeds
import inventory
import reporting
import scanner
from scheduler import Scheduler
from slm import SlmClient


@pytest.fixture
def sched(cfg, store, monkeypatch):
    cfg.batch_size = 2
    scanned, order = [], []
    images = {f"img{i}:1": f"sha256:{i}" for i in range(5)}

    monkeypatch.setattr(inventory, "discover", lambda c: {"docker": dict(images)})
    monkeypatch.setattr(scanner, "update_grype_db", lambda c: (True, "fp1"))
    monkeypatch.setattr(feeds, "refresh_kev", lambda c, s: set())
    monkeypatch.setattr(feeds, "check_malicious_packages", lambda c, s: [])
    monkeypatch.setattr(reporting, "dispatch_alerts", lambda c, s, m: order.append("alerts") or {})
    monkeypatch.setattr(reporting, "maybe_send_digest", lambda c, s, m, d=None: order.append("digest"))

    def fake_scan(c, s, target, source, image_id, **kw):
        scanned.append(target)
        s.record_success(target, source, image_id, kw.get("db_fp"))
        summary = {"total_vulnerabilities": 0, "new_findings": 0, "resolved_findings": 0}
        return scanner.ScanOutcome(target, source, True, summary=summary)

    monkeypatch.setattr(scanner, "scan_target", fake_scan)
    s = Scheduler(cfg, store, asyncio.Lock(), SlmClient(cfg))
    s.scanned, s.order, s.images = scanned, order, images
    return s


def test_tick_scans_in_small_batches_until_backlog_is_empty(sched):
    assert asyncio.run(sched.tick()) == 2 and sched.state["backlog"] == 5
    assert asyncio.run(sched.tick()) == 2 and sched.state["backlog"] == 3
    assert asyncio.run(sched.tick()) == 1
    assert asyncio.run(sched.tick()) == 0                             # all up to date
    assert sorted(sched.scanned) == sorted(sched.images) and len(sched.scanned) == 5
    assert sched.order.count("alerts") == 4 and sched.order.count("digest") == 4
    assert sched.state["last_error"] is None


def test_new_vulnerability_db_triggers_rescan_in_batches(sched, monkeypatch):
    for _ in range(3):
        asyncio.run(sched.tick())
    sched.scanned.clear()
    sched.store.kv_set("db_updated_at", "2000-01-01T00:00:00+00:00")  # force a DB refresh on the next tick
    monkeypatch.setattr(scanner, "update_grype_db", lambda c: (True, "fp2"))
    assert asyncio.run(sched.tick()) == 2                              # 5 targets due, batch of 2
    assert sched.state["backlog"] == 5


def test_tick_survives_component_failures(sched, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("osv down")

    monkeypatch.setattr(feeds, "check_malicious_packages", boom)
    asyncio.run(sched.tick())
    assert "osv down" in sched.state["last_error"]
    monkeypatch.setattr(feeds, "check_malicious_packages", lambda c, s: [])
    asyncio.run(sched.tick())
    assert sched.state["last_error"] is None


def test_first_tick_retention_runs_once_a_day(sched, monkeypatch):
    import retention

    calls = []
    monkeypatch.setattr(retention, "run_retention", lambda c, s: calls.append(1) or {})
    asyncio.run(sched.tick())
    asyncio.run(sched.tick())
    assert calls == [1]


def test_docker_inventory_skips_container_whose_image_is_gone(monkeypatch):
    import sys
    import types

    class Img:
        def __init__(self, tag, id_):
            self.tags, self.id, self.short_id = [tag] if tag else [], id_, id_[:12]

    class Gone:
        name = "orphan"
        attrs = {"Config": {"Image": "old:1"}}

        @property
        def image(self):
            raise RuntimeError("404 No such image")

    class Ok:
        name = "fine"
        attrs = {}
        image = Img("app:1", "sha256:" + "a" * 64)

    class Client:
        containers = types.SimpleNamespace(list=lambda: [Gone(), Ok()])
        images = types.SimpleNamespace(get=lambda n: (_ for _ in ()).throw(RuntimeError("gone")))

    fake = types.SimpleNamespace(from_env=lambda: Client())
    monkeypatch.setitem(sys.modules, "docker", fake)
    assert inventory.get_running_docker_inventory() == {"app:1": "sha256:" + "a" * 64}
