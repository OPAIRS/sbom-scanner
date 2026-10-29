from datetime import timedelta

from common import PRIO_KEV, PRIO_SEVERITY, alert_priority, iso, utcnow
from conftest import finding


def prio(f):
    return alert_priority(f, "Critical", True, 0.5)


def test_new_persisting_resolved_and_reopen(store):
    store.mark_inventory("docker", {"app:1": "sha256:a"})
    first = store.ingest_findings("app:1", [finding("CVE-1"), finding("CVE-2", severity="High")], prio, baseline=False)
    assert len(first["new"]) == 2 and first["resolved"] == 0

    second = store.ingest_findings("app:1", [finding("CVE-1")], prio, baseline=False)
    assert second["new"] == [] and second["persisting"] == 1 and second["resolved"] == 1

    third = store.ingest_findings("app:1", [finding("CVE-1"), finding("CVE-2", severity="High")], prio, baseline=False)
    assert [f["vuln_id"] for f in third["reopened"]] == ["CVE-2"]
    assert {r["vuln_id"] for r in store.open_findings()} == {"CVE-1", "CVE-2"}


def test_baseline_is_silent_but_kev_still_alerts(store):
    store.mark_inventory("docker", {"app:1": None})
    store.ingest_findings("app:1", [finding("CVE-1"), finding("CVE-9", kev=True)], prio, baseline=True)
    alertable = store.alertable_findings(prio)
    assert [(f["vuln_id"], p) for f, p in alertable] == [("CVE-9", PRIO_KEV)]


def test_escalation_to_kev_realerts_once(store):
    store.mark_inventory("docker", {"app:1": None})
    store.ingest_findings("app:1", [finding("CVE-1")], prio, baseline=False)
    (f, p), = store.alertable_findings(prio)
    assert p == PRIO_SEVERITY
    store.mark_alerted([(f["id"], p)])
    assert store.alertable_findings(prio) == []

    assert store.apply_kev({"CVE-1"}) == 1
    (f, p), = store.alertable_findings(prio)
    assert p == PRIO_KEV
    store.mark_alerted([(f["id"], p)])
    assert store.alertable_findings(prio) == []


def test_inactive_targets_do_not_alert_and_empty_discovery_is_ignored(store):
    store.mark_inventory("docker", {"a:1": None, "b:1": None})
    store.ingest_findings("a:1", [finding("CVE-1")], prio, baseline=False)
    store.mark_inventory("docker", {"b:1": None})
    assert store.alertable_findings(prio) == []          # a:1 is gone
    store.mark_inventory("docker", {})                   # transient discovery error
    assert store.get_target("b:1")["active"] is True


def test_pick_due_reasons_priority_and_backoff(store):
    now = utcnow()
    cands = {"new:1": ("docker", "sha256:n"), "old:1": ("docker", "sha256:o"), "fresh:1": ("docker", "sha256:f")}
    store.mark_inventory("docker", {k: v[1] for k, v in cands.items()})
    for t in ("old:1", "fresh:1"):
        store.set_sbom(t, "docker", cands[t][1], "/x")
        store.record_success(t, "docker", cands[t][1], "fp1")
    store._exec("UPDATE targets SET last_ok_at=? WHERE target='old:1'", (iso(now - timedelta(hours=30)),))

    due = store.pick_due(cands, "fp1", rescan_hours=24, limit=10)
    assert [(d["target"], d["reason"]) for d in due] == [("new:1", "new"), ("old:1", "periodic")]

    due = store.pick_due(cands, "fp2", rescan_hours=24, limit=1)       # DB changed → everything due, batch of 1
    assert len(due) == 1 and due[0]["target"] == "new:1"

    cands["fresh:1"] = ("docker", "sha256:CHANGED")
    reasons = {d["target"]: d["reason"] for d in store.pick_due(cands, "fp1", 24, 10)}
    assert reasons["fresh:1"] == "image-changed"

    store.record_failure("new:1", "docker", "boom", backoff_hours=1)
    assert "new:1" not in {d["target"] for d in store.pick_due(cands, "fp1", 24, 10)}
    store.record_failure("new:1", "docker", "boom", backoff_hours=1)
    assert store.get_target("new:1")["fail_count"] == 2


def test_manual_single_target_is_not_tracked_but_does_not_deactivate_tracked(store):
    store.mark_inventory("docker", {"nginx:1": None})
    store.record_success("nginx:1", "single", None, None)
    assert store.get_target("nginx:1")["active"] is True
    store.record_success("adhoc:1", "single", None, None)
    assert store.get_target("adhoc:1")["active"] is False


def test_malware_hit_lifecycle(store):
    store.mark_inventory("docker", {"app:1": None})
    key = ("app:1", "MAL-2026-1", "pkg:npm/evil@1.0.0")
    assert len(store.sync_malware_hits({key: "bad"})) == 1
    assert len(store.unalerted_malware_hits()) == 1
    store.mark_malware_alerted([store.open_malware_hits()[0]["id"]])
    assert store.sync_malware_hits({key: "bad"}) == []            # known, already alerted
    assert store.unalerted_malware_hits() == []
    store.sync_malware_hits({})
    assert store.open_malware_hits() == []


def test_purge_inactive(store):
    store.mark_inventory("docker", {"a:1": None, "b:1": None})
    store.ingest_findings("a:1", [finding("CVE-1")], prio, baseline=False)
    store.mark_inventory("docker", {"b:1": None})
    store._exec("UPDATE targets SET last_seen_at=? WHERE target='a:1'", (iso(utcnow() - timedelta(days=40)),))
    assert store.purge_inactive(30) == ["a:1"]
    assert store.get_target("a:1") is None
    assert store._all("SELECT * FROM findings") == []
