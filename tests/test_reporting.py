import pytest

import reporting
from common import alert_priority
from conftest import finding
from slm import SlmClient


class FakeSlm(SlmClient):
    def __init__(self, cfg, enabled=True):
        super().__init__(cfg)
        self._enabled = enabled
        self.calls = 0

    @property
    def enabled(self):
        return self._enabled

    def explain_finding(self, f, target):
        self.calls += 1
        return "Kurz: patchen."

    def explain_malware(self, hit):
        self.calls += 1
        return "Paket entfernen."

    def summarize_status(self, facts):
        return "Lage ruhig."


@pytest.fixture
def mail_cfg(cfg):
    cfg.smtp_host, cfg.mail_from, cfg.mail_to = "smtp.local", "sbom@example.org", ["it@example.org"]
    cfg.report_host_label = "hub-000"
    return cfg


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(reporting, "send_mail", lambda cfg, subject, text, html, urgent=False: sent.append((subject, text, html, urgent)))
    return sent


def prio(cfg):
    return lambda f: alert_priority(f, cfg.alert_min_severity, cfg.alert_on_kev, cfg.alert_epss_threshold)


def seed(store, cfg, findings):
    store.mark_inventory("docker", {"app:1": None})
    store.ingest_findings("app:1", findings, prio(cfg), baseline=False)


def test_alert_orders_kev_first_and_contains_actions_and_links(mail_cfg, store, outbox):
    seed(store, mail_cfg, [
        finding("CVE-2024-1", severity="Critical"),
        finding("CVE-2024-2", severity="High", kev=True, ransomware=True, fix_versions=[]),
        finding("CVE-2024-3", severity="High", epss=0.8),
        finding("CVE-2024-4", severity="Medium"),
    ])
    result = reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))
    assert result["sent"] and result["items"] == 3
    subject, text, html, urgent = outbox[0]
    assert urgent and "ALARM" in subject and "hub-000" in subject
    assert text.index("CVE-2024-2") < text.index("CVE-2024-1") < text.index("CVE-2024-3")
    assert "CVE-2024-4" not in text
    assert "Ransomware-Nutzung bekannt" in text and "Es gibt noch keinen Fix" in text
    assert "openssl auf 3.0.9 aktualisieren" in text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-1" in text
    assert "KI-Einschätzung" in text and "Kurz: patchen." in text


def test_no_duplicate_alerts_and_rate_limit(mail_cfg, store, outbox):
    seed(store, mail_cfg, [finding("CVE-2024-1")])
    assert reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))["sent"]
    assert reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))["reason"] == "nothing to report"

    store.ingest_findings("app:1", [finding("CVE-2024-1"), finding("CVE-2024-5")], prio(mail_cfg), baseline=False)
    assert reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))["reason"] == "rate-limited"
    store.ingest_findings("app:1", [finding("CVE-2024-1"), finding("CVE-2024-5"), finding("CVE-2024-6", kev=True)],
                          prio(mail_cfg), baseline=False)
    assert reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))["sent"]   # KEV bypasses the rate limit
    assert len(outbox) == 2


def test_not_configured_keeps_findings_pending(cfg, store, outbox):
    seed(store, cfg, [finding("CVE-2024-1")])
    assert reporting.dispatch_alerts(cfg, store, FakeSlm(cfg))["reason"] == "mail not configured"
    assert len(store.alertable_findings(prio(cfg))) == 1 and outbox == []


def test_send_failure_keeps_findings_pending_and_is_logged(mail_cfg, store, monkeypatch):
    seed(store, mail_cfg, [finding("CVE-2024-1")])

    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(reporting, "send_mail", boom)
    assert not reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))["sent"]
    assert len(store.alertable_findings(prio(mail_cfg))) == 1
    assert store.list_alerts()[0]["ok"] == 0


def test_malware_alert_is_urgent_and_marked(mail_cfg, store, outbox):
    store.mark_inventory("docker", {"app:1": None})
    store.sync_malware_hits({("app:1", "MAL-2026-7", "pkg:npm/evil@1.0.0"): "Steals tokens"})
    reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg))
    subject, text, _html, urgent = outbox[0]
    assert urgent and "Malware-Verdacht" in subject
    assert "MAL-2026-7" in text and "Zugangsdaten rotieren" in text and "Steals tokens" in text
    assert store.unalerted_malware_hits() == []


def test_overflow_is_counted_and_all_marked_as_alerted(mail_cfg, store, outbox):
    mail_cfg.alert_max_items = 5
    seed(store, mail_cfg, [finding(f"CVE-2024-{i:04d}") for i in range(12)])
    reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg, enabled=False))
    assert "und 7 weitere" in outbox[0][1]
    assert store.alertable_findings(prio(mail_cfg)) == []


def test_html_escapes_untrusted_content(mail_cfg, store, outbox):
    store.mark_inventory("docker", {"app:1": None})
    store.sync_malware_hits({("app:1", "MAL-1", "pkg:npm/x@1"): "<script>alert(1)</script>"})
    reporting.dispatch_alerts(mail_cfg, store, FakeSlm(mail_cfg, enabled=False))
    assert "<script>" not in outbox[0][2] and "&lt;script&gt;" in outbox[0][2]


def test_digest_contents_and_once_per_day(mail_cfg, store, outbox, monkeypatch):
    mail_cfg.digest_hour = 0
    seed(store, mail_cfg, [finding("CVE-2024-1"), finding("CVE-2024-2", severity="High", kev=True)])
    store.record_failure("app:1", "docker", "syft timeout (900s)", 1)
    disk = {"reports_bytes": 5 * 2**20, "sbom_store_bytes": 2**20, "work_bytes": 0, "disk_free_bytes": 50 * 2**30}

    first = reporting.maybe_send_digest(mail_cfg, store, FakeSlm(mail_cfg), disk)
    assert first["sent"]
    subject, text, _html, _u = outbox[0]
    assert "Tagesbericht" in subject and "1 kritisch" in subject and "1 KEV" in subject
    assert "Lage ruhig." in text and "syft timeout" in text and "Speicher: Reports 5.0 MB" in text
    assert reporting.maybe_send_digest(mail_cfg, store, FakeSlm(mail_cfg), disk) is None


def test_smtp_roundtrip_builds_multipart(mail_cfg, monkeypatch):
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, **kw): captured["addr"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def starttls(self, context=None): captured["tls"] = True
        def login(self, u, p): captured["login"] = (u, p)
        def send_message(self, msg): captured["msg"] = msg

    monkeypatch.setattr(reporting.smtplib, "SMTP", FakeSMTP)
    mail_cfg.smtp_user, mail_cfg.smtp_password = "u", "p"
    reporting.send_mail(mail_cfg, "Betreff", "text", "<b>html</b>", urgent=True)
    msg = captured["msg"]
    assert captured["tls"] and captured["login"] == ("u", "p")
    assert msg["To"] == "it@example.org" and msg["X-Priority"] == "1" and msg["Auto-Submitted"] == "auto-generated"
    assert msg.is_multipart() and {p.get_content_type() for p in msg.iter_parts()} == {"text/plain", "text/html"}


def test_same_advisory_in_several_images_and_packages_is_listed_once(mail_cfg, store, outbox):
    store.mark_inventory("docker", {"a:1": None, "b:1": None})
    for target in ("a:1", "b:1"):
        store.ingest_findings(target, [
            finding("CVE-2026-1", severity="Critical", pkg="libssl3", version="3.0", fix_versions=["3.1"]),
            finding("CVE-2026-1", severity="Critical", pkg="libcrypto3", version="3.0", fix_versions=["3.1"]),
            finding("CVE-2026-2", severity="Critical", pkg="busybox", version="1.0", fix_versions=["1.1"]),
        ], prio(mail_cfg), baseline=True)
    reporting.send_digest(mail_cfg, store, FakeSlm(mail_cfg, enabled=False))
    text = outbox[-1][1]
    assert text.count("CVE-2026-1 —") == 1
    assert "a:1, b:1" in text
    assert "libssl3" in text and "libcrypto3" in text                  # both packages get an action line
    assert text.count("CVE-2026-2 —") == 1


def test_group_findings_keeps_order_and_collects_targets():
    rows = [
        {"vuln_id": "X", "target": "a", "pkg": "p", "version": "1", "fix_versions": ["2"]},
        {"vuln_id": "Y", "target": "a", "pkg": "q", "version": "1", "fix_versions": []},
        {"vuln_id": "X", "target": "b", "pkg": "p", "version": "1", "fix_versions": ["2"]},
    ]
    grouped = reporting.group_findings(rows)
    assert [g["vuln_id"] for g in grouped] == ["X", "Y"]
    assert grouped[0]["targets"] == ["a", "b"] and len(grouped[0]["pkgs"]) == 1
