import pytest

from config import Settings
from store import Store


@pytest.fixture
def cfg(tmp_path):
    c = Settings(report_dir=tmp_path / "reports", data_dir=tmp_path / "data")
    c.scheduler_enabled = False
    c.ensure_dirs()
    return c


@pytest.fixture
def store(cfg):
    s = Store(cfg.db_path)
    yield s
    s.close()


def finding(vuln_id="CVE-2024-0001", pkg="openssl", version="3.0.1", severity="Critical", **kw):
    base = {
        "vuln_id": vuln_id, "pkg": pkg, "version": version, "cve_ids": [vuln_id] if vuln_id.startswith("CVE-") else [],
        "severity": severity, "cvss": 9.8, "epss": 0.1, "kev": False, "ransomware": False,
        "fix_versions": ["3.0.9"], "description": "demo",
    }
    base.update(kw)
    return base


def grype_match(vuln_id="CVE-2024-0001", severity="High", name="openssl", version="3.0.1", **vuln_extra):
    vuln = {"id": vuln_id, "severity": severity, "description": "d", "fix": {"versions": ["3.0.9"], "state": "fixed"}}
    vuln.update(vuln_extra)
    return {"vulnerability": vuln, "relatedVulnerabilities": [], "artifact": {"name": name, "version": version}}
