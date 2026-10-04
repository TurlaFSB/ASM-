import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import exports
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.finding_triage import FindingTriage
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.tests.test_vuln_api import _jsonb_as_json  # noqa: F401  (JSONB shim for SQLite)


@pytest.fixture()
def env():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="example.org", authorized=True, authorized_by="me", is_active=True)
    db.add(t); db.commit()
    sc = Scan(target_id=t.id, status="completed", completed_at=datetime.now(timezone.utc))
    db.add(sc); db.commit()
    v1 = Vulnerability(target_id=t.id, scan_id=sc.id, template_id="CVE-2021-41773", name="Apache traversal", severity="critical",
                       host="example.org", matched_at="https://example.org:443/x", cve_id="CVE-2021-41773", cvss_score=9.8, tags=["cve"])
    v2 = Vulnerability(target_id=t.id, scan_id=sc.id, template_id="tls-old", name="TLS 1.0", severity="medium",
                       host="example.org", matched_at="example.org:443", description="Old protocol")
    db.add_all([v1, v2]); db.commit()
    db.add(FindingTriage(target_id=t.id, key=v2.finding_key, status="accepted_risk", note="Legacy client", updated_by="admin"))
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="u", role="viewer", is_active=True)
    yield TestClient(app), sc
    app.dependency_overrides.clear()


def test_json_export_has_triage(env):
    c, sc = env
    r = c.get(f"/scans/{sc.id}/export/vulnerabilities.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    data = r.json()
    assert data["target"] == "example.org" and len(data["findings"]) == 2
    by = {f["template_id"]: f for f in data["findings"]}
    assert by["CVE-2021-41773"]["triage"] == {"status": "open"}
    assert by["tls-old"]["triage"]["status"] == "accepted_risk" and by["tls-old"]["triage"]["note"] == "Legacy client"


def test_sarif_export_structure_and_suppressions(env):
    c, sc = env
    r = c.get(f"/scans/{sc.id}/export/vulnerabilities.sarif")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
    s = r.json()
    assert s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "ASM Platform"
    rules = {x["id"]: x for x in s["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["CVE-2021-41773"]["helpUri"].endswith("CVE-2021-41773") and "helpUri" not in rules["tls-old"]
    res = {x["ruleId"]: x for x in s["runs"][0]["results"]}
    assert res["CVE-2021-41773"]["level"] == "error" and "suppressions" not in res["CVE-2021-41773"]
    assert res["tls-old"]["level"] == "warning"
    sup = res["tls-old"]["suppressions"][0]
    assert sup["status"] == "accepted" and "Legacy client" in sup["justification"]
    assert res["tls-old"]["partialFingerprints"]["asmFindingKey"]


def test_unknown_scan_is_404(env):
    c, _ = env
    assert c.get("/scans/9999/export/vulnerabilities.sarif").status_code == 404
    assert c.get("/scans/9999/export/vulnerabilities.json").status_code == 404


def test_unknown_severity_falls_back_to_info():
    v = SimpleNamespace(id=1, severity="weird", name="n", template_id="t", host="h", matched_at="", cve_id=None,
                        cvss_score=None, tags=None, description=None, finding_key=None)
    scan = SimpleNamespace(id=1, profile="quick", status="completed", completed_at=None)
    s = exports.build_sarif(scan, "d", [v], {})
    assert s["runs"][0]["results"][0]["level"] == "note"
    assert s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "h"
