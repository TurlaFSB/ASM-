from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.rollup import component_of, rollup_events, rollup_findings, short_summary


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


def vm(i, comp="Apache httpd 2.4.7", sev="high", cvss=7.5, kev=False, host="10.0.0.5", scan_id=1):
    return {"id": i, "scan_id": scan_id, "target_id": 1, "host": host, "verified": False, "severity": sev,
            "name": f"[version match] {comp}: CVE-2020-{1000 + i}", "cve_id": f"CVE-2020-{1000 + i}",
            "cvss_score": cvss, "tags": ["version-match"] + (["kev"] if kev else []),
            "description": "Does bad things. More detail. Matched by service version (x). Unverified."}


def test_component_and_summary_helpers():
    assert component_of("[version match] Apache httpd 2.4.7: CVE-2017-1234 foo") == "Apache httpd 2.4.7"
    assert component_of("SSH Weak Algorithms") is None and component_of(None) is None
    assert short_summary("Does bad things. More detail. Matched by service version (x).") == "Does bad things."


def test_cves_collapse_to_one_line_per_component_and_host():
    rows = [vm(1, sev="medium", cvss=5.0), vm(2, sev="critical", cvss=9.8, kev=True), vm(3),
            vm(4, comp="ProFTPD 1.3.5", sev="low", cvss=2.0), vm(5, host="10.0.0.9")]
    items = rollup_findings(rows)
    comps = [(i["component"], i["host"]) for i in items]
    assert sorted(comps) == [("Apache httpd 2.4.7", "10.0.0.5"), ("Apache httpd 2.4.7", "10.0.0.9"),
                             ("ProFTPD 1.3.5", "10.0.0.5")]
    first = items[0]
    assert first["severity"] == "critical" and first["kev_count"] == 1 and first["max_cvss"] == 9.8
    assert first["shown"] == 3 and first["total"] == 3 and first["capped"] is False
    assert [c["cve_id"] for c in first["cves"]][0] == "CVE-2020-1002"            # KEV/critical first
    assert first["by_severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert first["cves"][0]["summary"] == "Does bad things."


def test_capped_component_reads_n_of_m_and_totals_are_per_host():
    rows = [vm(1), vm(2), vm(3, host="10.0.0.9", scan_id=1)]
    totals = {(1, "10.0.0.5", "Apache httpd 2.4.7"): 31}
    by_host = {i["host"]: i for i in rollup_findings(rows, totals)}
    assert (by_host["10.0.0.5"]["shown"], by_host["10.0.0.5"]["total"], by_host["10.0.0.5"]["capped"]) == (2, 31, True)
    assert by_host["10.0.0.9"]["total"] == 1 and by_host["10.0.0.9"]["capped"] is False


def test_verified_findings_stay_individual_and_sort_by_urgency():
    verified = {"id": 9, "scan_id": 1, "host": "10.0.0.5", "verified": True, "severity": "critical", "name": "vsftpd backdoor",
                "tags": [], "cvss_score": 9.8}
    items = rollup_findings([vm(1, sev="medium", cvss=5.0), verified])
    assert [i["kind"] for i in items] == ["finding", "component"]
    assert items[0]["name"] == "vsftpd backdoor"


def _ev(i, group="Apache httpd 2.4.7", sev="high", ctype="added", kev=False, cat="finding"):
    rec = {"cve": f"CVE-2020-{i}", "cvss": 7.5, "kev": kev}
    return {"id": i, "category": cat, "change_type": ctype, "asset": "10.0.0.5", "group": group, "severity": sev,
            "confidence": "inferred", "scan_id": 2, "before": rec if ctype == "removed" else None,
            "after": None if ctype == "removed" else rec}


def test_events_roll_up_per_component_and_change_type_others_untouched():
    port = _ev(50, group=None, cat="port")
    plain = {**_ev(51, group=None), "after": {"cve": None}}
    events = [_ev(1), _ev(2, sev="critical", kev=True), _ev(3, ctype="removed"), port, plain]
    rest, rollups = rollup_events(events)
    assert [e["id"] for e in rest] == [50, 51]
    assert [(r["component"], r["change_type"], r["shown"]) for r in rollups] == [
        ("Apache httpd 2.4.7", "added", 2), ("Apache httpd 2.4.7", "removed", 1)]
    assert rollups[0]["severity"] == "critical" and rollups[0]["kev_count"] == 1


# ---- API ----

@pytest.fixture()
def client():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me")
    db.add(t); db.commit()
    scan = Scan(target_id=t.id, status="completed", module_results={
        "cve_truncated": [{"host": "10.0.0.5", "port": 80, "label": "Apache httpd 2.4.7", "shown": 3, "total": 31}],
        "diff_detail": {"baseline_scan_id": None}},
        completed_at=datetime.now(timezone.utc))
    db.add(scan); db.commit()
    for i in range(3):
        db.add(Vulnerability(target_id=t.id, scan_id=scan.id, template_id=f"nvd-{i}", severity="high",
                             name=f"[version match] Apache httpd 2.4.7: CVE-2020-100{i}", host="10.0.0.5",
                             cve_id=f"CVE-2020-100{i}", cvss_score=7.5, tags=["version-match"], description="x. y."))
    db.add(Vulnerability(target_id=t.id, scan_id=scan.id, template_id="ftp-backdoor", severity="critical",
                         name="vsftpd backdoor", host="10.0.0.5", tags=["network"], matched_at="10.0.0.5:21"))
    for i in range(3):
        db.add(ChangeEvent(target_id=t.id, scan_id=scan.id, profile="standard", category="finding",
                           change_type="added", section="findings_cve", asset="10.0.0.5", subject=f"nvd-{i}|10.0.0.5",
                           severity="high", confidence="inferred", status="confirmed", summary="new", group="Apache httpd 2.4.7",
                           after={"cve": f"CVE-2020-{i}", "cvss": 7.5, "kev": False}, fingerprint=f"fp{i}"))
    db.add(ChangeEvent(target_id=t.id, scan_id=scan.id, profile="standard", category="port", change_type="added",
                       section="ports", asset="10.0.0.5", subject="3306/tcp", severity="high", confidence="confirmed",
                       status="confirmed", summary="port", fingerprint="fp-port"))
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    c = TestClient(app)
    c.scan_id = scan.id
    yield c
    app.dependency_overrides.clear()


def test_vuln_rollup_endpoint(client):
    r = client.get("/vulnerabilities/rollup").json()
    assert r["findings"] == 4 and r["lines"] == 2
    kinds = {i["kind"]: i for i in r["items"]}
    assert kinds["finding"]["name"] == "vsftpd backdoor"
    comp = kinds["component"]
    assert (comp["component"], comp["shown"], comp["total"], comp["capped"]) == ("Apache httpd 2.4.7", 3, 31, True)


def test_changes_scan_endpoint_always_has_rollups_and_can_collapse(client):
    full = client.get(f"/changes/scans/{client.scan_id}").json()
    assert len(full["events"]) == 4 and len(full["rollups"]) == 1 and full["rollups"][0]["shown"] == 3
    collapsed = client.get(f"/changes/scans/{client.scan_id}?collapse_cves=true").json()
    assert [e["category"] for e in collapsed["events"]] == ["port"] and len(collapsed["rollups"]) == 1


def test_changes_list_collapse_changes_shape_only_when_asked(client):
    assert isinstance(client.get("/changes/").json(), list)
    c = client.get("/changes/?collapse_cves=true").json()
    assert set(c) == {"events", "rollups"} and len(c["events"]) == 1
