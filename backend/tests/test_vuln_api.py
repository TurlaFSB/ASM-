from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from backend.db import Base, get_db
from backend.main import app
from backend.auth import get_current_user
from backend.models import Target
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):  # let Postgres-typed models run on in-memory SQLite
    return "JSON"


@pytest.fixture()
def client():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    db = S()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me")
    db.add(t); db.commit()
    s1 = Scan(target_id=t.id, status="completed"); s2 = Scan(target_id=t.id, status="completed")
    s3 = Scan(target_id=t.id, status="running")
    db.add_all([s1, s2, s3]); db.commit()

    def v(scan, sev, name, cvss=None, tags=None):
        db.add(Vulnerability(target_id=t.id, scan_id=scan.id, template_id=name, name=name, severity=sev,
                             host="10.0.0.5", cvss_score=cvss, tags=tags or [], matched_at="10.0.0.5:80"))
    v(s1, "critical", "old-scan-finding")                       # superseded by scan 2
    v(s2, "low", "low-one"); v(s2, "critical", "crit-vm", 9.8, ["version-match"])
    v(s2, "high", "high-one", 7.5); v(s2, "critical", "crit-verified", 9.0)
    v(s2, "info", "dmarc-note", tags=["email-security", "posture", "dns"])
    v(s2, "medium", "lookalike", tags=["posture-extra"])        # must not match tag=posture
    v(s2, "high", "wild_card%", tags=["a_b"])
    v(s3, "critical", "in-progress-scan")                       # not completed -> excluded
    db.commit()

    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_latest_scope_and_severity_order(client):
    rows = client.get("/vulnerabilities/").json()
    sevs = [r["severity"] for r in rows]
    order = ["critical", "high", "medium", "low", "info"]
    assert sevs == sorted(sevs, key=order.index)                   # most severe first
    assert sevs[0] == "critical" and sevs[-1] == "info"
    names = [r["name"] for r in rows]
    assert {"crit-vm", "crit-verified", "high-one", "low-one"} <= set(names)
    assert "old-scan-finding" not in names and "in-progress-scan" not in names


def test_summary_counts_latest_only(client):
    assert client.get("/vulnerabilities/summary").json() == {"critical": 2, "high": 2, "medium": 1, "low": 1, "info": 1}
    assert client.get("/vulnerabilities/summary?scope=all").json()["critical"] == 4


def test_verified_flag(client):
    by = {r["name"]: r for r in client.get("/vulnerabilities/").json()}
    assert by["crit-vm"]["verified"] is False and by["crit-verified"]["verified"] is True


def test_limit_validation(client):
    assert client.get("/vulnerabilities/?limit=100000").status_code == 422


def test_target_and_scan_lists_sort_by_severity_not_alphabet(client):
    for url in ("/vulnerabilities/target/1", "/vulnerabilities/scan/2"):
        sev = [r["severity"] for r in client.get(url).json()]
        order = ["critical", "high", "medium", "low", "info"]
        assert sev == sorted(sev, key=order.index), (url, sev)


def _names(resp):
    assert resp.status_code == 200, resp.text
    return sorted(r["name"] for r in resp.json())


def test_severity_filter_single_and_multiple(client):
    assert _names(client.get("/vulnerabilities/?severity=info")) == ["dmarc-note"]
    assert _names(client.get("/vulnerabilities/?severity=critical,medium")) == ["crit-verified", "crit-vm", "lookalike"]
    assert _names(client.get("/vulnerabilities/?severity=low")) == ["low-one"]


def test_tag_filter_matches_exact_tag_only(client):
    assert _names(client.get("/vulnerabilities/?tag=posture")) == ["dmarc-note"]
    assert _names(client.get("/vulnerabilities/?tag=version-match")) == ["crit-vm"]
    assert _names(client.get("/vulnerabilities/?tag=nonexistent")) == []


def test_filters_combine_and_apply_to_summary_and_rollup(client):
    assert _names(client.get("/vulnerabilities/?tag=posture&severity=high")) == []
    assert client.get("/vulnerabilities/summary?tag=posture").json() == {"info": 1}
    assert client.get("/vulnerabilities/summary?severity=critical").json() == {"critical": 2}
    roll = client.get("/vulnerabilities/rollup?tag=posture").json()
    assert roll["findings"] == 1


def test_filter_values_are_validated_and_wildcards_are_literal(client):
    assert client.get("/vulnerabilities/?severity=urgent").status_code == 422
    assert client.get("/vulnerabilities/?severity=high,").status_code == 422
    assert client.get("/vulnerabilities/?tag=%25").status_code == 422          # '%' is not a tag character
    assert client.get("/vulnerabilities/?tag=a;drop").status_code == 422
    assert _names(client.get("/vulnerabilities/?tag=a_b")) == ["wild_card%"]
    assert _names(client.get("/vulnerabilities/?tag=a.b")) == []                # '.' is literal, not a wildcard
