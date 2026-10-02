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
    v(s3, "critical", "in-progress-scan")                       # not completed -> excluded
    db.commit()

    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_latest_scope_and_severity_order(client):
    rows = client.get("/vulnerabilities/").json()
    assert [r["name"] for r in rows] == ["crit-vm", "crit-verified", "high-one", "low-one"] \
        or [r["name"] for r in rows] == ["crit-verified", "crit-vm", "high-one", "low-one"]
    assert rows[0]["severity"] == "critical" and rows[-1]["severity"] == "low"   # critical first
    assert "old-scan-finding" not in [r["name"] for r in rows]
    assert "in-progress-scan" not in [r["name"] for r in rows]


def test_summary_counts_latest_only(client):
    assert client.get("/vulnerabilities/summary").json() == {"critical": 2, "high": 1, "low": 1}
    assert client.get("/vulnerabilities/summary?scope=all").json()["critical"] == 4


def test_verified_flag(client):
    by = {r["name"]: r for r in client.get("/vulnerabilities/").json()}
    assert by["crit-vm"]["verified"] is False and by["crit-verified"]["verified"] is True


def test_limit_validation(client):
    assert client.get("/vulnerabilities/?limit=100000").status_code == 422
