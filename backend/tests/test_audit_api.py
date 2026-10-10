from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models.audit_log import AuditLog
from backend.tests.test_auth_api import _j  # noqa: F401  (sqlite JSONB shim)


class Admin:
    role = "admin"
    username = "root"


class Viewer:
    role = "viewer"
    username = "view"


@pytest.fixture()
def client():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)
    rows = [("alice", "login_success"), ("bob", "login_failed"), ("Bob", "login_failed"), ("alice", "mfa_failed"),
            ("root", "user_created"), ("alice", "scan_triggered")]
    for i, (u, a) in enumerate(rows):
        db.add(AuditLog(username=u, action=a, ip_address="10.0.0.1", created_at=base + timedelta(minutes=i)))
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: Admin()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_newest_first_with_total_count(client):
    r = client.get("/audit/")
    assert r.status_code == 200 and r.headers["X-Total-Count"] == "6"
    assert [x["action"] for x in r.json()][:2] == ["scan_triggered", "user_created"]


def test_paging_covers_everything_once(client):
    seen = []
    for off in (0, 4):
        seen += [x["id"] for x in client.get("/audit/", params={"limit": 4, "offset": off}).json()]
    assert len(seen) == 6 and len(set(seen)) == 6


def test_action_filter_accepts_a_list(client):
    r = client.get("/audit/", params={"action": "login_failed,mfa_failed"})
    assert {x["action"] for x in r.json()} == {"login_failed", "mfa_failed"} and r.headers["X-Total-Count"] == "3"


def test_username_filter_is_exact_and_case_insensitive(client):
    assert len(client.get("/audit/", params={"username": "bob"}).json()) == 2
    assert len(client.get("/audit/", params={"username": "bo"}).json()) == 0


@pytest.mark.parametrize("bad", ["login'; drop", "A,B", "x" * 1001, "a,,b"])
def test_malformed_action_filter_is_rejected(client, bad):
    assert client.get("/audit/", params={"action": bad}).status_code == 422


def test_viewers_cannot_read_the_audit_log(client):
    from backend.auth import require_admin
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_current_user] = lambda: Viewer()
    assert client.get("/audit/").status_code == 403
