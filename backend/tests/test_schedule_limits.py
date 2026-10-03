from types import SimpleNamespace
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
from backend.models.audit_log import AuditLog
import backend.models.schedule  # noqa: F401


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def env():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me", is_active=True)
    off = Target(domain="10.0.0.6", authorized=True, authorized_by="me", is_active=False)
    db.add_all([t, off]); db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="pranav")
    yield db, t, off, TestClient(app)
    app.dependency_overrides.clear()


@pytest.mark.parametrize("expr", ["* * * * *", "*/5 * * * *", "*/59 * * * *", "0 * * * * *", "* * * * * *", "nope", ""])
def test_rejects_too_frequent_or_malformed(env, expr):
    _, t, _, c = env
    assert c.post("/schedules/", json={"target_id": t.id, "cron_expression": expr}).status_code == 422


def test_accepts_hourly_and_daily(env):
    _, t, _, c = env
    assert c.post("/schedules/", json={"target_id": t.id, "cron_expression": "15 * * * *"}).status_code == 200
    assert c.post("/schedules/", json={"target_id": t.id, "cron_expression": "0 3 * * 1"}).status_code == 200
    assert c.post("/schedules/", json={"target_id": t.id, "preset": "hourly"}).status_code == 200


def test_inactive_target_refused(env):
    _, _, off, c = env
    assert c.post("/schedules/", json={"target_id": off.id, "preset": "daily"}).status_code == 409


def test_patch_enforces_the_same_limit(env):
    _, t, _, c = env
    sid = c.post("/schedules/", json={"target_id": t.id, "preset": "daily"}).json()["id"]
    assert c.patch(f"/schedules/{sid}", json={"cron_expression": "*/10 * * * *"}).status_code == 422
    assert c.patch(f"/schedules/{sid}", json={"cron_expression": "30 2 * * *"}).status_code == 200


def test_changes_are_audited(env):
    db, t, _, c = env
    sid = c.post("/schedules/", json={"target_id": t.id, "preset": "daily"}).json()["id"]
    c.patch(f"/schedules/{sid}/toggle"); c.delete(f"/schedules/{sid}")
    acts = [a.action for a in db.query(AuditLog).order_by(AuditLog.id)]
    assert acts == ["schedule_created", "schedule_toggled", "schedule_deleted"]
