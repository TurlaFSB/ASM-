"""A control changed in the UI must be saved by the API AND honoured by the code that acts on it."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import tasks
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.scan import Scan
from backend.models.schedule import ScheduledScan


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    t = Target(domain="acme.com", authorized=True, authorized_by="me", is_active=True)
    db.add(t)
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="pranav", role="admin")
    import backend.db as dbmod
    monkeypatch.setattr(dbmod, "SessionLocal", Session)          # what the beat task opens
    launched = []

    def fake_delay(**kw):
        launched.append(kw)
        return SimpleNamespace(id=f"task-{len(launched)}")
    import backend.api.scans as scans_api
    monkeypatch.setattr(scans_api.run_scan, "delay", fake_delay)
    monkeypatch.setattr(tasks.run_scan, "delay", fake_delay)
    monkeypatch.setattr(scans_api, "request_cancel", lambda *a, **k: None)
    monkeypatch.setattr(scans_api.celery_app.control, "revoke", lambda *a, **k: None)
    yield SimpleNamespace(db=db, t=t, c=TestClient(app), launched=launched, Session=Session)
    app.dependency_overrides.clear()


def _due_schedule(db, t, enabled=True):
    s = ScheduledScan(target_id=t.id, cron_expression="0 3 * * *", enabled=enabled,
                      next_run_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    db.add(s)
    db.commit()
    return s


# ---- scan options ----

def test_target_directory_toggle_reaches_manual_and_scheduled_scans(env):
    c, t = env.c, env.t
    assert c.patch(f"/targets/{t.id}/dirbuster-toggle", json={"dirbuster_enabled": False}).status_code == 200
    env.db.refresh(t)
    assert t.dirbuster_enabled is False
    assert c.post("/scans/", json={"target_id": t.id, "profile": "standard"}).status_code == 200
    assert env.launched[-1]["enable_dirbuster"] is False
    # the scheduler honours it too
    env.db.query(Scan).update({"status": "completed"})
    _due_schedule(env.db, t)
    tasks.check_scheduled_scans()
    assert env.launched[-1]["enable_dirbuster"] is False


def test_per_scan_veto_and_profile_decide_directory_discovery(env):
    c, t = env.c, env.t
    assert c.post("/scans/", json={"target_id": t.id, "profile": "standard", "run_dirbuster": False}).status_code == 200
    assert env.launched[-1]["enable_dirbuster"] is False
    env.db.query(Scan).update({"status": "completed"})
    assert c.post("/scans/", json={"target_id": t.id, "profile": "quick"}).status_code == 200
    assert env.launched[-1]["enable_dirbuster"] is False and env.launched[-1]["profile"] == "quick"
    env.db.query(Scan).update({"status": "completed"})
    assert c.post("/scans/", json={"target_id": t.id, "profile": "standard"}).status_code == 200
    assert env.launched[-1]["enable_dirbuster"] is True


def test_default_profile_is_used_by_manual_and_scheduled_scans(env):
    c, t = env.c, env.t
    assert c.patch(f"/targets/{t.id}/profile", json={"default_profile": "deep"}).status_code == 200
    assert c.patch(f"/targets/{t.id}/profile", json={"default_profile": "bogus"}).status_code == 422
    assert c.post("/scans/", json={"target_id": t.id}).status_code == 200
    assert env.launched[-1]["profile"] == "deep"
    env.db.query(Scan).update({"status": "completed"})
    _due_schedule(env.db, t)
    tasks.check_scheduled_scans()
    assert env.launched[-1]["profile"] == "deep"


# ---- schedules ----

def test_paused_schedule_never_fires_and_resuming_waits_for_the_next_slot(env):
    c, t, db = env.c, env.t, env.db
    s = _due_schedule(db, t, enabled=True)
    assert c.patch(f"/schedules/{s.id}", json={"enabled": False}).json()["enabled"] is False
    tasks.check_scheduled_scans()
    assert env.launched == []                                    # paused: a due time is ignored
    # resume (explicit set, idempotent): must not fire for the time that passed while paused
    r = c.patch(f"/schedules/{s.id}", json={"enabled": True}).json()
    assert r["enabled"] is True
    assert c.patch(f"/schedules/{s.id}", json={"enabled": True}).json()["enabled"] is True
    db.refresh(s)
    nxt = s.next_run_at if s.next_run_at.tzinfo else s.next_run_at.replace(tzinfo=timezone.utc)
    assert nxt > datetime.now(timezone.utc)
    tasks.check_scheduled_scans()
    assert env.launched == []


def test_legacy_toggle_endpoint_also_reschedules_on_resume(env):
    c, t, db = env.c, env.t, env.db
    s = _due_schedule(db, t, enabled=False)
    assert c.patch(f"/schedules/{s.id}/toggle").json()["enabled"] is True
    tasks.check_scheduled_scans()
    assert env.launched == []


def test_enabled_due_schedule_does_fire_and_advances(env):
    s = _due_schedule(env.db, env.t)
    tasks.check_scheduled_scans()
    assert len(env.launched) == 1
    env.db.refresh(s)
    assert s.last_run_at is not None


# ---- deleting a target ----

def test_deleting_a_target_pauses_schedules_cancels_scans_and_hides_them(env):
    c, t, db = env.c, env.t, env.db
    s = _due_schedule(db, t)
    scan = Scan(target_id=t.id, status="running")
    db.add(scan)
    db.commit()
    assert [x["id"] for x in c.get("/schedules/").json()] == [s.id]
    assert c.delete(f"/targets/{t.id}").status_code == 200
    db.refresh(s); db.refresh(scan); db.refresh(t)
    assert t.is_active is False and s.enabled is False and scan.status == "cancelled"
    assert c.get("/schedules/").json() == []
    tasks.check_scheduled_scans()
    assert env.launched == []
    assert c.post("/scans/", json={"target_id": t.id}).status_code == 404


# ---- exposure sources ----

def test_exposure_source_switch_controls_the_sweep(env, monkeypatch):
    c, t, db = env.c, env.t, env.db
    queued = []
    monkeypatch.setattr(tasks.run_exposure_checks, "apply_async", lambda args, countdown=0: queued.append(args[0]))
    assert tasks.exposure_sweep() == {"queued": 0}               # nothing switched on
    assert c.put(f"/exposure/targets/{t.id}/sources", json={"sources": ["xposedornot"]}).status_code == 200
    assert tasks.exposure_sweep() == {"queued": 1} and queued == [t.id]
    assert c.put(f"/exposure/targets/{t.id}/sources", json={"sources": []}).status_code == 200
    assert tasks.exposure_sweep() == {"queued": 0} and queued == [t.id]    # switched off again: not queued


# ---- notification settings ----

def test_notification_settings_round_trip_and_partial_updates_keep_the_rest(env):
    c, t = env.c, env.t
    r = c.put(f"/targets/{t.id}/notifications", json={"alert_min_severity": "critical", "webhook_format": "slack",
                                                      "email_recipients": ["Sec@Acme.com", "sec@acme.com"]})
    assert r.status_code == 200
    got = c.get(f"/targets/{t.id}/notifications").json()
    assert got["alert_min_severity"] == "critical" and got["webhook_format"] == "slack"
    assert got["email_recipients"] == ["sec@acme.com"]
    # a partial update (only recipients) must not reset the threshold or format to defaults
    assert c.put(f"/targets/{t.id}/notifications", json={"email_recipients": []}).status_code == 200
    got = c.get(f"/targets/{t.id}/notifications").json()
    assert got["alert_min_severity"] == "critical" and got["webhook_format"] == "slack" and got["email_recipients"] == []
    assert c.put(f"/targets/{t.id}/notifications", json={"alert_min_severity": "nonsense"}).status_code == 422
    assert c.get(f"/targets/{t.id}/notifications").json()["alert_min_severity"] == "critical"   # a rejected save changes nothing
