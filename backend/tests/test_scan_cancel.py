import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import cancellation as cx
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.scan import Scan


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


class FakeRedis:
    store = {}
    def __init__(self): pass
    @classmethod
    def from_url(cls, *a, **k): return cls()
    def get(self, k): return self.store.get(k)
    def setex(self, k, ttl, v): self.store[k] = v
    def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None); FakeLock.held.discard(k)      # a redis lock IS a key
    def lock(self, key, timeout=None): return FakeLock(key)


class FakeLock:
    held = set()
    def __init__(self, key): self.key = key
    def acquire(self, blocking=False):
        if self.key in FakeLock.held: return False
        FakeLock.held.add(self.key); return True
    def release(self): FakeLock.held.discard(self.key)
    def extend(self, *a, **k): pass


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    db = Session()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me"); db.add(t); db.commit()
    FakeRedis.store.clear(); FakeLock.held.clear()
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setattr("redis.Redis", FakeRedis)
    monkeypatch.setattr("backend.db.SessionLocal", Session)
    revoked = []
    monkeypatch.setattr("backend.api.scans.celery_app.control.revoke", lambda *a, **k: revoked.append((a, k)))
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: type("U", (), {"username": "tester"})()
    yield db, t, TestClient(app), revoked
    app.dependency_overrides.clear()


def _scan(db, t, status, task="abc"):
    s = Scan(target_id=t.id, status=status, celery_task_id=task); db.add(s); db.commit(); return s


def test_cancel_sets_flag_status_and_revokes_without_terminate(env):
    db, t, client, revoked = env
    s = _scan(db, t, "running")
    r = client.patch(f"/scans/{s.id}/cancel")
    assert r.status_code == 200
    db.refresh(s)
    assert s.status == "cancelled" and FakeRedis.store[cx.flag_key(s.id)] == "1"
    assert revoked and "terminate" not in revoked[0][1]          # SIGTERM-ing the worker is what leaked the lock


def test_cancel_rejects_finished_scan(env):
    db, t, client, _ = env
    s = _scan(db, t, "completed")
    assert client.patch(f"/scans/{s.id}/cancel").status_code == 400


def test_new_scan_allowed_right_after_cancel(env, monkeypatch):
    db, t, client, _ = env
    s = _scan(db, t, "running")
    client.patch(f"/scans/{s.id}/cancel")
    monkeypatch.setattr("backend.api.scans.run_scan.delay", lambda **k: type("T", (), {"id": "new"})())
    r = client.post("/scans/", json={"target_id": t.id})
    assert r.status_code == 200 and r.json()["status"] == "pending"


def _run(scan, t):
    from backend.tasks import run_scan
    return run_scan.run(target_id=t.id, domain=t.domain, scan_id=scan.id, profile="quick")


def test_scan_cancelled_while_queued_never_starts(env):
    db, t, _, _ = env
    s = _scan(db, t, "pending")
    cx.request_cancel(FakeRedis(), s.id)                          # flag set, DB row still pending
    assert _run(s, t) == {"status": "cancelled", "scan_id": s.id}
    db.refresh(s)
    assert s.status == "cancelled" and not FakeLock.held         # never took the lock, never went 'running'


def test_stale_lock_from_dead_worker_is_cleared(env):
    db, t, _, _ = env
    dead = _scan(db, t, "failed")                                 # owner finished/died without releasing
    FakeLock.held.add(cx.lock_key(t.id)); FakeRedis.store[cx.owner_key(t.id)] = str(dead.id)
    new = _scan(db, t, "pending")
    cx.request_cancel(FakeRedis(), new.id)                        # keep the run short: it must get past the lock first
    # cancelled-before-start returns before the lock, so exercise the lock path with a flag set after it:
    FakeRedis.store.pop(cx.flag_key(new.id))
    import backend.tasks as tasks
    seen = {}
    real = cx.ScanGuard
    class StopEarly(Exception): pass
    def guard(*a, **k):
        seen["took_lock"] = True; raise StopEarly()
    cx.ScanGuard = guard
    try:
        with pytest.raises(StopEarly):
            _run(new, t)
    finally:
        cx.ScanGuard = real
    assert seen.get("took_lock") and FakeRedis.store[cx.owner_key(t.id)] == str(new.id)


def test_lock_held_by_live_scan_is_respected(env):
    db, t, _, _ = env
    live = _scan(db, t, "running")
    FakeLock.held.add(cx.lock_key(t.id)); FakeRedis.store[cx.owner_key(t.id)] = str(live.id)
    new = _scan(db, t, "pending")
    with pytest.raises(Exception) as e:
        _run(new, t)
    assert "Retry" in type(e.value).__name__ or "retry" in str(e.value).lower()
    assert cx.lock_key(t.id) in FakeLock.held                      # untouched


def test_legacy_lock_without_owner_marker_is_cleared_when_nothing_runs(env):
    """The lock the OLD cancel leaked has no owner key; nothing is running, so it must not block."""
    db, t, _, _ = env
    _scan(db, t, "cancelled")
    FakeLock.held.add(cx.lock_key(t.id))                           # leaked, no owner marker
    new = _scan(db, t, "pending")
    import backend.tasks as tasks
    real, took = cx.ScanGuard, {}
    class StopEarly(Exception): pass
    def guard(*a, **k):
        took["lock"] = True; raise StopEarly()
    cx.ScanGuard = guard
    try:
        with pytest.raises(StopEarly):
            _run(new, t)
    finally:
        cx.ScanGuard = real
    assert took.get("lock")


def test_legacy_lock_is_kept_while_another_scan_is_really_running(env):
    db, t, _, _ = env
    _scan(db, t, "running")
    FakeLock.held.add(cx.lock_key(t.id))                           # no owner marker, but a scan IS running
    new = _scan(db, t, "pending")
    with pytest.raises(Exception) as e:
        _run(new, t)
    assert "retry" in str(e.value).lower() or "Retry" in type(e.value).__name__
    assert cx.lock_key(t.id) in FakeLock.held
