import threading
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend import cancellation as cx
from backend import watchdog as wd
from backend.db import Base
from backend.models import Target
from backend.models.scan import Scan


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


class R:
    def __init__(self): self.keys = {}
    def exists(self, k): return 1 if k in self.keys else 0
    def get(self, k): return self.keys.get(k)
    def setex(self, k, ttl, v): self.keys[k] = v


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    s.add(Target(domain="10.0.0.5", authorized=True, authorized_by="me")); s.commit()
    return s


def mk(db, status, age, task="x", started=True):
    t = NOW - timedelta(seconds=age)
    s = Scan(target_id=1, status=status, celery_task_id=task, created_at=t, started_at=t if started else None)
    db.add(s); db.commit(); return s


def test_running_scan_with_lost_lock_is_failed(db):
    s = mk(db, "running", 3600)
    assert wd.reap_stuck_scans(db, R(), NOW) == {"running": 1, "pending": 0}
    db.refresh(s)
    assert s.status == "failed" and "worker" in s.error_log and s.completed_at is not None


def test_running_scan_with_live_lock_is_left_alone(db):
    s = mk(db, "running", 3600); r = R(); r.keys[cx.lock_key(1)] = "t"
    assert wd.reap_stuck_scans(db, r, NOW)["running"] == 0
    db.refresh(s); assert s.status == "running"


def test_young_running_scan_is_not_reaped_before_it_takes_the_lock(db):
    s = mk(db, "running", 60)
    assert wd.reap_stuck_scans(db, R(), NOW)["running"] == 0


def test_over_max_runtime_is_failed_even_if_lock_is_held(db):
    s = mk(db, "running", wd.SCAN_MAX_SECONDS + wd.REAP_GRACE_SECONDS + 5); r = R(); r.keys[cx.lock_key(1)] = "t"
    assert wd.reap_stuck_scans(db, r, NOW)["running"] == 1
    db.refresh(s); assert "maximum runtime" in s.error_log and r.keys[cx.flag_key(s.id)] == "1"


def test_redis_down_leaves_running_scans_alone(db):
    class Down(R):
        def exists(self, k): raise RuntimeError("down")
    s = mk(db, "running", 3600)
    assert wd.reap_stuck_scans(db, Down(), NOW)["running"] == 0


def test_pending_rules(db):
    old = mk(db, "pending", wd.SCAN_PENDING_MAX_SECONDS + 10, started=False)
    wd.reap_stuck_scans(db, R(), NOW); db.refresh(old); assert old.status == "failed"
    db.delete(old); db.commit()
    unq = mk(db, "pending", 1200, task=None, started=False)
    assert wd.reap_stuck_scans(db, R(), NOW)["pending"] == 1
    db.refresh(unq); assert unq.status == "failed"
    db.delete(unq); db.commit()
    ok = mk(db, "pending", 1200, started=False)
    assert wd.reap_stuck_scans(db, R(), NOW)["pending"] == 0


def test_guard_enforces_deadline_and_checkpoint_raises_timeout():
    now = [0.0]; killed = []
    g = cx.ScanGuard(R(), 1, poll=0.01, killer=lambda: killed.append(1) or [], max_seconds=100, clock=lambda: now[0])
    g.start()
    g.checkpoint()                                   # inside the budget: fine
    now[0] = 101.0
    assert g.timed_out.wait(2) and killed
    with pytest.raises(cx.ScanTimedOut):
        g.checkpoint()
    assert issubclass(cx.ScanTimedOut, cx.ScanCancelled)
    g.stop()
