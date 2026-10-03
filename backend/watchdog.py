"""Watchdog for scans that can no longer finish on their own.

A worker that is killed, OOM'd or lost mid-scan leaves its Scan row 'running' forever; with one
active scan allowed per target that would block the target for good. `reap_stuck_scans` (run by
celery beat) fails such rows. A live worker also enforces SCAN_MAX_SECONDS itself via ScanGuard.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from backend import cancellation as cx
from backend.models.scan import Scan

logger = logging.getLogger(__name__)

SCAN_MAX_SECONDS = int(os.getenv("SCAN_MAX_SECONDS", "21600"))               # 6h hard runtime cap
SCAN_PENDING_MAX_SECONDS = int(os.getenv("SCAN_PENDING_MAX_SECONDS", "43200"))  # 12h waiting in the queue
REAP_GRACE_SECONDS = 600       # let a live worker's own timeout fire first
LOCK_STARTUP_SECONDS = 300     # a scan this young may not have taken its lock yet
UNQUEUED_SECONDS = 600         # pending with no celery task id this long = never queued


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _fail(db, scan: Scan, reason: str, redis_client, now: datetime) -> None:
    scan.status = "failed"
    scan.current_stage = None
    scan.completed_at = now
    scan.error_log = reason
    try:
        cx.request_cancel(redis_client, scan.id)    # if a worker is somehow alive, make it stop
    except Exception:  # noqa: BLE001
        pass


def reap_stuck_scans(db, redis_client, now: Optional[datetime] = None) -> Dict[str, int]:
    now = now or datetime.now(timezone.utc)
    out = {"running": 0, "pending": 0}

    for s in db.query(Scan).filter(Scan.status == "running").all():
        started = _aware(s.started_at) or _aware(s.created_at) or now
        age = (now - started).total_seconds()
        if age > SCAN_MAX_SECONDS + REAP_GRACE_SECONDS:
            _fail(db, s, f"Scan exceeded the maximum runtime of {SCAN_MAX_SECONDS // 60} minutes", redis_client, now)
            out["running"] += 1
            continue
        if age > LOCK_STARTUP_SECONDS:
            try:
                held = bool(redis_client.exists(cx.lock_key(s.target_id)))
            except Exception:  # noqa: BLE001  can't tell: leave it for the next pass
                continue
            if not held:
                _fail(db, s, "Scan stopped unexpectedly (the worker running it was lost)", redis_client, now)
                out["running"] += 1

    for s in db.query(Scan).filter(Scan.status == "pending").all():
        age = (now - (_aware(s.created_at) or now)).total_seconds()
        if age > SCAN_PENDING_MAX_SECONDS:
            _fail(db, s, "Scan waited too long in the queue and was dropped", redis_client, now)
            out["pending"] += 1
        elif not s.celery_task_id and age > UNQUEUED_SECONDS:
            _fail(db, s, "Scan was never queued for a worker", redis_client, now)
            out["pending"] += 1

    if out["running"] or out["pending"]:
        db.commit()
        logger.warning(f"[watchdog] failed stuck scans: {out}")
    return out
