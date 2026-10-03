"""Run the enabled collectors for one target and fold the results into exposure_findings."""
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.exposure import registry
from backend.exposure.base import CollectorError, Finding, NotApplicable, RateLimited, SEVERITIES, fingerprint
from backend.exposure.http import HttpClient
from backend.exposure.notify import notify_exposure
from backend.models.exposure import CollectorRun, ExposureFinding
from backend.models.target import Target

logger = logging.getLogger(__name__)

STALE_RUN_SECONDS = 30 * 60
RESOLVE_AFTER_MISSES = 3          # runs in a row that no longer return a finding before it counts as resolved
MAX_FINDINGS_PER_RUN = 500
MIN_FORCE_GAP_SECONDS = 300       # "run now" can still not hammer a source
RETRY_AFTER_FAILURE_SECONDS = 3600


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def enabled_sources(target: Target) -> List[str]:
    return [s for s in (target.exposure_sources or []) if registry.get(s)]


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _close_stale(db: Session, target_id: int, source: str, now: datetime) -> None:
    cutoff = now - timedelta(seconds=STALE_RUN_SECONDS)
    for r in db.query(CollectorRun).filter(CollectorRun.target_id == target_id, CollectorRun.source == source,
                                           CollectorRun.status == "running").all():
        if _aware(r.started_at) < cutoff:
            r.status, r.error, r.finished_at = "failed", "stale (worker stopped)", now
    db.commit()


def _too_soon(db: Session, target_id: int, collector, force: bool, now: datetime) -> Optional[str]:
    last = (db.query(CollectorRun).filter(CollectorRun.target_id == target_id, CollectorRun.source == collector.name,
                                          CollectorRun.status.in_(("ok", "failed", "rate_limited", "skipped")))
            .order_by(CollectorRun.started_at.desc()).first())
    if last is None:
        return None
    age = (now - _aware(last.started_at)).total_seconds()
    if force:
        return "too_soon" if age < MIN_FORCE_GAP_SECONDS else None
    wait = collector.min_interval_seconds if last.status in ("ok", "skipped") else min(collector.min_interval_seconds, RETRY_AFTER_FAILURE_SECONDS)
    return "too_soon" if age < wait else None


def _upsert(db: Session, target: Target, source: str, findings: List[Finding],
            now: datetime, complete: bool = True) -> Tuple[List[Tuple[ExposureFinding, str]], int]:
    findings = sorted(findings, key=lambda f: (_rank(f.severity), f.key))[:MAX_FINDINGS_PER_RUN]
    existing = {f.fingerprint: f for f in db.query(ExposureFinding).filter(
        ExposureFinding.target_id == target.id, ExposureFinding.source == source).all()}
    notify: List[Tuple[ExposureFinding, str]] = []
    seen = set()
    for f in findings:
        fp = fingerprint(source, f.key)
        if fp in seen:
            continue
        seen.add(fp)
        row = existing.get(fp)
        if row is None:
            row = ExposureFinding(target_id=target.id, source=source, kind=f.kind, fingerprint=fp, title=f.title,
                                  summary=f.summary, severity=f.severity, url=f.url, evidence=f.evidence,
                                  status="open", seen_count=1, missed_runs=0, first_seen=now, last_seen=now)
            db.add(row)
            db.flush()
            notify.append((row, "new"))
            continue
        reason = None
        if row.status == "resolved":
            row.status, reason = "open", "reappeared"
        elif row.status == "open" and _rank(f.severity) < _rank(row.severity):
            reason = "escalated"
        row.title, row.summary, row.url, row.evidence, row.kind = f.title, f.summary, f.url, f.evidence, f.kind
        row.severity = f.severity
        row.seen_count = (row.seen_count or 0) + 1
        row.missed_runs, row.last_seen = 0, now
        if reason:
            notify.append((row, reason))
    for fp, row in existing.items():
        if complete and fp not in seen and row.status == "open":
            row.missed_runs = (row.missed_runs or 0) + 1
            if row.missed_runs >= RESOLVE_AFTER_MISSES:
                row.status = "resolved"
    db.commit()
    return notify, len(seen)


def run_collectors(db: Session, target: Target, sources: Optional[List[str]] = None, *, force: bool = False,
                   http=None, sleep=time.sleep, now: Optional[datetime] = None) -> Dict[str, Dict]:
    """Returns {source: {"status": ..., "found": n, "new": n}}. One source failing never affects the others."""
    now = now or datetime.now(timezone.utc)
    result: Dict[str, Dict] = {}
    if not target.is_active:
        return result
    http = http or HttpClient()
    wanted = enabled_sources(target)
    if sources is not None:
        wanted = [s for s in wanted if s in sources]
    to_notify: List[Tuple[ExposureFinding, str]] = []
    for name in wanted:
        collector = registry.get(name)
        if not collector.configured():
            result[name] = {"status": "not_configured", "found": 0, "new": 0}
            continue
        _close_stale(db, target.id, name, now)
        reason = _too_soon(db, target.id, collector, force, now)
        if reason:
            result[name] = {"status": reason, "found": 0, "new": 0}
            continue
        run = CollectorRun(target_id=target.id, source=name, status="running", started_at=now)
        db.add(run)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            result[name] = {"status": "already_running", "found": 0, "new": 0}
            continue
        try:
            found = collector.collect(target.domain, http, sleep)
            fresh, count = _upsert(db, target, name, found, now, complete=getattr(found, "complete", True))
            run.status, run.found, run.new = "ok", count, len(fresh)
            to_notify.extend(fresh)
        except RateLimited:
            db.rollback()
            run.status, run.error = "rate_limited", "rate limited"
        except NotApplicable as e:
            db.rollback()
            run.status, run.error = "skipped", e.label[:80]
        except CollectorError as e:
            db.rollback()
            run.status, run.error = "failed", e.label[:80]
        except Exception as e:  # noqa: BLE001
            db.rollback()
            logger.exception("[exposure] collector %s crashed", name)
            run.status, run.error = "failed", "internal error"
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
        db.commit()
        result[name] = {"status": run.status, "found": run.found or 0, "new": run.new or 0}
    if to_notify:
        notify_exposure(db, target, to_notify, sleep=sleep)
    return result
