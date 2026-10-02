from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.db import get_db
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan

router = APIRouter(prefix="/changes", tags=["changes"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _view(e: ChangeEvent) -> dict:
    return {"id": e.id, "target_id": e.target_id, "scan_id": e.scan_id, "baseline_scan_id": e.baseline_scan_id,
            "category": e.category, "change_type": e.change_type, "asset": e.asset, "subject": e.subject,
            "severity": e.severity, "confidence": e.confidence, "status": e.status, "summary": e.summary,
            "group": e.group, "before": e.before, "after": e.after,
            "created_at": e.created_at.isoformat() if e.created_at else None}


@router.get("/")
def list_changes(
    target_id: Optional[int] = None,
    scan_id: Optional[int] = None,
    severity: Optional[str] = Query(None, description="comma-separated, e.g. critical,high"),
    category: Optional[str] = None,
    confidence: Optional[str] = None,
    status: str = Query("confirmed", pattern="^(confirmed|pending|dismissed|superseded)$"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    q = db.query(ChangeEvent).filter(ChangeEvent.status == status)
    if target_id is not None:
        q = q.filter(ChangeEvent.target_id == target_id)
    if scan_id is not None:
        q = q.filter(ChangeEvent.scan_id == scan_id)
    if severity:
        wanted = [s.strip().lower() for s in severity.split(",") if s.strip()]
        bad = [s for s in wanted if s not in SEVERITIES]
        if bad:
            raise HTTPException(status_code=422, detail=f"unknown severity: {', '.join(bad)}")
        q = q.filter(ChangeEvent.severity.in_(wanted))
    if category:
        q = q.filter(ChangeEvent.category == category)
    if confidence:
        q = q.filter(ChangeEvent.confidence == confidence)
    rows = q.order_by(ChangeEvent.created_at.desc(), ChangeEvent.id.desc()).limit(limit).offset(offset).all()
    return [_view(r) for r in rows]


@router.get("/scans/{scan_id}")
def scan_changes(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Everything that changed in one scan versus its baseline, with counts and comparison coverage."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan_id, ChangeEvent.status == "confirmed").all()
    rows.sort(key=lambda r: (SEVERITIES.index(r.severity) if r.severity in SEVERITIES else 9, r.category, r.asset, r.subject))
    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    detail = (scan.module_results or {}).get("diff_detail") or {}
    pending = db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan_id, ChangeEvent.status == "pending").count()
    return {"scan_id": scan_id, "profile": scan.profile,
            "baseline_scan_id": detail.get("baseline_scan_id"),
            "is_baseline": bool(detail.get("baseline")) or (scan.module_results or {}).get("diff") == "baseline recorded",
            "counts": counts, "pending_removals": pending, "not_compared": detail.get("skipped", []),
            "events": [_view(r) for r in rows]}
