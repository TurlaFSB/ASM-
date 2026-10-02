from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.alert import Alert
from backend.models.webhook_delivery import WebhookDelivery
from backend.auth import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/")
def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    target_id: int = None,
    alert_type: str = None,
    severity: str = Query(None, description="comma-separated, e.g. critical,high"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    query = db.query(Alert)
    if target_id is not None:
        query = query.filter(Alert.target_id == target_id)
    if alert_type is not None:
        query = query.filter(Alert.alert_type == alert_type)
    if severity:
        query = query.filter(Alert.severity.in_([x.strip().lower() for x in severity.split(",") if x.strip()]))
    alerts = query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit).offset(offset).all()
    return alerts


@router.get("/deliveries")
def list_deliveries(limit: int = Query(50, ge=1, le=200), target_id: int = None,
                    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Recent webhook delivery attempts (audit trail; the webhook URL itself is never exposed)."""
    q = db.query(WebhookDelivery)
    if target_id is not None:
        q = q.filter(WebhookDelivery.target_id == target_id)
    return [{"id": d.id, "target_id": d.target_id, "scan_id": d.scan_id, "host": d.host, "kind": d.kind,
             "status": d.status, "http_status": d.http_status, "attempts": d.attempts,
             "event_count": d.event_count, "error": d.error,
             "created_at": d.created_at.isoformat() if d.created_at else None}
            for d in q.order_by(WebhookDelivery.id.desc()).limit(limit).all()]

@router.get("/unread")
def unread_alerts(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    alerts = db.query(Alert).filter(Alert.is_read == False).order_by(Alert.created_at.desc()).limit(limit).offset(offset).all()
    return alerts

@router.patch("/{alert_id}/read")
def mark_read(alert_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.is_read = True
        db.commit()
    return {"status": "ok"}

@router.patch("/mark-all-read")
def mark_all_read(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    db.query(Alert).filter(Alert.is_read == False).update({"is_read": True})
    db.commit()
    return {"status": "ok"}
