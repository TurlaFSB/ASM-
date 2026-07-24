from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.alert import Alert
from backend.auth import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/")
def list_alerts(
    limit: int = 100,
    offset: int = 0,
    target_id: int = None,
    alert_type: str = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    query = db.query(Alert)
    if target_id is not None:
        query = query.filter(Alert.target_id == target_id)
    if alert_type is not None:
        query = query.filter(Alert.alert_type == alert_type)
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).offset(offset).all()
    return alerts

@router.get("/unread")
def unread_alerts(limit: int = 100, offset: int = 0, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
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
