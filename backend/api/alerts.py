from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/")
def list_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return alerts

@router.get("/unread")
def unread_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.is_read == "unread").order_by(Alert.created_at.desc()).all()
    return alerts

@router.patch("/{alert_id}/read")
def mark_read(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.is_read = "read"
        db.commit()
    return {"status": "ok"}

@router.patch("/mark-all-read")
def mark_all_read(db: Session = Depends(get_db)):
    db.query(Alert).filter(Alert.is_read == "unread").update({"is_read": "read"})
    db.commit()
    return {"status": "ok"}
