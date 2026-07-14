from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.audit_log import AuditLog
from backend.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/")
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs
