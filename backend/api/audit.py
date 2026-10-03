from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.audit_log import AuditLog
from backend.auth import require_admin

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/")
def list_audit_logs(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs
