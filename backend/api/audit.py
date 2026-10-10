from typing import Optional

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.db import get_db
from backend.models.audit_log import AuditLog
from backend.auth import require_admin

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/")
def list_audit_logs(
    response: Response,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, pattern=r"^[a-z_]+(,[a-z_]+)*$", max_length=1000,
                                  description="One or more action names, comma-separated, e.g. login_failed,mfa_failed"),
    username: Optional[str] = Query(None, max_length=64, description="Only entries by this user (exact match)"),
    db: Session = Depends(get_db), current_user: dict = Depends(require_admin),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action.in_(action.split(",")))
    if username:
        q = q.filter(func.lower(AuditLog.username) == username.lower())
    response.headers["X-Total-Count"] = str(q.count())
    return q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit).offset(offset).all()
