from sqlalchemy.orm import Session
from backend.models.audit_log import AuditLog


def log_action(db: Session, username: str, action: str, target_id: int = None,
                scan_id: int = None, detail: dict = None, ip_address: str = None):
    """
    Record an audit log entry. Called at key action points (target create/delete,
    scan trigger/cancel) to maintain a compliance-grade trail of who did what, when.
    Does not raise on failure -- an audit log write should never break the
    primary operation it's logging.
    """
    try:
        entry = AuditLog(
            username=username,
            action=action,
            target_id=target_id,
            scan_id=scan_id,
            detail=detail,
            ip_address=ip_address,
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
