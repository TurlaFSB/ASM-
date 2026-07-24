from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from backend.db import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)  # e.g. "scan_triggered", "target_created", "target_deleted", "scan_cancelled"
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    detail = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
