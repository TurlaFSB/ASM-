from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.sql import func
from backend.db import Base


class ScanSnapshot(Base):
    """Normalized, comparable view of one completed scan (see backend/diffing/snapshot.py)."""
    __tablename__ = "scan_snapshots"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_scan_snapshots_scan_id"),)

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    profile = Column(String, nullable=False, index=True)
    schema_version = Column(Integer, nullable=False)
    content_hash = Column(String, nullable=False)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
