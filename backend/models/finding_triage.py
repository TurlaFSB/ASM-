from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.sql import func

from backend.db import Base


class FindingTriage(Base):
    """A person's decision about a finding on a target, kept across scans. See backend/triage.py."""
    __tablename__ = "finding_triage"
    __table_args__ = (UniqueConstraint("target_id", "key", name="uq_finding_triage_target_key"),)

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    key = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)
    note = Column(Text, nullable=True)
    updated_by = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
