from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text, Index
from sqlalchemy.sql import func
from backend.db import Base


class ChangeEvent(Base):
    """One structured change between two comparable scans of a target.

    status: confirmed (report it) | pending (removal seen once, held back) |
            dismissed (pending removal that turned out to be a flap) | superseded (pending
            removal replaced by its confirmed event).
    """
    __tablename__ = "change_events"
    __table_args__ = (Index("ix_change_events_target_status", "target_id", "profile", "status"),)

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    baseline_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    profile = Column(String, nullable=False)

    category = Column(String, nullable=False, index=True)    # asset|port|technology|http|path|finding
    change_type = Column(String, nullable=False)             # added|removed|modified
    section = Column(String, nullable=False)                 # coverage section it belongs to
    asset = Column(String, nullable=False, default="")
    subject = Column(String, nullable=False)                 # "8181/tcp", "/admin", finding key ...
    severity = Column(String, nullable=False, index=True)
    confidence = Column(String, nullable=False, default="confirmed")   # confirmed | inferred
    status = Column(String, nullable=False, default="confirmed")
    summary = Column(Text, nullable=False)
    group = Column(String, nullable=True)                    # e.g. product for version-matched CVEs
    before = Column(JSON, nullable=True)
    after = Column(JSON, nullable=True)
    fingerprint = Column(String, nullable=False, index=True)

    # scan that settled a pending removal (confirmed it -> superseded, or saw it return -> dismissed)
    resolved_by_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
