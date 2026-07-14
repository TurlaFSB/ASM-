from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.db import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)

    # Scan lifecycle
    status = Column(String, default="pending")     # pending, running, completed, failed
    current_stage = Column(String, nullable=True)   # e.g. "subdomain_enumeration", "vuln_scanning"
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Results summary
    total_assets = Column(Integer, default=0)
    new_assets = Column(Integer, default=0)
    changed_assets = Column(Integer, default=0)
    disappeared_assets = Column(Integer, default=0)

    # Per-module status — did each scanner succeed or fail
    module_results = Column(JSON, nullable=True)   # {"subdomain": "ok", "portscan": "timeout"}

    # Error tracking
    error_log = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship
    target = relationship("Target", back_populates="scans")