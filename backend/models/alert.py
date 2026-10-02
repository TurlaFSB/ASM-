from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.db import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    # Alerts are generated from confirmed ChangeEvents (alert_type = "<category>_<change_type>",
    # or "changes_summary" when a scan exceeded the per-scan cap). Rows written before change-event
    # alerting keep their legacy types (new_asset, changed_asset, disappeared_asset, ...).
    alert_type = Column(String, nullable=False, index=True)
    change_event_id = Column(Integer, ForeignKey("change_events.id"), nullable=True, unique=True)
    severity = Column(String, nullable=True, index=True)
    category = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    
    # What changed
    asset_subdomain = Column(String, nullable=False)
    asset_ip = Column(String, nullable=True)
    
    # Detail of what changed
    detail = Column(JSON, nullable=True)
    
    # Read status
    is_read = Column(Boolean, default=False)
    webhook_sent = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    target = relationship("Target")
    scan = relationship("Scan")