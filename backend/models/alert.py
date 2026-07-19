from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.db import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    # Alert type: new_asset, changed_asset, disappeared_asset
    alert_type = Column(String, nullable=False, index=True)
    
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