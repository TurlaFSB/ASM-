from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from backend.db import Base


class WebhookDelivery(Base):
    """One attempt series to deliver a scan's change digest. Kept as an audit trail: what was sent,
    to which host (never the full URL, it may embed a token), and how it ended."""
    __tablename__ = "webhook_deliveries"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    host = Column(String, nullable=False, default="")
    kind = Column(String, nullable=False, default="digest")      # digest | test
    status = Column(String, nullable=False)                      # sent | failed | blocked
    http_status = Column(Integer, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    event_count = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
