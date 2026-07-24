from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.db import Base

class DiscoveredPath(Base):
    __tablename__ = "discovered_paths"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    # Discovery result
    path = Column(String, nullable=False, index=True)      # e.g. "/admin", "/backup.zip"
    status_code = Column(Integer, nullable=True)
    content_length = Column(Integer, nullable=True)
    redirect_location = Column(String, nullable=True)      # where it redirects to, if 3xx

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship
    asset = relationship("Asset")
