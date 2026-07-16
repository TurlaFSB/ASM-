from sqlalchemy import Column, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.db import Base


class ScanAsset(Base):
    """
    Association between a scan and the assets that were live/observed
    during that specific scan. Enables point-in-time asset inventory
    for VAPT reports, independent of the Asset table's mutable current state.
    """
    __tablename__ = "scan_assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
