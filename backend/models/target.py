from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from backend.db import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False, index=True)
    
    # Authorization gate — enforced at DB level
    authorized = Column(Boolean, default=False, nullable=False)
    authorized_by = Column(String, nullable=True)
    authorized_at = Column(DateTime(timezone=True), nullable=True)
    scope_note = Column(Text, nullable=True)
    whois_data = Column(JSONB, nullable=True)  # {"domain_whois": {...}, "asn": {...}}
    webhook_url = Column(String, nullable=True)
    
    # Rate limiting per target
    rate_limit = Column(Integer, default=10)
    dirbuster_enabled = Column(Boolean, default=True)  # persisted per-target toggle for the directory discovery pipeline stage
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)

    # Relationships
    assets = relationship("Asset", back_populates="target")
    scans = relationship("Scan", back_populates="target")