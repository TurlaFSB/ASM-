from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, Float
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from backend.db import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    
    # Asset identity — natural key is target_id + subdomain
    subdomain = Column(String, nullable=False, index=True)
    ip = Column(String, nullable=True)
    
    # Scan results
    open_ports = Column(JSON, nullable=True)       # [{"port": 80, "service": "http"}]
    technologies = Column(JSON, nullable=True)     # ["nginx", "php"]
    http_status = Column(Integer, nullable=True)
    http_title = Column(String, nullable=True)
    
    # Change detection
    content_hash = Column(String, nullable=True)   # hash of ports+techs+status+title
    last_seen = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, default="active")      # active, disappeared, new
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)  # Critical, High, Medium, Low, Informational
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship
    target = relationship("Target", back_populates="assets")