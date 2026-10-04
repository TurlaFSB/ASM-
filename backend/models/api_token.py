from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from backend.db import Base


class ApiToken(Base):
    """A long-lived credential for scripts and CI. Only a SHA-256 of the secret is stored; the secret is shown once."""
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    prefix = Column(String, nullable=False)                  # first characters of the secret, to recognise it in a list
    token_hash = Column(String, nullable=False, unique=True, index=True)
    scope = Column(String, nullable=False, default="read")   # read: GET only | write: same rights as the user
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
