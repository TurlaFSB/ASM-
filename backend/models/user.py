from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, text
from sqlalchemy.sql import func
from backend.db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Bumped on password change/reset and deactivation: every token issued before that stops working.
    token_version = Column(Integer, nullable=False, default=0, server_default=text("0"))
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)

    # Two-step sign-in (authenticator app). The secret is stored encrypted; recovery codes only as hashes.
    mfa_enabled = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    mfa_secret = Column(String, nullable=True)
    mfa_last_step = Column(Integer, nullable=True)        # newest accepted 30-second step: a code works once
    mfa_recovery = Column(JSON, nullable=True)            # list of sha256 hashes of unused recovery codes
