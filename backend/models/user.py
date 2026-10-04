from sqlalchemy import Column, Integer, String, DateTime, Boolean, text
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
