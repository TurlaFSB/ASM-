from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.sql import func
from backend.db import Base


class Ticket(Base):
    """A ticket opened in the team's tracker for one confirmed finding. The (target, fingerprint) pair is unique,
    so the same finding never produces two tickets, however many scans see it or how often a task is retried.

    status: created | failed (retried on later scans, up to a limit)."""
    __tablename__ = "tickets"
    __table_args__ = (UniqueConstraint("target_id", "fingerprint", name="uq_tickets_target_fingerprint"),)

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    change_event_id = Column(Integer, ForeignKey("change_events.id"), nullable=True)
    fingerprint = Column(String, nullable=False)
    provider = Column(String, nullable=False)                  # github | jira
    destination = Column(String, nullable=False)               # owner/repo or Jira project key
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    status = Column(String, nullable=False, default="created")
    external_key = Column(String, nullable=True)               # #123 or PROJ-45
    url = Column(String, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
