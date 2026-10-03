from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Index, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from backend.db import Base


class ExposureFinding(Base):
    """Something found OUTSIDE the target's own infrastructure that concerns it: a possible leaked secret in
    public code, a public data-breach record, a dark-web mention.

    Only masked evidence is ever stored (see backend/exposure/masking.py): never a full secret or password.
    status: open | dismissed (analyst said ignore, never re-alerts) | resolved (no longer returned by the source).
    """
    __tablename__ = "exposure_findings"
    __table_args__ = (
        UniqueConstraint("target_id", "fingerprint", name="uq_exposure_target_fingerprint"),
        Index("ix_exposure_target_status", "target_id", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    source = Column(String, nullable=False, index=True)       # github_code | xposedornot | lookalike_domains | ransomlook
    kind = Column(String, nullable=False)                     # secret | breach | mention
    fingerprint = Column(String, nullable=False)
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=False, default="")
    severity = Column(String, nullable=False, index=True)
    url = Column(String, nullable=True)                       # evidence link on the source (https only)
    evidence = Column(JSONB, nullable=True)                   # masked, bounded
    status = Column(String, nullable=False, default="open", server_default="open")
    seen_count = Column(Integer, nullable=False, default=1, server_default="1")
    missed_runs = Column(Integer, nullable=False, default=0, server_default="0")
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())


class CollectorRun(Base):
    """One run of one source for one target (audit trail, rate limiting and the run-now guard)."""
    __tablename__ = "collector_runs"
    __table_args__ = (
        Index("uq_collector_running", "target_id", "source", unique=True,
              postgresql_where=text("status = 'running'"), sqlite_where=text("status = 'running'")),
        Index("ix_collector_runs_lookup", "target_id", "source", "started_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    source = Column(String, nullable=False)
    status = Column(String, nullable=False)                   # running | ok | failed | rate_limited
    found = Column(Integer, nullable=False, default=0)
    new = Column(Integer, nullable=False, default=0)
    error = Column(String, nullable=True)                     # short label only, never a URL or token
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
