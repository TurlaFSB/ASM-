from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from backend.db import Base


class ScanSeal(Base):
    """Tamper-evident record of a completed scan: a signed hash over its snapshot, chained to the
    previous seal of the same target (see backend/integrity.py). Rows are append-only."""
    __tablename__ = "scan_seals"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_scan_seals_scan_id"),
        UniqueConstraint("target_id", "seq", name="uq_scan_seals_target_seq"),
    )

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)                 # 1, 2, 3 ... per target; gaps reveal deleted seals
    profile = Column(String, nullable=False)
    snapshot_hash = Column(String, nullable=False)
    prev_seal_hash = Column(String, nullable=True)        # null only for seq 1
    seal_hash = Column(String, nullable=False)
    signature = Column(String, nullable=False)            # Ed25519 over seal_hash, hex
    key_id = Column(String, nullable=False)
    sealed_at = Column(DateTime(timezone=True), server_default=func.now())
