"""Tamper-evident scan history: signed, chained seals per completed scan.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_seals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("snapshot_hash", sa.String(), nullable=False),
        sa.Column("prev_seal_hash", sa.String(), nullable=True),
        sa.Column("seal_hash", sa.String(), nullable=False),
        sa.Column("signature", sa.String(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", name="uq_scan_seals_scan_id"),
        sa.UniqueConstraint("target_id", "seq", name="uq_scan_seals_target_seq"),
    )
    op.create_index("ix_scan_seals_target_id", "scan_seals", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_seals_target_id", table_name="scan_seals")
    op.drop_table("scan_seals")
