"""Diff engine: scan_snapshots and change_events.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", name="uq_scan_snapshots_scan_id"),
    )
    op.create_index("ix_scan_snapshots_id", "scan_snapshots", ["id"])
    op.create_index("ix_scan_snapshots_target_id", "scan_snapshots", ["target_id"])
    op.create_index("ix_scan_snapshots_profile", "scan_snapshots", ["profile"])

    op.create_table(
        "change_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("baseline_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("change_type", sa.String(), nullable=False),
        sa.Column("section", sa.String(), nullable=False),
        sa.Column("asset", sa.String(), nullable=False, server_default=""),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("confidence", sa.String(), nullable=False, server_default="confirmed"),
        sa.Column("status", sa.String(), nullable=False, server_default="confirmed"),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("group", sa.String(), nullable=True),
        sa.Column("before", sa.JSON(), nullable=True),
        sa.Column("after", sa.JSON(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_change_events_id", "change_events", ["id"])
    op.create_index("ix_change_events_target_id", "change_events", ["target_id"])
    op.create_index("ix_change_events_scan_id", "change_events", ["scan_id"])
    op.create_index("ix_change_events_category", "change_events", ["category"])
    op.create_index("ix_change_events_severity", "change_events", ["severity"])
    op.create_index("ix_change_events_fingerprint", "change_events", ["fingerprint"])
    op.create_index("ix_change_events_target_status", "change_events", ["target_id", "profile", "status"])


def downgrade() -> None:
    op.drop_table("change_events")
    op.drop_table("scan_snapshots")
