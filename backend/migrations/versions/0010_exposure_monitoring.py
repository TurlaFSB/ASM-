"""Exposure monitoring: leaks, breaches and mentions found outside the target's own infrastructure.

exposure_findings: masked evidence only. collector_runs: audit trail + run guard (one running per target/source).
targets.exposure_sources: which collectors are switched on (off by default).
alerts.scan_id becomes nullable: exposure alerts are not tied to a scan.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("exposure_sources", postgresql.JSONB(), nullable=True))
    op.alter_column("alerts", "scan_id", existing_type=sa.Integer(), nullable=True)

    op.create_table(
        "exposure_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("missed_runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "fingerprint", name="uq_exposure_target_fingerprint"),
    )
    op.create_index("ix_exposure_findings_id", "exposure_findings", ["id"])
    op.create_index("ix_exposure_findings_target_id", "exposure_findings", ["target_id"])
    op.create_index("ix_exposure_findings_source", "exposure_findings", ["source"])
    op.create_index("ix_exposure_findings_severity", "exposure_findings", ["severity"])
    op.create_index("ix_exposure_target_status", "exposure_findings", ["target_id", "status"])

    op.create_table(
        "collector_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_collector_runs_id", "collector_runs", ["id"])
    op.create_index("ix_collector_runs_target_id", "collector_runs", ["target_id"])
    op.create_index("ix_collector_runs_lookup", "collector_runs", ["target_id", "source", "started_at"])
    op.execute("CREATE UNIQUE INDEX uq_collector_running ON collector_runs (target_id, source) WHERE status = 'running'")


def downgrade() -> None:
    op.drop_table("collector_runs")
    op.drop_table("exposure_findings")
    # alerts.scan_id stays nullable on downgrade: exposure alerts may exist and cannot be back-filled
    op.drop_column("targets", "exposure_sources")
