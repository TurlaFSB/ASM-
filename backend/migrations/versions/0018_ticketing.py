"""Ticketing: per-target destination and threshold, plus the tickets that were opened.

Revision ID: 0018
Revises: 0017
"""
from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("ticket_destination", sa.String(), nullable=True))
    op.add_column("targets", sa.Column("ticket_min_severity", sa.String(), nullable=False, server_default="high"))
    op.create_table(
        "tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("change_event_id", sa.Integer(), sa.ForeignKey("change_events.id"), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("destination", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="created"),
        sa.Column("external_key", sa.String(), nullable=True),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "fingerprint", name="uq_tickets_target_fingerprint"),
    )
    op.create_index("ix_tickets_id", "tickets", ["id"])
    op.create_index("ix_tickets_target_id", "tickets", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_tickets_target_id", table_name="tickets")
    op.drop_index("ix_tickets_id", table_name="tickets")
    op.drop_table("tickets")
    op.drop_column("targets", "ticket_min_severity")
    op.drop_column("targets", "ticket_destination")
