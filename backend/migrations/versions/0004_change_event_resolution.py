"""change_events.resolved_by_scan_id: which scan settled a pending removal.

Lets a scan's changes be recomputed exactly (rediff restores the flaps/confirmations it caused).

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("change_events", sa.Column("resolved_by_scan_id", sa.Integer(),
                                             sa.ForeignKey("scans.id"), nullable=True))
    op.create_index("ix_change_events_resolved_by_scan_id", "change_events", ["resolved_by_scan_id"])


def downgrade() -> None:
    op.drop_index("ix_change_events_resolved_by_scan_id", table_name="change_events")
    op.drop_column("change_events", "resolved_by_scan_id")
