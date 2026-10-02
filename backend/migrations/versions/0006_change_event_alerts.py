"""Alerts and webhooks driven by change events.

alerts: link to the change event, severity, category, summary.
targets: webhook format, signing secret, minimum alert severity.
webhook_deliveries: audit trail of digest deliveries.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("change_event_id", sa.Integer(), sa.ForeignKey("change_events.id"), nullable=True))
    op.add_column("alerts", sa.Column("severity", sa.String(), nullable=True))
    op.add_column("alerts", sa.Column("category", sa.String(), nullable=True))
    op.add_column("alerts", sa.Column("summary", sa.Text(), nullable=True))
    op.create_unique_constraint("uq_alerts_change_event_id", "alerts", ["change_event_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])

    op.add_column("targets", sa.Column("webhook_format", sa.String(), nullable=False, server_default="json"))
    op.add_column("targets", sa.Column("webhook_secret", sa.String(), nullable=True))
    op.add_column("targets", sa.Column("alert_min_severity", sa.String(), nullable=False, server_default="medium"))

    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("host", sa.String(), nullable=False, server_default=""),
        sa.Column("kind", sa.String(), nullable=False, server_default="digest"),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_webhook_deliveries_id", "webhook_deliveries", ["id"])
    op.create_index("ix_webhook_deliveries_target_id", "webhook_deliveries", ["target_id"])
    op.create_index("ix_webhook_deliveries_scan_id", "webhook_deliveries", ["scan_id"])


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_column("targets", "alert_min_severity")
    op.drop_column("targets", "webhook_secret")
    op.drop_column("targets", "webhook_format")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_constraint("uq_alerts_change_event_id", "alerts", type_="unique")
    for c in ("summary", "category", "severity", "change_event_id"):
        op.drop_column("alerts", c)
