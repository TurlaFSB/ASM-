"""AI triage columns on change events (advisory; the rule-based severity column is untouched).

Revision ID: 0009
Revises: 0008
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

COLS = [("ai_status", "VARCHAR"), ("ai_severity", "VARCHAR"), ("final_severity", "VARCHAR"),
        ("ai_summary", "TEXT"), ("ai_action", "TEXT"), ("ai_model", "VARCHAR"), ("ai_error", "VARCHAR")]


def upgrade() -> None:
    for name, typ in COLS:
        op.execute(f"ALTER TABLE change_events ADD COLUMN IF NOT EXISTS {name} {typ}")


def downgrade() -> None:
    for name, _ in reversed(COLS):
        op.execute(f"ALTER TABLE change_events DROP COLUMN IF EXISTS {name}")
