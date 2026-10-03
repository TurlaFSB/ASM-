"""Indexes on the foreign keys and flags that nearly every list query filters by.

Plain (non-unique) indexes only, so this cannot fail on existing data. Created with IF NOT EXISTS so a
database that already has some of them (hand-added) upgrades cleanly.

Revision ID: 0007
Revises: 0006
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

INDEXES = [
    ("scans", "target_id"), ("scans", "status"),
    ("vulnerabilities", "target_id"), ("vulnerabilities", "scan_id"),
    ("assets", "target_id"),
    ("alerts", "target_id"), ("alerts", "scan_id"), ("alerts", "is_read"),
    ("discovered_paths", "asset_id"), ("discovered_paths", "scan_id"),
]


def upgrade() -> None:
    for table, col in INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_{col} ON {table} ({col})")


def downgrade() -> None:
    for table, col in INDEXES:
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_{col}")
