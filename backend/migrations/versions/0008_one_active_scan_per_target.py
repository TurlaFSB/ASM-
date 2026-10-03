"""At most one pending or running scan per target, enforced by the database.

Existing duplicates (left by earlier races or crashes) would make the unique index fail, so every active
scan except the newest one per target is closed as failed first.

Revision ID: 0008
Revises: 0007
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        UPDATE scans
           SET status = 'failed',
               completed_at = COALESCE(completed_at, now()),
               error_log = COALESCE(error_log || ' ', '') || 'Closed by migration 0008: duplicate active scan for this target.'
         WHERE status IN ('pending', 'running')
           AND id NOT IN (SELECT max(id) FROM scans WHERE status IN ('pending', 'running') GROUP BY target_id)
    """)
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_active_per_target
            ON scans (target_id) WHERE status IN ('pending', 'running')
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_scans_active_per_target")
