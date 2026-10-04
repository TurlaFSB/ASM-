"""Per-target email recipients for change and exposure digests.

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("email_recipients", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "email_recipients")
