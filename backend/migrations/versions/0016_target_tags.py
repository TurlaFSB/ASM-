"""Free-form tags on targets, for grouping and filtering.

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("tags", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "tags")
