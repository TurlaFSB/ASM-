"""Scan profiles: scans.profile and targets.default_profile.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default backfills existing rows: historic scans all ran the full (standard) pipeline
    op.add_column("scans", sa.Column("profile", sa.String(), nullable=False, server_default="standard"))
    op.add_column("targets", sa.Column("default_profile", sa.String(), nullable=False, server_default="standard"))


def downgrade() -> None:
    op.drop_column("targets", "default_profile")
    op.drop_column("scans", "profile")
