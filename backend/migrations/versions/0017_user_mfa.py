"""Two-step sign-in (TOTP) columns on users.

Revision ID: 0017
Revises: 0016
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("users", sa.Column("mfa_secret", sa.String(), nullable=True))
    op.add_column("users", sa.Column("mfa_last_step", sa.Integer(), nullable=True))
    op.add_column("users", sa.Column("mfa_recovery", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    for col in ("mfa_recovery", "mfa_last_step", "mfa_secret", "mfa_enabled"):
        op.drop_column("users", col)
