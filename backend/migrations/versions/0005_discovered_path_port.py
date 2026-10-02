"""discovered_paths.port: which web port a path was found on.

Nullable: rows saved before port tracking keep NULL (shown without a port).

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("discovered_paths", sa.Column("port", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("discovered_paths", "port")
