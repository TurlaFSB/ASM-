"""Finding triage: decisions about findings that last across scans, plus a stable finding_key on vulnerabilities.

Revision ID: 0013
Revises: 0012
"""
import hashlib
import re

from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def _key(template_id, cve_id, host, matched_at) -> str:
    # Frozen copy of backend.triage.finding_key as it was when this migration was written.
    m = None
    if matched_at:
        m = re.search(r"://[^/:]+:(\d+)", matched_at) or re.search(r":(\d+)(?:/|$)", matched_at)
    port = int(m.group(1)) if m else None
    raw = "|".join([(template_id or "").lower(), (cve_id or "").upper(), (host or "").lower(), str(port or "")])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("finding_key", sa.String(), nullable=True))
    op.create_index("ix_vulnerabilities_finding_key", "vulnerabilities", ["finding_key"])
    op.create_table(
        "finding_triage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("target_id", "key", name="uq_finding_triage_target_key"),
    )
    op.create_index("ix_finding_triage_target_id", "finding_triage", ["target_id"])
    op.create_index("ix_finding_triage_key", "finding_triage", ["key"])

    # Give existing findings their key, in batches.
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, template_id, cve_id, host, matched_at FROM vulnerabilities WHERE finding_key IS NULL")).fetchall()
    for i in range(0, len(rows), 1000):
        bind.execute(
            sa.text("UPDATE vulnerabilities SET finding_key = :k WHERE id = :i"),
            [{"k": _key(r[1], r[2], r[3], r[4]), "i": r[0]} for r in rows[i:i + 1000]],
        )


def downgrade() -> None:
    op.drop_table("finding_triage")
    op.drop_index("ix_vulnerabilities_finding_key", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "finding_key")
