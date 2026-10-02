"""Baseline schema (as created by Base.metadata.create_all before migrations existed).

Databases created by the old create_all already contain these tables; for those this
revision is a no-op, so `alembic upgrade head` works on both fresh and legacy installs.
A partially-present schema is refused loudly instead of guessed at.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = ['targets', 'users', 'assets', 'scans', 'scheduled_scans', 'alerts', 'audit_logs', 'discovered_paths', 'scan_assets', 'vulnerabilities']


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    present = [t for t in TABLES if t in existing]
    if len(present) == len(TABLES):
        return  # legacy create_all database: baseline already in place
    if present:
        raise RuntimeError(
            "Partial legacy schema detected (have %s, missing %s). "
            "Fix or recreate the database before migrating." % (present, [t for t in TABLES if t not in existing])
        )
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False),
        sa.Column("authorized_by", sa.String(), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope_note", sa.Text(), nullable=True),
        sa.Column("whois_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("webhook_url", sa.String(), nullable=True),
        sa.Column("rate_limit", sa.Integer(), nullable=True),
        sa.Column("dirbuster_enabled", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
    )
    op.create_index("ix_targets_id", "targets", ["id"])
    op.create_index("ix_targets_domain", "targets", ["domain"], unique=True)
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("subdomain", sa.String(), nullable=False),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("open_ports", sa.JSON(), nullable=True),
        sa.Column("technologies", sa.JSON(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("http_title", sa.String(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_assets_id", "assets", ["id"])
    op.create_index("ix_assets_subdomain", "assets", ["subdomain"])
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("celery_task_id", sa.String(), nullable=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("current_stage", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_assets", sa.Integer(), nullable=True),
        sa.Column("new_assets", sa.Integer(), nullable=True),
        sa.Column("changed_assets", sa.Integer(), nullable=True),
        sa.Column("disappeared_assets", sa.Integer(), nullable=True),
        sa.Column("module_results", sa.JSON(), nullable=True),
        sa.Column("error_log", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_scans_id", "scans", ["id"])
    op.create_index("ix_scans_celery_task_id", "scans", ["celery_task_id"])
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("preset", sa.String(), nullable=True),
        sa.Column("cron_expression", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_scheduled_scans_id", "scheduled_scans", ["id"])
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("alert_type", sa.String(), nullable=False),
        sa.Column("asset_subdomain", sa.String(), nullable=False),
        sa.Column("asset_ip", sa.String(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("is_read", sa.Boolean(), nullable=True),
        sa.Column("webhook_sent", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_alerts_id", "alerts", ["id"])
    op.create_index("ix_alerts_alert_type", "alerts", ["alert_type"])
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"])
    op.create_index("ix_audit_logs_username", "audit_logs", ["username"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_table(
        "discovered_paths",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_length", sa.Integer(), nullable=True),
        sa.Column("redirect_location", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_discovered_paths_id", "discovered_paths", ["id"])
    op.create_index("ix_discovered_paths_path", "discovered_paths", ["path"])
    op.create_table(
        "scan_assets",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=False), nullable=True),
    )
    op.create_index("ix_scan_assets_id", "scan_assets", ["id"])
    op.create_index("ix_scan_assets_scan_id", "scan_assets", ["scan_id"])
    op.create_index("ix_scan_assets_asset_id", "scan_assets", ["asset_id"])
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("template_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("matched_at", sa.String(), nullable=True),
        sa.Column("vuln_type", sa.String(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("is_exploitable_confirmed", sa.Boolean(), nullable=True),
        sa.Column("exploitability_reasons", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("now()")),
    )
    op.create_index("ix_vulnerabilities_id", "vulnerabilities", ["id"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vulnerabilities_is_exploitable_confirmed", "vulnerabilities", ["is_exploitable_confirmed"])


def downgrade() -> None:
    for table in (
        "vulnerabilities",
        "scan_assets",
        "discovered_paths",
        "audit_logs",
        "alerts",
        "scheduled_scans",
        "scans",
        "assets",
        "users",
        "targets",
    ):
        op.drop_table(table)
