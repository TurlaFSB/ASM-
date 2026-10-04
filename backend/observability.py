"""Operational visibility: Prometheus-format metrics and optional JSON logs.

`/metrics` is admin-only (cookie or bearer token), so a scraper authenticates with an admin token. Counts only,
no target names or finding details.
"""
import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.alert import Alert  # noqa: F401  (keeps metadata importable)
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.vulnerability import Vulnerability

SCAN_STATUSES = ("pending", "running", "completed", "failed", "cancelled")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _line(out, name, help_, kind, samples):
    out.append(f"# HELP {name} {help_}")
    out.append(f"# TYPE {name} {kind}")
    for labels, value in samples:
        lab = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}" if labels else ""
        out.append(f"{name}{lab} {value}")


def render_metrics(db: Session, queue_depth=None, now=None) -> str:
    now = now or datetime.now(timezone.utc)
    out = []
    by_status = dict(db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all())
    _line(out, "asm_scans", "Scans by status", "gauge",
          [({"status": s}, by_status.get(s, 0)) for s in SCAN_STATUSES])
    _line(out, "asm_targets", "Targets", "gauge", [({}, db.query(func.count(Target.id)).scalar() or 0)])
    _line(out, "asm_assets", "Assets that are not marked disappeared", "gauge",
          [({}, db.query(func.count(Asset.id)).filter(Asset.status != "disappeared").scalar() or 0)])
    sev = dict(db.query(func.lower(Vulnerability.severity), func.count(Vulnerability.id))
               .group_by(func.lower(Vulnerability.severity)).all())
    _line(out, "asm_findings", "Stored findings by severity (all scans, before triage)", "gauge",
          [({"severity": s}, sev.get(s, 0)) for s in SEVERITIES])
    last = db.query(func.max(Scan.completed_at)).filter(Scan.status == "completed").scalar()
    if last is not None:
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        _line(out, "asm_last_completed_scan_age_seconds", "Seconds since the last completed scan", "gauge",
              [({}, int((now - last).total_seconds()))])
    if queue_depth is not None:
        _line(out, "asm_queue_depth", "Tasks waiting in the Celery queue", "gauge", [({}, queue_depth)])
    return "\n".join(out) + "\n"


class JsonFormatter(logging.Formatter):
    """One JSON object per line, for log shippers."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def configure_logging() -> None:
    """ASM_LOG_FORMAT=json switches the root logger (and uvicorn's) to JSON lines."""
    if os.getenv("ASM_LOG_FORMAT", "text").lower() != "json":
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "celery"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
