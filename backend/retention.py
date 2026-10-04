"""Data retention: stop scan artifacts and delivery logs growing without bound.

What is pruned (age is by modification time, 0 disables a rule):
  * screenshot run folders  (SCREENSHOT_DIR/run-*)            after ASM_RETENTION_DAYS (default 90)
  * per-scan tool output    (scan_output/<scan id>/)          after ASM_RETENTION_DAYS
  * cached PDF reports      (scan_output/reports/*)           after ASM_RETENTION_DAYS (rebuilt on demand)
  * webhook delivery log rows                                 after ASM_RETENTION_DELIVERY_DAYS (default 180)
What is never pruned: scans, assets, findings, change events, seals and the audit log. They are the tamper-evident
record, and deleting any of them would break the signed history.
"""
import logging
import os
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def _days(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _remove(path: Path) -> int:
    """Delete a file or directory tree without following symlinks; return bytes freed (best effort)."""
    try:
        if path.is_symlink():
            path.unlink()
            return 0
        if path.is_dir():
            size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())
            shutil.rmtree(path)
            return size
        size = path.stat().st_size
        path.unlink()
        return size
    except OSError as e:
        logger.warning(f"[retention] could not remove {path}: {e}")
        return 0


def prune_older_than(directory: Path, days: int, *, match, now: Optional[float] = None) -> Dict[str, int]:
    """Remove direct children of `directory` accepted by `match(name)` whose mtime is older than `days`."""
    out = {"removed": 0, "bytes": 0}
    if days <= 0 or not directory.is_dir():
        return out
    cutoff = (time.time() if now is None else now) - days * 86400
    for child in directory.iterdir():
        if not match(child.name):
            continue
        try:
            if child.lstat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        out["bytes"] += _remove(child)
        out["removed"] += 1
    return out


def prune_deliveries(db, days: int, now: Optional[datetime] = None) -> int:
    if days <= 0:
        return 0
    from backend.models.webhook_delivery import WebhookDelivery
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    n = db.query(WebhookDelivery).filter(WebhookDelivery.created_at < cutoff).delete(synchronize_session=False)
    db.commit()
    return n


def run_retention(db, *, now: Optional[float] = None) -> Dict[str, object]:
    from backend.report_cache import cache_dir
    days = _days("ASM_RETENTION_DAYS", 90)
    delivery_days = _days("ASM_RETENTION_DELIVERY_DAYS", 180)
    screenshots = Path(os.getenv("SCREENSHOT_DIR", "/app/screenshots"))
    scan_output = cache_dir().parent
    summary = {
        "screenshots": prune_older_than(screenshots, days, match=lambda n: n.startswith("run-"), now=now),
        "scan_output": prune_older_than(scan_output, days, match=str.isdigit, now=now),
        "reports": prune_older_than(cache_dir(), days, match=lambda n: not n.startswith("."), now=now),
        "webhook_deliveries": prune_deliveries(db, delivery_days),
    }
    logger.info(f"[retention] {summary}")
    return summary
