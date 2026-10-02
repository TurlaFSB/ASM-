"""Run the (CPU-heavy) report build in a separate long-lived process.

WeasyPrint holds the GIL for seconds; in the API process that freezes every other request, which is
what made the whole UI feel stuck while a report generated. A one-process pool keeps the API
responsive; if the pool cannot be used the build falls back to in-process rather than failing."""
import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import Optional

logger = logging.getLogger(__name__)
_pool: Optional[ProcessPoolExecutor] = None


def _build(scan_id: int) -> bytes:
    """Runs inside the pool process: own DB session, same cache."""
    from backend.db import SessionLocal
    from backend.report_cache import get_or_build_pdf
    db = SessionLocal()
    try:
        return get_or_build_pdf(db, scan_id)
    finally:
        db.close()


def _get_pool() -> ProcessPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn"))
    return _pool


def build_report_isolated(scan_id: int, timeout: int = 180) -> bytes:
    global _pool
    try:
        return _get_pool().submit(_build, scan_id).result(timeout=timeout)
    except (ValueError, TimeoutError):
        raise
    except (BrokenProcessPool, OSError, RuntimeError) as e:
        logger.warning(f"[report] isolated build unavailable ({e}); building in-process")
        _pool = None
        return _build(scan_id)
