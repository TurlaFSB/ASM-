"""PDF report cache.

Rendering a report costs several seconds of CPU (WeasyPrint), and in the API process that CPU time
also stalls every other request. Reports are therefore built once, stored on disk under a signature
of everything they are rendered from, and served from there; a changed scan, a changed template or a
new report version produces a new signature and a rebuild.
"""
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import reports
from backend.models.alert import Alert
from backend.models.change_event import ChangeEvent
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.scan_asset import ScanAsset
from backend.models.target import Target
from backend.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

REPORT_VERSION = 1          # bump to invalidate every cached report
_locks_guard = threading.Lock()
_scan_locks = {}


def cache_dir() -> Path:
    return Path(os.getenv("ASM_REPORT_CACHE_DIR", "/app/scan_output/reports"))


def _template_stamp() -> str:
    parts = []
    for p in (Path(reports.__file__), Path(reports.TEMPLATE_DIR) / "report.html"):
        try:
            st = p.stat()
            parts.append(f"{p.name}:{st.st_size}:{int(st.st_mtime)}")
        except OSError:
            parts.append(f"{p.name}:?")
    return "|".join(parts)


def report_signature(db: Session, scan: Scan) -> str:
    def agg(model, *conds):
        n, mx = db.query(func.count(model.id), func.max(model.id)).filter(*conds).one()
        return [n or 0, mx or 0]

    target = db.query(Target).filter(Target.id == scan.target_id).first()
    # Triage decisions change what a report lists, so the set of hidden findings is part of the signature.
    _, hidden = reports.triage_split(db, db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all())
    material = {
        "triaged": sorted(v.id for v in hidden),
        "v": REPORT_VERSION, "tpl": _template_stamp(),
        "scan": [scan.id, scan.status, str(scan.completed_at), scan.profile,
                 json.dumps(scan.module_results, sort_keys=True, default=str)],
        "vulns": agg(Vulnerability, Vulnerability.scan_id == scan.id),
        "paths": agg(DiscoveredPath, DiscoveredPath.scan_id == scan.id),
        "assets": agg(ScanAsset, ScanAsset.scan_id == scan.id),
        "changes": agg(ChangeEvent, ChangeEvent.scan_id == scan.id),
        "alerts": agg(Alert, Alert.scan_id == scan.id) if hasattr(Alert, "scan_id") else [],
        "whois": json.dumps(getattr(target, "whois_data", None), sort_keys=True, default=str),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:20]


def _path(scan_id: int, sig: str) -> Path:
    return cache_dir() / f"scan_{scan_id}_{sig}.pdf"


def cached_pdf(db: Session, scan_id: int) -> Optional[bytes]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        return None
    p = _path(scan_id, report_signature(db, scan))
    try:
        return p.read_bytes() if p.exists() else None
    except OSError:
        return None


def get_or_build_pdf(db: Session, scan_id: int) -> bytes:
    """Cached PDF for the scan's current state, building (once, even under concurrent clicks) if needed.
    Raises ValueError for an unknown scan, like generate_pdf_report."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")
    sig = report_signature(db, scan)
    path = _path(scan_id, sig)
    with _locks_guard:
        lock = _scan_locks.setdefault(scan_id, threading.Lock())
    with lock:
        try:
            if path.exists():
                return path.read_bytes()
        except OSError:
            pass
        pdf = reports.generate_pdf_report(db, scan_id)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(pdf)
            os.replace(tmp, path)
            for old in path.parent.glob(f"scan_{scan_id}_*.pdf"):
                if old != path:
                    old.unlink(missing_ok=True)
        except OSError as e:
            logger.warning(f"[report] could not cache report for scan {scan_id}: {e}")
        return pdf
