"""Persistence glue for the diff engine: build a snapshot from a finished scan, diff it against
the previous comparable scan, and store snapshot + change events.

Never raises into the scan pipeline's happy path on its own; the caller wraps it so a diff bug
can't turn a completed scan into a failed one.
"""
import logging
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from backend.diffing.engine import diff_snapshots
from backend.diffing.snapshot import SCHEMA_VERSION, build_snapshot, snapshot_hash
from backend.models.asset import Asset
from backend.models.change_event import ChangeEvent
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.scan_asset import ScanAsset
from backend.models.scan_snapshot import ScanSnapshot
from backend.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def snapshot_from_db(db: Session, scan: Scan) -> Dict:
    """Snapshot of what THIS scan observed (assets via scan_assets, paths and findings by scan_id)."""
    assets = (db.query(Asset).join(ScanAsset, ScanAsset.asset_id == Asset.id)
              .filter(ScanAsset.scan_id == scan.id).all())
    by_id = {a.id: a.subdomain for a in assets}
    asset_dicts = [{"subdomain": a.subdomain, "ip": a.ip, "open_ports": a.open_ports,
                    "technologies": a.technologies, "http_status": a.http_status,
                    "http_title": a.http_title} for a in assets]
    paths = [{"subdomain": by_id[p.asset_id], "path": p.path, "status_code": p.status_code}
             for p in db.query(DiscoveredPath).filter(DiscoveredPath.scan_id == scan.id).all()
             if p.asset_id in by_id]
    findings = [{"template_id": v.template_id, "host": v.host, "name": v.name, "severity": v.severity,
                 "tags": v.tags, "cve_id": v.cve_id, "cvss_score": v.cvss_score}
                for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()]
    return build_snapshot(scan.profile, scan.module_results or {}, asset_dicts, paths, findings)


def _row_to_dict(r: ChangeEvent) -> Dict:
    return {"fingerprint": r.fingerprint, "section": r.section, "category": r.category, "asset": r.asset,
            "subject": r.subject, "before": r.before, "after": r.after, "status": r.status}


def record_scan_changes(db: Session, scan: Scan) -> Dict:
    """Store this scan's snapshot and the change events versus its baseline. Idempotent per scan."""
    if db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == scan.id).first():
        return {"baseline": False, "skipped_existing": True, "events": 0, "pending": 0, "dismissed": 0}

    snap = snapshot_from_db(db, scan)
    baseline: Optional[ScanSnapshot] = (
        db.query(ScanSnapshot)
        .filter(ScanSnapshot.target_id == scan.target_id, ScanSnapshot.profile == snap["profile"],
                ScanSnapshot.scan_id != scan.id)
        .order_by(ScanSnapshot.scan_id.desc()).first())

    existing_pending: List[ChangeEvent] = (
        db.query(ChangeEvent).filter(ChangeEvent.target_id == scan.target_id,
                                     ChangeEvent.profile == snap["profile"],
                                     ChangeEvent.status == "pending").all())
    pending_by_fp = {r.fingerprint: r for r in existing_pending}

    result = diff_snapshots(baseline.data if baseline else None, snap,
                            [_row_to_dict(r) for r in existing_pending])

    def _add(e: Dict, status: str):
        db.add(ChangeEvent(
            target_id=scan.target_id, scan_id=scan.id, baseline_scan_id=baseline.scan_id if baseline else None,
            profile=snap["profile"], category=e["category"], change_type=e["change_type"], section=e["section"],
            asset=e["asset"] or "", subject=e["subject"], severity=e["severity"], confidence=e["confidence"],
            status=status, summary=e["summary"], group=e.get("group"), before=e.get("before"),
            after=e.get("after"), fingerprint=e["fingerprint"]))

    for e in result["events"]:
        _add(e, "confirmed")
        old = pending_by_fp.get(e["fingerprint"])
        if old is not None and e["change_type"] == "removed":
            old.status = "superseded"              # replaced by the confirmed removal above
    for e in result["pending"]:
        if e["fingerprint"] not in pending_by_fp:  # carried-over ones already have a row
            _add(e, "pending")
    for fp in result["dismissed"]:
        row = pending_by_fp.get(fp)
        if row is not None:
            row.status = "dismissed"

    db.add(ScanSnapshot(scan_id=scan.id, target_id=scan.target_id, profile=snap["profile"],
                        schema_version=SCHEMA_VERSION, content_hash=snapshot_hash(snap), data=snap))
    db.commit()

    by_sev: Dict[str, int] = {}
    for e in result["events"]:
        by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1
    return {"baseline": result["baseline"], "baseline_scan_id": baseline.scan_id if baseline else None,
            "events": len(result["events"]), "pending": len(result["pending"]),
            "dismissed": len(result["dismissed"]), "by_severity": by_sev, "skipped": result["skipped"]}
