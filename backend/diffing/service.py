"""Persistence glue for the diff engine: build a snapshot from a finished scan, diff it against
the previous comparable scan, and store snapshot + change events.

Never raises into the scan pipeline's happy path on its own; the caller wraps it so a diff bug
can't turn a completed scan into a failed one.
"""
import logging
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from backend.diffing.engine import _fp, diff_snapshots
from backend.diffing.snapshot import SCHEMA_VERSION, build_snapshot, compute_coverage, snapshot_hash
from backend.models.asset import Asset
from backend.models.change_event import ChangeEvent
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.scan_asset import ScanAsset
from backend.models.scan_snapshot import ScanSnapshot
from backend.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def snapshot_from_db(db: Session, scan: Scan, module_results: Optional[Dict] = None) -> Dict:
    """Snapshot of what THIS scan observed (assets via scan_assets, paths and findings by scan_id)."""
    assets = (db.query(Asset).join(ScanAsset, ScanAsset.asset_id == Asset.id)
              .filter(ScanAsset.scan_id == scan.id).all())
    by_id = {a.id: a.subdomain for a in assets}
    asset_dicts = [{"subdomain": a.subdomain, "ip": a.ip, "open_ports": a.open_ports,
                    "technologies": a.technologies, "http_status": a.http_status,
                    "http_title": a.http_title} for a in assets]
    paths = [{"subdomain": by_id[p.asset_id], "path": p.path, "port": p.port,
              "status_code": p.status_code}
             for p in db.query(DiscoveredPath).filter(DiscoveredPath.scan_id == scan.id).all()
             if p.asset_id in by_id]
    findings = [{"template_id": v.template_id, "host": v.host, "name": v.name, "severity": v.severity,
                 "tags": v.tags, "cve_id": v.cve_id, "cvss_score": v.cvss_score}
                for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()]
    # The pipeline only persists scan.module_results at the very end, so the live run passes its own.
    return build_snapshot(scan.profile, module_results if module_results is not None else (scan.module_results or {}),
                          asset_dicts, paths, findings)


def _row_to_dict(r: ChangeEvent) -> Dict:
    return {"fingerprint": r.fingerprint, "section": r.section, "category": r.category, "asset": r.asset,
            "subject": r.subject, "before": r.before, "after": r.after, "status": r.status}


def _healed_baseline_data(db: Session, baseline: ScanSnapshot) -> Dict:
    """Coverage is derived from the scan's stored module_results, which is the source of truth.
    Recomputing it for the baseline heals snapshots written before module_results was available."""
    data = dict(baseline.data)
    bscan = db.query(Scan).filter(Scan.id == baseline.scan_id).first()
    if bscan is not None and bscan.module_results:
        data["coverage"] = compute_coverage(baseline.profile, bscan.module_results)
    return data


REAPPEAR_WINDOW = 5      # scans


def _label_reappeared(db: Session, scan: Scan, profile: str, events: List[Dict]) -> None:
    """An 'added' event whose removal was confirmed within the last few scans is a flap, not news.
    It stays reported (a real regression must not be hidden) but says so, so alternating
    added/removed noise from unstable detection is recognisable at a glance."""
    adds = [e for e in events if e["change_type"] == "added"]
    if not adds:
        return
    recent = [r[0] for r in db.query(ScanSnapshot.scan_id)
              .filter(ScanSnapshot.target_id == scan.target_id, ScanSnapshot.profile == profile,
                      ScanSnapshot.scan_id != scan.id)
              .order_by(ScanSnapshot.scan_id.desc()).limit(REAPPEAR_WINDOW).all()]
    if not recent:
        return
    fps = {e["fingerprint"]: _fp(e["category"], "removed", e["asset"], e["subject"]) for e in adds}
    rows = (db.query(ChangeEvent).filter(ChangeEvent.target_id == scan.target_id,
                                         ChangeEvent.profile == profile, ChangeEvent.status == "confirmed",
                                         ChangeEvent.change_type == "removed",
                                         ChangeEvent.scan_id.in_(recent),
                                         ChangeEvent.fingerprint.in_(set(fps.values())))
            .order_by(ChangeEvent.scan_id.desc()).all())
    last_removed = {}
    for r in rows:
        last_removed.setdefault(r.fingerprint, r.scan_id)
    for e in adds:
        sid = last_removed.get(fps[e["fingerprint"]])
        if sid is not None:
            e["summary"] += f" (reappeared; had been resolved in scan {sid})"
            e["after"] = dict(e.get("after") or {}, reappeared_after_scan=sid)


def record_scan_changes(db: Session, scan: Scan, module_results: Optional[Dict] = None) -> Dict:
    """Store this scan's snapshot and the change events versus its baseline. Idempotent per scan.
    module_results: the live pipeline's per-stage results (scan.module_results is not saved yet)."""
    if db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == scan.id).first():
        return {"baseline": False, "skipped_existing": True, "events": 0, "pending": 0, "dismissed": 0}

    snap = snapshot_from_db(db, scan, module_results)
    baseline: Optional[ScanSnapshot] = (
        db.query(ScanSnapshot)
        .filter(ScanSnapshot.target_id == scan.target_id, ScanSnapshot.profile == snap["profile"],
                ScanSnapshot.scan_id != scan.id)
        .order_by(ScanSnapshot.scan_id.desc()).first())

    existing_pending: List[ChangeEvent] = (
        db.query(ChangeEvent).filter(ChangeEvent.target_id == scan.target_id,
                                     ChangeEvent.profile == snap["profile"],
                                     ChangeEvent.status == "pending").all())
    if baseline is not None:
        # A pending removal is always settled by the very next scan. Rows that predate the baseline
        # scan are orphans (left behind by older tooling or interrupted runs): close them so they
        # cannot be revived into every later comparison.
        for row in [r for r in existing_pending if r.scan_id < baseline.scan_id]:
            row.status = "superseded"
            row.resolved_by_scan_id = scan.id
        existing_pending = [r for r in existing_pending if r.scan_id >= baseline.scan_id]
    pending_by_fp: Dict[str, List[ChangeEvent]] = {}
    for r in existing_pending:
        pending_by_fp.setdefault(r.fingerprint, []).append(r)

    result = diff_snapshots(_healed_baseline_data(db, baseline) if baseline else None, snap,
                            [_row_to_dict(r) for r in existing_pending])

    _label_reappeared(db, scan, snap["profile"], result["events"])

    if result["baseline"]:
        # Fresh baseline (first scan, or the snapshot schema changed): pending removals recorded
        # against the old shape can never be resolved, so close them instead of leaving them open.
        for row in existing_pending:
            row.status = "superseded"
            row.resolved_by_scan_id = scan.id
        pending_by_fp = {}

    def _add(e: Dict, status: str):
        db.add(ChangeEvent(
            target_id=scan.target_id, scan_id=scan.id, baseline_scan_id=baseline.scan_id if baseline else None,
            profile=snap["profile"], category=e["category"], change_type=e["change_type"], section=e["section"],
            asset=e["asset"] or "", subject=e["subject"], severity=e["severity"], confidence=e["confidence"],
            status=status, summary=e["summary"], group=e.get("group"), before=e.get("before"),
            after=e.get("after"), fingerprint=e["fingerprint"]))

    for e in result["events"]:
        _add(e, "confirmed")
        if e["change_type"] == "removed":
            for old in pending_by_fp.get(e["fingerprint"], []):
                old.status = "superseded"          # replaced by the confirmed removal above
                old.resolved_by_scan_id = scan.id
    for e in result["pending"]:
        if e["fingerprint"] not in pending_by_fp:  # carried-over ones already have a row
            _add(e, "pending")
    for fp in result["dismissed"]:
        for row in pending_by_fp.get(fp, []):
            row.status = "dismissed"
            row.resolved_by_scan_id = scan.id

    db.add(ScanSnapshot(scan_id=scan.id, target_id=scan.target_id, profile=snap["profile"],
                        schema_version=SCHEMA_VERSION, content_hash=snapshot_hash(snap), data=snap))
    db.commit()

    by_sev: Dict[str, int] = {}
    for e in result["events"]:
        by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1
    return {"baseline": result["baseline"], "baseline_scan_id": baseline.scan_id if baseline else None,
            "events": len(result["events"]), "pending": len(result["pending"]),
            "dismissed": len(result["dismissed"]), "by_severity": by_sev, "skipped": result["skipped"]}


def rebuild_scan_changes(db: Session, scan: Scan) -> Dict:
    """Recompute one scan's snapshot and change events from its stored data (maintenance tool).

    Only safe for the NEWEST scan of its profile: later scans' events were derived from this scan's
    snapshot and are not recomputed. Pending removals this scan confirmed or dismissed are put back to
    pending first (via resolved_by_scan_id), so the recomputation matches what the live run did.
    Rows settled before that column existed cannot be traced: confirmed ones are matched by
    fingerprint, dismissed ones are not restored."""
    newer = (db.query(ScanSnapshot).filter(ScanSnapshot.target_id == scan.target_id,
                                            ScanSnapshot.profile == scan.profile,
                                            ScanSnapshot.scan_id > scan.id).first())
    if newer is not None:
        raise ValueError(f"scan {scan.id} is not the newest {scan.profile} scan (scan {newer.scan_id} came after)")
    # Undo this scan's side effects on older pending removals before recomputing
    mine = db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id).all()
    for r in db.query(ChangeEvent).filter(ChangeEvent.resolved_by_scan_id == scan.id).all():
        r.status = "pending"
        r.resolved_by_scan_id = None
    for e in mine:
        if e.status == "confirmed" and e.change_type == "removed":
            old = (db.query(ChangeEvent).filter(ChangeEvent.fingerprint == e.fingerprint,
                                                ChangeEvent.target_id == scan.target_id,
                                                ChangeEvent.status == "superseded").first())
            if old is not None:
                old.status = "pending"
    for e in mine:
        db.delete(e)
    db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == scan.id).delete()
    db.commit()
    return record_scan_changes(db, scan, scan.module_results or {})
