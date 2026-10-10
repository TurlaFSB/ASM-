from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from pydantic import BaseModel
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.asset import Asset
from backend.models.scan_asset import ScanAsset
from backend.models.vulnerability import Vulnerability
from backend.tasks import run_scan, celery_app
from backend.auth import get_current_user, require_admin
from backend.audit import log_action
from backend.validators import validate_target
from backend.scan_profiles import PROFILES, DEFAULT_PROFILE, get_profile, is_valid_profile
from typing import Optional
import redis
from backend.config import settings
from backend.cancellation import request_cancel

def _csv_safe(v):
    """Neutralise spreadsheet formulas: cell text comes from scanned hosts, so a title like
    =HYPERLINK(...) must not execute when an analyst opens the export in Excel."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


router = APIRouter(prefix="/scans", tags=["scans"])

class ScanCreate(BaseModel):
    target_id: int
    profile: Optional[str] = None       # quick | standard | deep; None = the target's default profile
    run_dirbuster: Optional[bool] = None  # False vetoes directory discovery even if the profile has it


@router.get("/profiles")
def list_profiles(current_user: dict = Depends(get_current_user)):
    """Scan depth presets for the UI, so labels/estimates live in one place (scan_profiles.py)."""
    return {"default": DEFAULT_PROFILE, "profiles": [p.public() for p in PROFILES.values()]}

@router.post("/")
def trigger_scan(scan: ScanCreate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.is_active:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.authorized or not target.authorized_by:
        raise HTTPException(
            status_code=403,
            detail=f"Target {target.domain} is not authorized for scanning."
        )

    # Re-validate at scan time: policy (e.g. private targets flag) may have changed
    # since the target was created, and DB rows can be edited out-of-band.
    try:
        validate_target(target.domain)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    active_scan = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.status.in_(["pending", "running"])
    ).first()
    if active_scan:
        raise HTTPException(
            status_code=409,
            detail=f"A scan (#{active_scan.id}) is already {active_scan.status} for {target.domain}. Wait for it to finish or cancel it first."
        )

    requested = scan.profile or target.default_profile
    if not is_valid_profile(requested):
        raise HTTPException(status_code=422, detail=f"Unknown profile '{requested}'. Use one of: {', '.join(PROFILES)}")
    prof = get_profile(requested)
    # Directory discovery runs only if the profile includes it AND neither the target
    # toggle nor this request turned it off.
    dirs_on = bool(prof.run_dirbuster and target.dirbuster_enabled and scan.run_dirbuster is not False)

    db_scan = Scan(
        target_id=target.id,
        status="pending",
        profile=prof.name,
        created_at=datetime.now(timezone.utc)
    )
    db.add(db_scan)
    try:
        db.commit()
    except IntegrityError:
        # Lost a race with another trigger for the same target: the database allows one active scan each.
        db.rollback()
        raise HTTPException(status_code=409, detail=f"A scan is already pending or running for {target.domain}.")
    db.refresh(db_scan)
    log_action(db, current_user.username, "scan_triggered", target_id=target.id,
               scan_id=db_scan.id, detail={"domain": target.domain, "profile": prof.name, "directory_discovery": dirs_on},
               ip_address=request.client.host)

    try:
        task = run_scan.delay(
            target_id=target.id,
            domain=target.domain,
            rate_limit=target.rate_limit,
            scan_id=db_scan.id,
            enable_dirbuster=dirs_on,
            profile=prof.name,
        )
    except Exception:
        # Broker unreachable: without this the row stays "pending" forever and every later
        # trigger for the target is refused with 409.
        db_scan.status = "failed"
        db_scan.error_log = "Could not queue the scan (task queue unavailable). Try again shortly."
        db.commit()
        raise HTTPException(status_code=503, detail="Task queue unavailable. The scan was not started; try again shortly.")

    db_scan.celery_task_id = task.id
    db.commit()

    return {
        "scan_id": db_scan.id,
        "task_id": task.id,
        "target": target.domain,
        "status": "pending",
        "profile": prof.name,
        "message": "Scan queued successfully"
    }

@router.get("/")
def list_scans(response: Response, limit: int = Query(500, ge=1, le=2000), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    response.headers["X-Total-Count"] = str(db.query(func.count(Scan.id)).scalar() or 0)
    scans = (db.query(Scan).options(joinedload(Scan.target)).order_by(Scan.created_at.desc(), Scan.id.desc())
             .limit(limit).offset(offset).all())
    result = []
    for s in scans:
        row = {c.name: getattr(s, c.name) for c in s.__table__.columns}
        row["target_domain"] = s.target.domain if s.target else None
        result.append(row)
    return result

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).options(joinedload(Scan.target)).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    row = {c.name: getattr(scan, c.name) for c in scan.__table__.columns}
    row["target_domain"] = scan.target.domain if scan.target else None
    return row

@router.get("/{scan_id}/screenshots")
def scan_screenshots(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    from backend.screenshots import list_screenshots
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, "screenshots": list_screenshots(scan)}


@router.get("/{scan_id}/screenshots/{shot_id}")
def scan_screenshot_image(scan_id: int, shot_id: int, db: Session = Depends(get_db),
                          current_user: dict = Depends(get_current_user)):
    from fastapi.responses import FileResponse
    from backend.screenshots import screenshot_path
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    path = screenshot_path(scan, shot_id) if scan else None
    if path is None:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(path, media_type="image/png",
                        headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"})


@router.get("/{scan_id}/assets")
def get_scan_assets(scan_id: int, response: Response, limit: int = Query(5000, ge=1, le=20000), offset: int = Query(0, ge=0),
                    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    q = db.query(Asset).filter(Asset.target_id == scan.target_id)
    response.headers["X-Total-Count"] = str(q.count())
    return q.order_by(Asset.id).limit(limit).offset(offset).all()

@router.get("/{scan_id}/progress")
def scan_progress(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "started_at": scan.started_at,
        "current_stage": scan.current_stage,
        "module_results": scan.module_results
    }

@router.patch("/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Scan is not running")
    cancel_scan_row(db, scan)
    log_action(db, current_user.username, "scan_cancelled", target_id=scan.target_id,
               scan_id=scan.id, ip_address=request.client.host)
    return {"message": "Scan cancelled"}


def cancel_scan_row(db: Session, scan: Scan) -> None:
    """Cooperative cancel of a pending or running scan.

    Flag first (the running task's guard kills its tools and unwinds cleanly, releasing the target lock),
    then the DB status, then drop the task if it is still queued. terminate=True is deliberately NOT used:
    it SIGTERMs the worker process mid-flight, skipping cleanup and orphaning nmap/nuclei/feroxbuster, which
    is what left the next scan 'pending'."""
    try:
        request_cancel(redis.Redis.from_url(settings.redis_url, socket_timeout=2), scan.id)
    except Exception:  # noqa: BLE001  the DB status below is still checked by the pipeline
        pass
    scan.status = "cancelled"
    scan.current_stage = None
    db.commit()
    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id)


from fastapi.responses import Response
from backend.report_cache import cached_pdf
from backend.report_runner import build_report_isolated

@router.get("/{scan_id}/report")
def download_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = cached_pdf(db, scan_id)             # instant when pre-built or generated before
    if pdf_bytes is None:
        try:
            pdf_bytes = build_report_isolated(scan_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=asm_report_scan_{scan_id}.pdf"}
    )

import csv
import json
import io
from fastapi.responses import StreamingResponse

@router.get("/{scan_id}/export/assets.csv")
def export_assets_csv(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Point in time: the assets this scan actually observed. Scans from before scan_assets
    # existed have none recorded, so they fall back to the target's current assets.
    assets = (db.query(Asset).join(ScanAsset, ScanAsset.asset_id == Asset.id)
              .filter(ScanAsset.scan_id == scan_id).all())
    if not assets:
        assets = db.query(Asset).filter(Asset.target_id == scan.target_id).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["subdomain", "ip", "http_status", "http_title", "technologies",
                      "open_ports", "risk_score", "risk_level", "status", "last_seen"])
    for a in assets:
        writer.writerow([_csv_safe(x) for x in [
            a.subdomain,
            a.ip or "",
            a.http_status or "",
            a.http_title or "",
            ", ".join(a.technologies or []),
            ", ".join(str(p.get("port")) for p in (a.open_ports or [])),
            a.risk_score if a.risk_score is not None else "",
            a.risk_level or "",
            a.status or "",
            a.last_seen.isoformat() if a.last_seen else "",
        ]])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=assets_scan_{scan_id}.csv"}
    )


@router.get("/{scan_id}/export/vulnerabilities.csv")
def export_vulnerabilities_csv(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    from backend import triage as tg
    decisions = tg.lookup(db, vulns)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "name", "host", "cve_id", "cvss_score",
                      "template_id", "matched_at", "description", "triage_status", "triage_note"])
    for v in vulns:
        d = decisions.get(v.id) or {}
        writer.writerow([_csv_safe(x) for x in [
            v.severity or "",
            v.name or "",
            v.host or "",
            v.cve_id or "",
            v.cvss_score if v.cvss_score is not None else "",
            v.template_id or "",
            v.matched_at or "",
            (v.description or "").replace("\n", " ").strip(),
            d.get("status") or "open",
            d.get("note") or "",
        ]])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vulnerabilities_scan_{scan_id}.csv"}
    )


def _scan_findings(db, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).order_by(Vulnerability.id).all()
    from backend import triage as tg
    return scan, (target.domain if target else ""), vulns, tg.lookup(db, vulns)


@router.get("/{scan_id}/export/vulnerabilities.json")
def export_vulnerabilities_json(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """All findings of a scan with their triage decisions, as JSON."""
    from backend import exports
    scan, domain, vulns, decisions = _scan_findings(db, scan_id)
    return Response(content=json.dumps(exports.build_json(scan, domain, vulns, decisions)), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=vulnerabilities_scan_{scan_id}.json"})


@router.get("/{scan_id}/export/vulnerabilities.sarif")
def export_vulnerabilities_sarif(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """All findings of a scan as SARIF 2.1.0; triage decisions become `suppressions`."""
    from backend import exports
    scan, domain, vulns, decisions = _scan_findings(db, scan_id)
    return Response(content=json.dumps(exports.build_sarif(scan, domain, vulns, decisions)),
                    media_type="application/sarif+json",
                    headers={"Content-Disposition": f"attachment; filename=vulnerabilities_scan_{scan_id}.sarif"})
