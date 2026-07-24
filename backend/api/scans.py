from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, joinedload
from pydantic import BaseModel
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.asset import Asset
from backend.models.vulnerability import Vulnerability
from backend.tasks import run_scan, celery_app
from backend.auth import get_current_user
from backend.audit import log_action

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanCreate(BaseModel):
    target_id: int
    wordlist: str = "small"  # directory discovery wordlist: "small" (fast default) or "medium" (deeper, slower)
    run_dirbuster: bool = True  # toggle directory/content discovery stage on/off for this scan

@router.post("/")
def trigger_scan(scan: ScanCreate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.authorized:
        raise HTTPException(
            status_code=403,
            detail=f"Target {target.domain} is not authorized for scanning."
        )

    active_scan = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.status.in_(["pending", "running"])
    ).first()
    if active_scan:
        raise HTTPException(
            status_code=409,
            detail=f"A scan (#{active_scan.id}) is already {active_scan.status} for {target.domain}. Wait for it to finish or cancel it first."
        )

    db_scan = Scan(
        target_id=target.id,
        status="pending",
        created_at=datetime.now(timezone.utc)
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    log_action(db, current_user.username, "scan_triggered", target_id=target.id,
               scan_id=db_scan.id, detail={"domain": target.domain}, ip_address=request.client.host)

    task = run_scan.delay(
        target_id=target.id,
        domain=target.domain,
        rate_limit=target.rate_limit,
        scan_id=db_scan.id,
        wordlist=scan.wordlist,
        enable_dirbuster=scan.run_dirbuster
    )

    db_scan.celery_task_id = task.id
    db.commit()

    return {
        "scan_id": db_scan.id,
        "task_id": task.id,
        "target": target.domain,
        "status": "pending",
        "message": "Scan queued successfully"
    }

@router.get("/")
def list_scans(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scans = db.query(Scan).options(joinedload(Scan.target)).order_by(Scan.created_at.desc()).all()
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

@router.get("/{scan_id}/assets")
def get_scan_assets(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assets = db.query(Asset).filter(Asset.target_id == scan.target_id).all()
    return assets

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
def cancel_scan(scan_id: int, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Scan is not running")
    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True)
    scan.status = "cancelled"
    db.commit()
    log_action(db, current_user.username, "scan_cancelled", target_id=scan.target_id,
               scan_id=scan.id, ip_address=request.client.host)
    return {"message": "Scan cancelled"}

from fastapi.responses import Response
from backend.reports import generate_pdf_report

@router.get("/{scan_id}/report")
def download_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        pdf_bytes = generate_pdf_report(db, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=asm_report_scan_{scan_id}.pdf"}
    )

import csv
import io
from fastapi.responses import StreamingResponse

@router.get("/{scan_id}/export/assets.csv")
def export_assets_csv(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.target_id == scan.target_id).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["subdomain", "ip", "http_status", "http_title", "technologies",
                      "open_ports", "risk_score", "risk_level", "status", "last_seen"])
    for a in assets:
        writer.writerow([
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
        ])

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

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "name", "host", "cve_id", "cvss_score",
                      "template_id", "matched_at", "description"])
    for v in vulns:
        writer.writerow([
            v.severity or "",
            v.name or "",
            v.host or "",
            v.cve_id or "",
            v.cvss_score if v.cvss_score is not None else "",
            v.template_id or "",
            v.matched_at or "",
            (v.description or "").replace("\n", " ").strip(),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vulnerabilities_scan_{scan_id}.csv"}
    )
