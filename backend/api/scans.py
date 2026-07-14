from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.asset import Asset
from backend.tasks import run_scan, celery_app
from backend.auth import get_current_user

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanCreate(BaseModel):
    target_id: int

@router.post("/")
def trigger_scan(scan: ScanCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.authorized:
        raise HTTPException(
            status_code=403,
            detail=f"Target {target.domain} is not authorized for scanning."
        )

    db_scan = Scan(
        target_id=target.id,
        status="pending",
        created_at=datetime.now(timezone.utc)
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    task = run_scan.delay(
        target_id=target.id,
        domain=target.domain,
        rate_limit=target.rate_limit,
        scan_id=db_scan.id
    )

    return {
        "scan_id": db_scan.id,
        "task_id": task.id,
        "target": target.domain,
        "status": "pending",
        "message": "Scan queued successfully"
    }

@router.get("/")
def list_scans(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return scans

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

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
        "module_results": scan.module_results
    }

@router.patch("/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ["pending", "running"]:
        raise HTTPException(status_code=400, detail="Scan is not running")
    celery_app.control.revoke(str(scan.id), terminate=True)
    scan.status = "cancelled"
    db.commit()
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
