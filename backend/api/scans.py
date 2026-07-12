from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.asset import Asset
from backend.tasks import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanCreate(BaseModel):
    target_id: int

@router.post("/")
def trigger_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    # Fetch target
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Authorization gate — enforced at API layer too
    if not target.authorized:
        raise HTTPException(
            status_code=403,
            detail=f"Target {target.domain} is not authorized for scanning."
        )

    # Create scan record
    db_scan = Scan(
        target_id=target.id,
        status="pending",
        created_at=datetime.now(timezone.utc)
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # Trigger Celery task
       # Trigger Celery task
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

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/assets")
def get_scan_assets(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assets = db.query(Asset).filter(Asset.target_id == scan.target_id).all()
    return assets

@router.get("/")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return scans