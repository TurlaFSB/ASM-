from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.db import get_db
from backend.models.vulnerability import Vulnerability
from backend.auth import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

@router.get("/summary")
def vuln_summary(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    summary = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.severity).all()
    return {row.severity: row.count for row in summary}

@router.get("/")
def list_vulnerabilities(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()
    return vulns

@router.get("/target/{target_id}")
def vulns_by_target(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).filter(
        Vulnerability.target_id == target_id
    ).order_by(Vulnerability.severity).all()
    return vulns

@router.get("/scan/{scan_id}")
def vulns_by_scan(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).order_by(Vulnerability.severity).all()
    return vulns
