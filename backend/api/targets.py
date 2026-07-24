import re
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.target import Target
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.models.asset import Asset
from backend.auth import get_current_user
from backend.audit import log_action

router = APIRouter(prefix="/targets", tags=["targets"])

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)

class TargetCreate(BaseModel):
    domain: str
    authorized: bool
    authorized_by: str
    scope_note: Optional[str] = None
    rate_limit: Optional[int] = 10

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("Domain cannot be empty")
        if len(v) > 253:
            raise ValueError("Domain is too long")
        if not DOMAIN_REGEX.match(v):
            raise ValueError("Invalid domain format (e.g. example.com)")
        return v

    @field_validator("authorized_by")
    @classmethod
    def validate_authorized_by(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("authorized_by cannot be empty")
        if len(v) > 100:
            raise ValueError("authorized_by is too long (max 100 chars)")
        return v

    @field_validator("scope_note")
    @classmethod
    def validate_scope_note(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 1000:
            raise ValueError("scope_note is too long (max 1000 chars)")
        return v

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: Optional[int]) -> int:
        if v is None:
            return 10
        if v <= 0:
            raise ValueError("rate_limit must be greater than 0")
        if v > 100:
            raise ValueError("rate_limit cannot exceed 100 req/s")
        return v

class TargetResponse(BaseModel):
    id: int
    domain: str
    authorized: bool
    authorized_by: str
    scope_note: Optional[str]
    rate_limit: int
    created_at: datetime
    whois_data: Optional[dict] = None
    dirbuster_enabled: bool = True

    class Config:
        from_attributes = True

@router.post("/", response_model=TargetResponse)
def create_target(target: TargetCreate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not target.authorized:
        raise HTTPException(
            status_code=400,
            detail="Target must be explicitly authorized before adding. Check the authorization box to confirm you have permission to scan this domain."
        )

    existing = db.query(Target).filter(Target.domain == target.domain).first()
    if existing:
        if not existing.is_active:
            existing.is_active = True
            existing.authorized = target.authorized
            existing.authorized_by = target.authorized_by
            existing.authorized_at = datetime.now(timezone.utc)
            existing.scope_note = target.scope_note
            existing.rate_limit = target.rate_limit
            db.commit()
            db.refresh(existing)
            return existing
        raise HTTPException(status_code=409, detail=f"Target {target.domain} already exists")

    db_target = Target(
        domain=target.domain,
        authorized=target.authorized,
        authorized_by=target.authorized_by,
        authorized_at=datetime.now(timezone.utc),
        scope_note=target.scope_note,
        rate_limit=target.rate_limit
    )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    log_action(db, current_user.username, "target_created", target_id=db_target.id,
               detail={"domain": db_target.domain, "authorized_by": db_target.authorized_by},
               ip_address=request.client.host)
    return db_target

@router.get("/")
def list_targets(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    targets = db.query(Target).filter(Target.is_active == True).all()
    return targets

@router.get("/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.get("/{target_id}/history")
def get_target_history(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.completed_at.asc())
        .all()
    )

    history = []
    for scan in scans:
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rows = (
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .filter(Vulnerability.scan_id == scan.id)
            .group_by(Vulnerability.severity)
            .all()
        )
        for severity, count in rows:
            key = (severity or "").lower()
            if key in sev_counts:
                sev_counts[key] = count

        history.append({
            "scan_id": scan.id,
            "scan_date": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_assets": scan.total_assets or 0,
            "new_assets": scan.new_assets or 0,
            "changed_assets": scan.changed_assets or 0,
            "disappeared_assets": scan.disappeared_assets or 0,
            "vuln_counts": sev_counts,
        })

    return {"history": history}

@router.get("/{target_id}/infrastructure")
def get_target_infrastructure(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    assets = (
        db.query(Asset)
        .filter(Asset.target_id == target_id, Asset.status != "disappeared")
        .all()
    )
    tech_set = set()
    for asset in assets:
        for tech in (asset.technologies or []):
            tech_set.add(tech)

    tls_findings = (
        db.query(Vulnerability)
        .filter(Vulnerability.target_id == target_id, Vulnerability.vuln_type == "tls-misconfiguration")
        .order_by(Vulnerability.severity.asc())
        .all()
    )

    return {
        "whois_data": target.whois_data,
        "technologies": sorted(tech_set),
        "tls_findings": [
            {
                "id": v.id,
                "name": v.name,
                "severity": v.severity,
                "host": v.host,
                "description": v.description,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
            }
            for v in tls_findings
        ],
    }
class TargetDirbusterUpdate(BaseModel):
    dirbuster_enabled: bool


@router.patch("/{target_id}/dirbuster-toggle", response_model=TargetResponse)
def update_dirbuster_toggle(target_id: int, payload: TargetDirbusterUpdate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.dirbuster_enabled = payload.dirbuster_enabled
    db.commit()
    db.refresh(target)
    log_action(db, current_user.username, "dirbuster_toggle_updated", target_id=target.id,
               detail={"dirbuster_enabled": payload.dirbuster_enabled}, ip_address=request.client.host)
    return target


@router.delete("/{target_id}")
def delete_target(target_id: int, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = False
    db.commit()
    log_action(db, current_user.username, "target_deleted", target_id=target.id,
               detail={"domain": target.domain}, ip_address=request.client.host)
    return {"message": f"Target {target.domain} deactivated"}
