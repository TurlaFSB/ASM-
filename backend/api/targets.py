import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.target import Target
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

    class Config:
        from_attributes = True

@router.post("/", response_model=TargetResponse)
def create_target(target: TargetCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
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
               detail={"domain": db_target.domain, "authorized_by": db_target.authorized_by})
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

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = False
    db.commit()
    log_action(db, current_user.username, "target_deleted", target_id=target.id,
               detail={"domain": target.domain})
    return {"message": f"Target {target.domain} deactivated"}
