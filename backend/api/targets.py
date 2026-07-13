from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.target import Target

router = APIRouter(prefix="/targets", tags=["targets"])

class TargetCreate(BaseModel):
    domain: str
    authorized: bool
    authorized_by: str
    scope_note: Optional[str] = None
    rate_limit: Optional[int] = 10

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
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
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
    return db_target

@router.get("/")
def list_targets(db: Session = Depends(get_db)):
    targets = db.query(Target).filter(Target.is_active == True).all()
    return targets

@router.get("/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = False
    db.commit()
    return {"message": f"Target {target.domain} deactivated"}