from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime, timezone
from croniter import croniter

from backend.db import get_db
from backend.models.schedule import ScheduledScan, PRESET_CRON
from backend.models.target import Target
from backend.auth import get_current_user

router = APIRouter(prefix="/schedules", tags=["schedules"])

class ScheduleCreate(BaseModel):
    target_id: int
    preset: Optional[str] = None          # "hourly" | "daily" | "weekly"
    cron_expression: Optional[str] = None # required if preset not given
    enabled: bool = True

    @field_validator("preset")
    @classmethod
    def validate_preset(cls, v):
        if v is not None and v not in PRESET_CRON:
            raise ValueError(f"preset must be one of {list(PRESET_CRON.keys())}")
        return v

class ScheduleUpdate(BaseModel):
    preset: Optional[str] = None
    cron_expression: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("preset")
    @classmethod
    def validate_preset(cls, v):
        if v is not None and v not in PRESET_CRON:
            raise ValueError(f"preset must be one of {list(PRESET_CRON.keys())}")
        return v

class ScheduleResponse(BaseModel):
    id: int
    target_id: int
    preset: Optional[str]
    cron_expression: str
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

def compute_next_run(cron_expr: str) -> datetime:
    base = datetime.now(timezone.utc)
    itr = croniter(cron_expr, base)
    return itr.get_next(datetime)

@router.post("/", response_model=ScheduleResponse)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.authorized:
        raise HTTPException(status_code=403, detail="Target is not authorized for scanning")

    if payload.preset:
        cron_expr = PRESET_CRON[payload.preset]
    elif payload.cron_expression:
        if not croniter.is_valid(payload.cron_expression):
            raise HTTPException(status_code=422, detail="Invalid cron expression")
        cron_expr = payload.cron_expression
    else:
        raise HTTPException(status_code=422, detail="Either preset or cron_expression is required")

    schedule = ScheduledScan(
        target_id=payload.target_id,
        preset=payload.preset,
        cron_expression=cron_expr,
        enabled=payload.enabled,
        next_run_at=compute_next_run(cron_expr),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.get("/", response_model=list[ScheduleResponse])
def list_schedules(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return db.query(ScheduledScan).order_by(ScheduledScan.created_at.desc()).all()

@router.patch("/{schedule_id}", response_model=ScheduleResponse)
def update_schedule(schedule_id: int, payload: ScheduleUpdate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    cron_changed = False

    if payload.preset is not None:
        schedule.preset = payload.preset
        schedule.cron_expression = PRESET_CRON[payload.preset]
        cron_changed = True
    elif payload.cron_expression is not None:
        if not croniter.is_valid(payload.cron_expression):
            raise HTTPException(status_code=422, detail="Invalid cron expression")
        schedule.preset = None
        schedule.cron_expression = payload.cron_expression
        cron_changed = True

    if payload.enabled is not None:
        schedule.enabled = payload.enabled

    if cron_changed:
        schedule.next_run_at = compute_next_run(schedule.cron_expression)

    db.commit()
    db.refresh(schedule)
    return schedule

@router.patch("/{schedule_id}/toggle")
def toggle_schedule(schedule_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.enabled = not schedule.enabled
    db.commit()
    return {"id": schedule.id, "enabled": schedule.enabled}

@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(schedule)
    db.commit()
    return {"message": "Schedule deleted"}
