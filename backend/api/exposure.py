from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import case
from sqlalchemy.orm import Session

from backend.audit import log_action
from backend.auth import get_current_user, require_admin
from backend.db import get_db
from backend.exposure import registry
from backend.exposure.base import SEVERITIES
from backend.models.exposure import CollectorRun, ExposureFinding
from backend.models.target import Target

router = APIRouter(prefix="/exposure", tags=["exposure"])

FINDING_STATUSES = ("open", "dismissed", "resolved")


def _sources_view():
    return [{"name": c.name, "label": c.label, "description": c.description, "configured": c.configured(),
             "min_interval_seconds": c.min_interval_seconds} for c in registry.all_sources()]


def _active_target(db: Session, target_id: int) -> Target:
    t = db.query(Target).filter(Target.id == target_id, Target.is_active == True).first()  # noqa: E712
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    return t


def _finding(f: ExposureFinding) -> dict:
    return {"id": f.id, "target_id": f.target_id, "source": f.source, "kind": f.kind, "title": f.title,
            "summary": f.summary, "severity": f.severity, "url": f.url, "evidence": f.evidence, "status": f.status,
            "seen_count": f.seen_count, "first_seen": f.first_seen, "last_seen": f.last_seen}


@router.get("/sources")
def list_sources(current_user=Depends(get_current_user)):
    return _sources_view()


class SourcesUpdate(BaseModel):
    sources: List[str]

    @field_validator("sources")
    @classmethod
    def _known(cls, v):
        unknown = [s for s in v if registry.get(s) is None]
        if unknown:
            raise ValueError(f"Unknown source: {unknown[0]}")
        return list(dict.fromkeys(v))


@router.get("/targets/{target_id}/sources")
def get_target_sources(target_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    t = _active_target(db, target_id)
    on = set(t.exposure_sources or [])
    return [{**s, "enabled": s["name"] in on} for s in _sources_view()]


@router.put("/targets/{target_id}/sources")
def set_target_sources(target_id: int, payload: SourcesUpdate, request: Request, db: Session = Depends(get_db),
                       current_user=Depends(require_admin)):
    t = _active_target(db, target_id)
    t.exposure_sources = payload.sources
    db.commit()
    log_action(db, current_user.username, "exposure_sources_set", target_id=t.id, detail={"sources": payload.sources},
               ip_address=request.client.host if request.client else None)
    return [{**s, "enabled": s["name"] in set(payload.sources)} for s in _sources_view()]


@router.post("/targets/{target_id}/run", status_code=202)
def run_now(target_id: int, request: Request, db: Session = Depends(get_db), current_user=Depends(require_admin)):
    t = _active_target(db, target_id)
    from backend.exposure.runner import enabled_sources
    if not enabled_sources(t):
        raise HTTPException(status_code=409, detail="Turn on at least one exposure source for this target first")
    from backend.tasks import run_exposure_checks
    run_exposure_checks.delay(t.id, None, True)
    log_action(db, current_user.username, "exposure_run", target_id=t.id,
               ip_address=request.client.host if request.client else None)
    return {"status": "queued"}


@router.get("/findings")
def list_findings(response: Response, target_id: Optional[int] = None, source: Optional[str] = None,
                  status: Optional[str] = Query(None, description="open, dismissed or resolved"),
                  severity: Optional[str] = Query(None, description="comma-separated"),
                  limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                  db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    q = db.query(ExposureFinding)
    if target_id is not None:
        q = q.filter(ExposureFinding.target_id == target_id)
    if source:
        q = q.filter(ExposureFinding.source == source)
    if status:
        if status not in FINDING_STATUSES:
            raise HTTPException(status_code=422, detail="Unknown status")
        q = q.filter(ExposureFinding.status == status)
    if severity:
        q = q.filter(ExposureFinding.severity.in_([s.strip().lower() for s in severity.split(",") if s.strip() in SEVERITIES]))
    response.headers["X-Total-Count"] = str(q.count())
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    order = case(rank, value=ExposureFinding.severity, else_=len(rank))
    rows = q.order_by(order, ExposureFinding.last_seen.desc(), ExposureFinding.id.desc()).limit(limit).offset(offset).all()
    return [_finding(f) for f in rows]


class FindingStatus(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def _ok(cls, v):
        if v not in ("open", "dismissed"):
            raise ValueError("status must be open or dismissed")
        return v


@router.patch("/findings/{finding_id}")
def set_finding_status(finding_id: int, payload: FindingStatus, request: Request, db: Session = Depends(get_db),
                       current_user=Depends(require_admin)):
    f = db.query(ExposureFinding).filter(ExposureFinding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = payload.status
    f.missed_runs = 0
    db.commit()
    log_action(db, current_user.username, "exposure_finding_" + payload.status, target_id=f.target_id,
               detail={"finding_id": f.id}, ip_address=request.client.host if request.client else None)
    return _finding(f)


@router.get("/runs")
def list_runs(target_id: Optional[int] = None, limit: int = Query(50, ge=1, le=200),
              db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    q = db.query(CollectorRun)
    if target_id is not None:
        q = q.filter(CollectorRun.target_id == target_id)
    rows = q.order_by(CollectorRun.started_at.desc(), CollectorRun.id.desc()).limit(limit).all()
    return [{"id": r.id, "target_id": r.target_id, "source": r.source, "status": r.status, "found": r.found,
             "new": r.new, "error": r.error, "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]
