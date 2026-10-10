from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import String, and_, case, cast, exists, func, or_
from backend import triage as tg
from backend.audit import log_action
from backend.db import get_db
from backend.models.finding_triage import FindingTriage
from backend.models.vulnerability import Vulnerability
from backend.models.scan import Scan
from backend.auth import get_current_user, require_admin
from backend.rollup import rollup_findings

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

_extract_port = tg.extract_port


def _serialize(v, triage=None):
    row = {c.name: getattr(v, c.name) for c in v.__table__.columns}
    row.pop("finding_key", None)
    row["port"] = _extract_port(v.matched_at)
    # "version-match" = inferred from a service version string (unverified), vs. a scanner check
    row["verified"] = "version-match" not in (v.tags or [])
    row["triage"] = triage
    return row


def _serialize_all(db, vulns):
    t = tg.lookup(db, vulns)
    return [_serialize(v, t.get(v.id)) for v in vulns]


SEVERITY_RANK = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
    value=func.lower(Vulnerability.severity), else_=5,
)


def _latest_scan_ids(db: Session):
    """Most recent completed scan per target: the 'current state' of the attack surface."""
    return (
        db.query(func.max(Scan.id))
        .filter(Scan.status == "completed")
        .group_by(Scan.target_id)
        .scalar_subquery()
    )


TRIAGE_MODES = "^(active|triaged|all)$"


def _suppressed_clause():
    """SQL for 'a person has decided this finding is hidden right now' (same rule as triage.is_suppressing)."""
    t, now = FindingTriage, datetime.now(timezone.utc)
    return exists().where(and_(
        t.target_id == Vulnerability.target_id, t.key == Vulnerability.finding_key,
        or_(t.status == "false_positive",
            and_(t.status == "accepted_risk", or_(t.expires_at.is_(None), t.expires_at > now)),
            and_(t.status == "resolved", Vulnerability.created_at <= t.updated_at))))


def _has_decision_clause():
    t = FindingTriage
    return exists().where(and_(t.target_id == Vulnerability.target_id, t.key == Vulnerability.finding_key))


SEVERITY_FILTER = r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$"
TAG_FILTER = r"^[a-z0-9][a-z0-9._-]{0,39}$"


def _scoped(db: Session, scope: str, scan_id: Optional[int], target_id: Optional[int], triage: str = "active",
            severity: Optional[str] = None, tag: Optional[str] = None):
    q = db.query(Vulnerability)
    if severity:
        q = q.filter(func.lower(Vulnerability.severity).in_(severity.split(",")))
    if tag:
        # tags is a JSON array of strings; match the quoted element so "posture" never matches "posture-x".
        # autoescape keeps %, _ and \ in the value literal (the pattern also restricts it to plain characters).
        q = q.filter(cast(Vulnerability.tags, String).contains(f'"{tag}"', autoescape=True))
    if triage == "active":
        q = q.filter(~_suppressed_clause())
    elif triage == "triaged":
        q = q.filter(_has_decision_clause())
    if scan_id is not None:
        q = q.filter(Vulnerability.scan_id == scan_id)
    elif scope == "latest":
        q = q.filter(Vulnerability.scan_id.in_(_latest_scan_ids(db)))
    if target_id is not None:
        q = q.filter(Vulnerability.target_id == target_id)
    return q


@router.get("/summary")
def vuln_summary(scope: str = Query("latest", pattern="^(latest|all)$"), scan_id: Optional[int] = None,
                 target_id: Optional[int] = None, triage: str = Query("active", pattern=TRIAGE_MODES),
                 severity: Optional[str] = Query(None, pattern=SEVERITY_FILTER),
                 tag: Optional[str] = Query(None, pattern=TAG_FILTER),
                 db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Counts by severity. Default scope is the latest completed scan per target, so repeated
    scans don't inflate the numbers."""
    base = _scoped(db, scope, scan_id, target_id, triage, severity, tag).subquery()
    rows = db.query(base.c.severity, func.count()).group_by(base.c.severity).all()
    return {sev: n for sev, n in rows}


@router.get("/")
def list_vulnerabilities(limit: int = Query(500, ge=1, le=1000), offset: int = Query(0, ge=0),
                         scope: str = Query("latest", pattern="^(latest|all)$"),
                         scan_id: Optional[int] = None, target_id: Optional[int] = None,
                         triage: str = Query("active", pattern=TRIAGE_MODES),
                         severity: Optional[str] = Query(None, pattern=SEVERITY_FILTER,
                                                         description="One or more of critical,high,medium,low,info, comma separated"),
                         tag: Optional[str] = Query(None, pattern=TAG_FILTER,
                                                    description="Only findings carrying this tag, e.g. posture, takeover, email-security, dns-hygiene"),
                         db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    q = _scoped(db, scope, scan_id, target_id, triage, severity, tag)
    vulns = (q.order_by(SEVERITY_RANK, Vulnerability.is_exploitable_confirmed.desc(),
                        Vulnerability.cvss_score.desc().nullslast(), Vulnerability.id)
             .limit(limit).offset(offset).all())
    return _serialize_all(db, vulns)

@router.get("/rollup")
def vuln_rollup(limit: int = Query(1000, ge=1, le=5000), scope: str = Query("latest", pattern="^(latest|all)$"),
                scan_id: Optional[int] = None, target_id: Optional[int] = None,
                triage: str = Query("active", pattern=TRIAGE_MODES),
                severity: Optional[str] = Query(None, pattern=SEVERITY_FILTER),
                tag: Optional[str] = Query(None, pattern=TAG_FILTER),
                db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Same data as `/`, but version-matched CVEs collapse into ONE item per (scan, host, component) with
    worst severity, KEV count and 'shown of total' (the per-service cap hides the lowest-risk matches).
    Scanner-verified findings stay one item each. Items are ordered most urgent first."""
    q = _scoped(db, scope, scan_id, target_id, triage, severity, tag)
    vulns = q.order_by(SEVERITY_RANK, Vulnerability.id).limit(limit).all()
    rows = _serialize_all(db, vulns)
    totals = {}
    for sid, mr in db.query(Scan.id, Scan.module_results).filter(Scan.id.in_({r["scan_id"] for r in rows})).all():
        for t in (mr or {}).get("cve_truncated") or []:
            if t.get("label"):
                totals[(sid, t.get("host"), t["label"])] = t.get("total")
    items = rollup_findings(rows, totals)
    return {"items": items, "findings": len(rows), "lines": len(items)}


@router.get("/target/{target_id}")
def vulns_by_target(target_id: int, response: Response, limit: int = Query(5000, ge=1, le=20000), offset: int = Query(0, ge=0),
                    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    q = db.query(Vulnerability).filter(Vulnerability.target_id == target_id)
    response.headers["X-Total-Count"] = str(q.count())
    return _serialize_all(db, q.order_by(SEVERITY_RANK, Vulnerability.id).limit(limit).offset(offset).all())

@router.get("/scan/{scan_id}")
def vulns_by_scan(scan_id: int, response: Response, limit: int = Query(5000, ge=1, le=20000), offset: int = Query(0, ge=0),
                  db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    q = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    response.headers["X-Total-Count"] = str(q.count())
    return _serialize_all(db, q.order_by(SEVERITY_RANK, Vulnerability.id).limit(limit).offset(offset).all())


@router.get("/hidden-count")
def hidden_count(scope: str = Query("latest", pattern="^(latest|all)$"), target_id: Optional[int] = None,
                 db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """How many findings the active list hides because of a triage decision."""
    total = _scoped(db, scope, None, target_id, "all").count()
    shown = _scoped(db, scope, None, target_id, "active").count()
    return {"hidden": max(0, total - shown)}


class TriageRequest(BaseModel):
    ids: List[int]
    status: str
    note: Optional[str] = None
    expires_in_days: Optional[int] = None


@router.post("/triage")
def set_triage(payload: TriageRequest, request: Request, db: Session = Depends(get_db), admin=Depends(require_admin)):
    """Record a decision for one or more findings (by id). Applies to the finding itself, so it carries over
    to later scans. `open` removes the decision."""
    if payload.status not in tg.STATUSES:
        raise HTTPException(status_code=422, detail="Unknown status.")
    ids = list(dict.fromkeys(payload.ids))
    if not ids or len(ids) > 500:
        raise HTTPException(status_code=422, detail="Choose between 1 and 500 findings.")
    note = (payload.note or "").strip()[:tg.NOTE_MAX] or None
    if payload.status in tg.NEEDS_REASON and (not note or len(note) < 3):
        raise HTTPException(status_code=422, detail="Add a short reason: it is kept for whoever reviews this later.")
    vulns = db.query(Vulnerability).filter(Vulnerability.id.in_(ids)).all()
    if len(vulns) != len(ids):
        raise HTTPException(status_code=404, detail="Some findings were not found.")
    now = datetime.now(timezone.utc)
    expires = None
    if payload.status == "accepted_risk":
        days = tg.DEFAULT_ACCEPT_DAYS if payload.expires_in_days is None else payload.expires_in_days
        if not 1 <= days <= tg.MAX_ACCEPT_DAYS:
            raise HTTPException(status_code=422, detail=f"Review date must be between 1 and {tg.MAX_ACCEPT_DAYS} days.")
        expires = now + timedelta(days=days)
    seen = set()
    changed = 0
    for v in vulns:
        ident = (v.target_id, v.finding_key)
        if not v.finding_key or ident in seen:
            continue
        seen.add(ident)
        row = db.query(FindingTriage).filter(FindingTriage.target_id == v.target_id, FindingTriage.key == v.finding_key).first()
        if payload.status == "open":
            if row:
                db.delete(row)
                changed += 1
            continue
        if row is None:
            row = FindingTriage(target_id=v.target_id, key=v.finding_key, status=payload.status)
            db.add(row)
        row.status, row.note, row.updated_by, row.expires_at, row.updated_at = payload.status, note, admin.username, expires, now
        changed += 1
    db.commit()
    log_action(db, admin.username, "finding_triaged", detail={"status": payload.status, "findings": changed, "has_note": bool(note)},
               ip_address=request.client.host if request.client else None)
    return {"updated": changed}

