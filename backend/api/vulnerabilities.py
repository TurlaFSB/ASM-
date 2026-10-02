import re
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import case, func
from backend.db import get_db
from backend.models.vulnerability import Vulnerability
from backend.models.scan import Scan
from backend.auth import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

def _extract_port(matched_at):
    if not matched_at:
        return None
    m = re.search(r"://[^/:]+:(\d+)", matched_at)
    if m:
        return int(m.group(1))
    m = re.search(r":(\d+)(?:/|$)", matched_at)
    if m:
        return int(m.group(1))
    return None

def _serialize(v):
    row = {c.name: getattr(v, c.name) for c in v.__table__.columns}
    row["port"] = _extract_port(v.matched_at)
    # "version-match" = inferred from a service version string (unverified), vs. a scanner check
    row["verified"] = "version-match" not in (v.tags or [])
    return row

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


def _scoped(db: Session, scope: str, scan_id: Optional[int], target_id: Optional[int]):
    q = db.query(Vulnerability)
    if scan_id is not None:
        q = q.filter(Vulnerability.scan_id == scan_id)
    elif scope == "latest":
        q = q.filter(Vulnerability.scan_id.in_(_latest_scan_ids(db)))
    if target_id is not None:
        q = q.filter(Vulnerability.target_id == target_id)
    return q


@router.get("/summary")
def vuln_summary(scope: str = Query("latest", pattern="^(latest|all)$"), scan_id: Optional[int] = None,
                 target_id: Optional[int] = None, db: Session = Depends(get_db),
                 current_user: dict = Depends(get_current_user)):
    """Counts by severity. Default scope is the latest completed scan per target, so repeated
    scans don't inflate the numbers."""
    base = _scoped(db, scope, scan_id, target_id).subquery()
    rows = db.query(base.c.severity, func.count()).group_by(base.c.severity).all()
    return {sev: n for sev, n in rows}


@router.get("/")
def list_vulnerabilities(limit: int = Query(500, ge=1, le=1000), offset: int = Query(0, ge=0),
                         scope: str = Query("latest", pattern="^(latest|all)$"),
                         scan_id: Optional[int] = None, target_id: Optional[int] = None,
                         db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    q = _scoped(db, scope, scan_id, target_id)
    vulns = (q.order_by(SEVERITY_RANK, Vulnerability.is_exploitable_confirmed.desc(),
                        Vulnerability.cvss_score.desc().nullslast(), Vulnerability.id)
             .limit(limit).offset(offset).all())
    return [_serialize(v) for v in vulns]

@router.get("/target/{target_id}")
def vulns_by_target(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).filter(
        Vulnerability.target_id == target_id
    ).order_by(Vulnerability.severity).all()
    return [_serialize(v) for v in vulns]

@router.get("/scan/{scan_id}")
def vulns_by_scan(scan_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).order_by(Vulnerability.severity).all()
    return [_serialize(v) for v in vulns]
