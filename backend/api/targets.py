from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, ConfigDict, field_validator
from typing import List, Optional
from datetime import datetime, timezone
from backend.db import get_db
from backend.models.target import Target
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.models.asset import Asset
from backend.auth import get_current_user, require_admin
from backend.audit import log_action
from backend.validators import validate_target, normalize_tags

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreate(BaseModel):
    domain: str
    authorized: bool
    authorized_by: str
    scope_note: Optional[str] = None
    rate_limit: Optional[int] = 10
    tags: Optional[List[str]] = None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        return None if v is None else normalize_tags(v)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return validate_target(v)

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
    default_profile: str = "standard"
    tags: List[str] = []

    @field_validator("tags", mode="before")
    @classmethod
    def _no_null_tags(cls, v):
        return v or []

    model_config = ConfigDict(from_attributes=True)

@router.post("/", response_model=TargetResponse)
def create_target(target: TargetCreate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
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
            existing.tags = target.tags or None
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
        rate_limit=target.rate_limit,
        tags=target.tags or None,
    )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    log_action(db, current_user.username, "target_created", target_id=db_target.id,
               detail={"domain": db_target.domain, "authorized_by": db_target.authorized_by},
               ip_address=request.client.host)
    return db_target

@router.get("/", response_model=list[TargetResponse])
def list_targets(response: Response, limit: int = Query(1000, ge=1, le=5000), offset: int = Query(0, ge=0),
                 tag: Optional[str] = Query(None, max_length=32),
                 db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    q = db.query(Target).filter(Target.is_active == True)
    if tag:
        # filtered in Python: tags are a short JSON list and the target table is small, which keeps this portable
        wanted = tag.strip().lower()
        ids = [t.id for t in q.all() if wanted in (t.tags or [])]
        q = q.filter(Target.id.in_(ids))
    response.headers["X-Total-Count"] = str(q.count())
    targets = q.order_by(Target.id).limit(limit).offset(offset).all()
    return targets

@router.get("/{target_id}", response_model=TargetResponse)
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
class TargetProfileUpdate(BaseModel):
    default_profile: str

    @field_validator("default_profile")
    @classmethod
    def _valid(cls, v):
        from backend.scan_profiles import PROFILES
        v = (v or "").lower()
        if v not in PROFILES:
            raise ValueError(f"must be one of: {', '.join(PROFILES)}")
        return v


@router.patch("/{target_id}/profile", response_model=TargetResponse)
def update_default_profile(target_id: int, payload: TargetProfileUpdate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    target = db.query(Target).filter(Target.id == target_id, Target.is_active == True).first()  # noqa: E712
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    old = target.default_profile
    target.default_profile = payload.default_profile
    db.commit()
    db.refresh(target)
    log_action(db, current_user.username, "target_profile_updated", target_id=target.id,
               detail={"old": old, "new": payload.default_profile}, ip_address=request.client.host)
    return target


class TargetDirbusterUpdate(BaseModel):
    dirbuster_enabled: bool


@router.patch("/{target_id}/dirbuster-toggle", response_model=TargetResponse)
def update_dirbuster_toggle(target_id: int, payload: TargetDirbusterUpdate, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.dirbuster_enabled = payload.dirbuster_enabled
    db.commit()
    db.refresh(target)
    log_action(db, current_user.username, "dirbuster_toggle_updated", target_id=target.id,
               detail={"dirbuster_enabled": payload.dirbuster_enabled}, ip_address=request.client.host)
    return target


class TargetTagsUpdate(BaseModel):
    tags: List[str]

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        return normalize_tags(v)


@router.put("/{target_id}/tags", response_model=TargetResponse)
def update_tags(target_id: int, payload: TargetTagsUpdate, request: Request, db: Session = Depends(get_db),
                current_user: dict = Depends(require_admin)):
    t = _active_target(db, target_id)
    t.tags = payload.tags or None
    db.commit()
    db.refresh(t)
    log_action(db, current_user.username, "target_tags_updated", target_id=t.id, detail={"tags": payload.tags},
               ip_address=request.client.host if request.client else None)
    return t


class NotificationSettingsUpdate(BaseModel):
    webhook_url: Optional[str] = None          # omitted/null keeps the current webhook; "" removes it
    webhook_format: Optional[str] = None       # omitted/null keeps the current format
    alert_min_severity: Optional[str] = None   # omitted/null keeps the current threshold
    rotate_secret: bool = False
    email_recipients: Optional[List[str]] = None   # omitted/null keeps the current list; [] removes it

    @field_validator("email_recipients")
    @classmethod
    def _recipients(cls, v):
        from backend.emailer import validate_recipients
        return None if v is None else validate_recipients(v)

    @field_validator("webhook_format")
    @classmethod
    def _fmt(cls, v):
        from backend.notifications import WEBHOOK_FORMATS
        if v is None:
            return None
        v = (v or "").lower()
        if v not in WEBHOOK_FORMATS:
            raise ValueError(f"must be one of: {', '.join(WEBHOOK_FORMATS)}")
        return v

    @field_validator("alert_min_severity")
    @classmethod
    def _sev(cls, v):
        from backend.notifications import SEVERITIES
        if v is None:
            return None
        v = (v or "").lower()
        if v not in SEVERITIES:
            raise ValueError(f"must be one of: {', '.join(SEVERITIES)}")
        return v


def _notification_view(t: Target, new_secret: Optional[str] = None) -> dict:
    from urllib.parse import urlparse
    from backend.emailer import smtp_configured
    host = urlparse(t.webhook_url).hostname if t.webhook_url else None
    out = {"target_id": t.id, "alert_min_severity": t.alert_min_severity or "medium",
           "webhook_configured": bool(t.webhook_url), "webhook_host": host,
           "webhook_format": t.webhook_format or "json", "has_secret": bool(t.webhook_secret),
           "email_recipients": list(t.email_recipients or []), "smtp_configured": smtp_configured()}
    if new_secret:
        out["webhook_secret"] = new_secret      # shown exactly once; only the hash-free key is stored
    return out


def _active_target(db: Session, target_id: int) -> Target:
    t = db.query(Target).filter(Target.id == target_id, Target.is_active == True).first()  # noqa: E712
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    return t


@router.get("/{target_id}/notifications")
def get_notification_settings(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return _notification_view(_active_target(db, target_id))


@router.put("/{target_id}/notifications")
def update_notification_settings(target_id: int, payload: NotificationSettingsUpdate, request: Request,
                                 db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    import secrets
    from backend.validators import validate_webhook_url
    t = _active_target(db, target_id)
    keep_url = payload.webhook_url is None
    url = (payload.webhook_url or "").strip()
    if url:
        try:
            url = validate_webhook_url(url)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    new_secret = None
    if payload.alert_min_severity is not None:
        t.alert_min_severity = payload.alert_min_severity
    if payload.webhook_format is not None:
        t.webhook_format = payload.webhook_format
    if payload.email_recipients is not None:
        t.email_recipients = payload.email_recipients or None
    if keep_url:
        if t.webhook_url and payload.rotate_secret:
            t.webhook_secret = new_secret = secrets.token_urlsafe(32)
    elif not url:
        t.webhook_url, t.webhook_secret = None, None
    else:
        t.webhook_url = url
        if payload.rotate_secret or not t.webhook_secret:
            t.webhook_secret = new_secret = secrets.token_urlsafe(32)
    db.commit()
    db.refresh(t)
    log_action(db, current_user.username, "notification_settings_updated", target_id=t.id,
               detail={"min_severity": t.alert_min_severity, "format": t.webhook_format,
                       "webhook": bool(t.webhook_url), "secret_rotated": bool(new_secret),
                       "email_recipients": len(t.email_recipients or [])},
               ip_address=request.client.host if request.client else None)
    return _notification_view(t, new_secret)


@router.post("/{target_id}/notifications/test")
def test_webhook(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    from backend.notifications import send_test
    t = _active_target(db, target_id)
    if not t.webhook_url:
        raise HTTPException(status_code=422, detail="No webhook is configured for this target")
    rec = send_test(db, t, sleep=lambda _s: None)
    return {"status": rec.status, "http_status": rec.http_status, "attempts": rec.attempts, "error": rec.error}


@router.post("/{target_id}/notifications/test-email")
def test_email(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    from backend.emailer import send_test_email, smtp_configured
    t = _active_target(db, target_id)
    if not smtp_configured():
        raise HTTPException(status_code=422, detail="Email is not set up on this server. Set the ASM_SMTP_* variables.")
    if not t.email_recipients:
        raise HTTPException(status_code=422, detail="Add at least one recipient first")
    rec = send_test_email(db, t, sleep=lambda _s: None)
    return {"status": rec.status, "attempts": rec.attempts, "error": rec.error}


class TicketingUpdate(BaseModel):
    destination: Optional[str] = None      # omitted/null keeps the current one; "" turns ticketing off for this target
    min_severity: Optional[str] = None     # omitted/null keeps the current threshold

    @field_validator("min_severity")
    @classmethod
    def _sev(cls, v):
        from backend.notifications import SEVERITIES
        if v is None:
            return None
        v = (v or "").lower()
        if v not in SEVERITIES:
            raise ValueError(f"must be one of: {', '.join(SEVERITIES)}")
        return v


def _ticketing_view(db: Session, t: Target) -> dict:
    from backend import tickets
    from backend.models.ticket import Ticket
    recent = (db.query(Ticket).filter(Ticket.target_id == t.id).order_by(Ticket.id.desc()).limit(10).all())
    return {"target_id": t.id, **tickets.status(), "destination": t.ticket_destination,
            "min_severity": t.ticket_min_severity or "high",
            "recent": [{"id": r.id, "severity": r.severity, "title": r.title, "status": r.status, "key": r.external_key,
                        "url": r.url, "error": r.error, "attempts": r.attempts, "scan_id": r.scan_id,
                        "created_at": r.created_at.isoformat() if r.created_at else None} for r in recent]}


@router.get("/{target_id}/ticketing")
def get_ticketing(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return _ticketing_view(db, _active_target(db, target_id))


@router.put("/{target_id}/ticketing")
def update_ticketing(target_id: int, payload: TicketingUpdate, request: Request, db: Session = Depends(get_db),
                     current_user: dict = Depends(require_admin)):
    from backend import tickets
    t = _active_target(db, target_id)
    if payload.destination is not None:
        provider = tickets.provider_name()
        if payload.destination.strip() and provider is None:
            raise HTTPException(status_code=422, detail="Ticketing is not set up on this server. Set ASM_TICKETS_PROVIDER first.")
        try:
            t.ticket_destination = tickets.validate_destination(provider, payload.destination) or None
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    if payload.min_severity is not None:
        t.ticket_min_severity = payload.min_severity
    db.commit()
    db.refresh(t)
    log_action(db, current_user.username, "ticketing_settings_updated", target_id=t.id,
               detail={"destination": t.ticket_destination, "min_severity": t.ticket_min_severity},
               ip_address=request.client.host if request.client else None)
    return _ticketing_view(db, t)


@router.post("/{target_id}/ticketing/check")
def check_ticketing(target_id: int, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    """Read-only: confirms the credentials work and the destination exists. Creates nothing."""
    import requests
    from backend import tickets
    t = _active_target(db, target_id)
    provider = tickets.provider_name()
    if provider is None or tickets.missing_settings(provider):
        raise HTTPException(status_code=422, detail="Ticketing is not set up on this server. See the README for the ASM_TICKETS_* and ASM_JIRA_* variables.")
    if not t.ticket_destination:
        raise HTTPException(status_code=422, detail="Choose a destination first")
    try:
        return {"ok": True, "message": tickets.check_destination(requests, provider, t.ticket_destination)}
    except tickets.TicketError as e:
        return {"ok": False, "message": e.label}


@router.delete("/{target_id}")
def delete_target(target_id: int, request: Request, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = False
    # A removed target must stop being scanned: pause its schedules and cancel a scan that is queued or running.
    from backend.api.scans import cancel_scan_row
    from backend.models.scan import Scan
    from backend.models.schedule import ScheduledScan
    paused = db.query(ScheduledScan).filter(ScheduledScan.target_id == target.id,
                                            ScheduledScan.enabled == True).update(  # noqa: E712
        {"enabled": False}, synchronize_session=False)
    active = db.query(Scan).filter(Scan.target_id == target.id, Scan.status.in_(["pending", "running"])).all()
    db.commit()
    for sc in active:
        cancel_scan_row(db, sc)
    log_action(db, current_user.username, "target_deleted", target_id=target.id,
               detail={"domain": target.domain, "schedules_paused": paused, "scans_cancelled": len(active)},
               ip_address=request.client.host)
    return {"message": f"Target {target.domain} deactivated"}
