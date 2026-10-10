"""Account management for admins. Accounts are deactivated, never deleted, so the audit trail keeps its names."""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.audit import log_action
from backend.auth import pwd_context, require_admin
from backend.db import get_db
from backend.models.user import User
from backend.user_policy import ROLES, validate_password, validate_username

router = APIRouter(prefix="/users", tags=["users"])


def _view(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role or "admin", "is_active": bool(u.is_active),
            "created_at": u.created_at, "last_login_at": u.last_login_at, "password_changed_at": u.password_changed_at,
            "mfa_enabled": bool(u.mfa_enabled)}


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _active_admins(db: Session) -> int:
    return db.query(User).filter(User.is_active == True, (User.role == "admin") | (User.role.is_(None))).count()  # noqa: E712


def _get(db: Session, user_id: int) -> User:
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u


@router.get("/")
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return [_view(u) for u in db.query(User).order_by(User.username).all()]


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(payload: NewUser, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    err = validate_username(payload.username) or validate_password(payload.password, payload.username)
    if err:
        raise HTTPException(status_code=422, detail=err)
    if payload.role not in ROLES:
        raise HTTPException(status_code=422, detail="Role must be admin or viewer.")
    if db.query(User).filter(func.lower(User.username) == payload.username.lower()).first():
        raise HTTPException(status_code=409, detail="That username is already taken.")
    u = User(username=payload.username, hashed_password=pwd_context.hash(payload.password), role=payload.role, is_active=True,
             token_version=0, password_changed_at=datetime.now(timezone.utc))
    db.add(u)
    db.commit()
    log_action(db, admin.username, "user_created", detail={"user": u.username, "role": u.role}, ip_address=_ip(request))
    return _view(u)


class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None


@router.patch("/{user_id}")
def update_user(user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    u = _get(db, user_id)
    changes = {}
    if payload.role is not None and payload.role != (u.role or "admin"):
        if payload.role not in ROLES:
            raise HTTPException(status_code=422, detail="Role must be admin or viewer.")
        if u.id == admin.id:
            raise HTTPException(status_code=409, detail="You cannot change your own role. Ask another admin.")
        if (u.role or "admin") == "admin" and u.is_active and _active_admins(db) <= 1:
            raise HTTPException(status_code=409, detail="There must be at least one active admin.")
        u.role = payload.role
        u.token_version = (u.token_version or 0) + 1       # new role applies to a fresh sign-in
        changes["role"] = payload.role
    if payload.is_active is not None and payload.is_active != bool(u.is_active):
        if not payload.is_active:
            if u.id == admin.id:
                raise HTTPException(status_code=409, detail="You cannot deactivate your own account.")
            if (u.role or "admin") == "admin" and _active_admins(db) <= 1:
                raise HTTPException(status_code=409, detail="There must be at least one active admin.")
            u.token_version = (u.token_version or 0) + 1   # signs the person out everywhere at once
        u.is_active = payload.is_active
        changes["is_active"] = payload.is_active
    if changes:
        db.commit()
        log_action(db, admin.username, "user_updated", detail={"user": u.username, **changes}, ip_address=_ip(request))
    return _view(u)


class PasswordReset(BaseModel):
    new_password: str


@router.post("/{user_id}/reset-password")
def reset_password(user_id: int, payload: PasswordReset, request: Request, db: Session = Depends(get_db),
                   admin: User = Depends(require_admin)):
    """Sets a new password for someone else and signs them out everywhere. Share the new password in person or
    through a secure channel; they can change it from the account menu."""
    u = _get(db, user_id)
    if u.id == admin.id:
        raise HTTPException(status_code=409, detail="Use Change password in the account menu for your own account.")
    err = validate_password(payload.new_password, u.username)
    if err:
        raise HTTPException(status_code=422, detail=err)
    u.hashed_password = pwd_context.hash(payload.new_password)
    u.token_version = (u.token_version or 0) + 1
    u.password_changed_at = datetime.now(timezone.utc)
    db.commit()
    from backend import api_tokens
    api_tokens.revoke_all(db, u.id)
    log_action(db, admin.username, "user_password_reset", detail={"user": u.username}, ip_address=_ip(request))
    return {"ok": True}


@router.post("/{user_id}/reset-mfa")
def reset_mfa(user_id: int, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """For someone who lost their phone and recovery codes: turns their two-step sign-in off and signs them out
    everywhere. They can switch it on again after signing in with their password."""
    u = _get(db, user_id)
    if u.id == admin.id:
        raise HTTPException(status_code=409, detail="Turn off your own two-step sign-in from the account menu.")
    u.mfa_enabled, u.mfa_secret, u.mfa_last_step, u.mfa_recovery = False, None, None, None
    u.token_version = (u.token_version or 0) + 1
    db.commit()
    log_action(db, admin.username, "user_mfa_reset", detail={"user": u.username}, ip_address=_ip(request))
    return {"ok": True}
