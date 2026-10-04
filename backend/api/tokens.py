"""Manage your own API tokens. Tokens are shown once, when created."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend import api_tokens
from backend.audit import log_action
from backend.auth import get_current_user
from backend.db import get_db
from backend.models.api_token import ApiToken
from backend.models.user import User

router = APIRouter(prefix="/auth/tokens", tags=["api tokens"])


class NewToken(BaseModel):
    name: str
    scope: str = "read"
    expires_in_days: Optional[int] = 90


def _ip(request: Request):
    return request.client.host if request.client else None


@router.get("/")
def list_tokens(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(ApiToken).filter(ApiToken.user_id == user.id).order_by(ApiToken.id.desc()).all()
    return [api_tokens.view(r) for r in rows]


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_token(payload: NewToken, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=403, detail="Create tokens from a signed-in browser session, not with another token.")
    name = payload.name.strip()
    if not 1 <= len(name) <= 80:
        raise HTTPException(status_code=422, detail="Give the token a name of 1 to 80 characters.")
    if payload.scope not in api_tokens.SCOPES:
        raise HTTPException(status_code=422, detail="Scope must be read or write.")
    if payload.scope == "write" and (user.role or "admin") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create write tokens.")
    days = payload.expires_in_days
    if days is not None and not 1 <= days <= api_tokens.MAX_DAYS:
        raise HTTPException(status_code=422, detail=f"Expiry must be between 1 and {api_tokens.MAX_DAYS} days.")
    active = db.query(ApiToken).filter(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None)).count()
    if active >= api_tokens.MAX_PER_USER:
        raise HTTPException(status_code=409, detail="You have reached the limit of active tokens. Revoke one first.")
    row, secret = api_tokens.create(db, user, name, payload.scope, days)
    log_action(db, user.username, "api_token_created", detail={"name": row.name, "scope": row.scope}, ip_address=_ip(request))
    return {**api_tokens.view(row), "token": secret}


@router.delete("/{token_id}")
def revoke_token(token_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = db.query(ApiToken).filter(ApiToken.id == token_id, ApiToken.user_id == user.id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()
        log_action(db, user.username, "api_token_revoked", detail={"name": row.name}, ip_address=_ip(request))
    return {"ok": True}
