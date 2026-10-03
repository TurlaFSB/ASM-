import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.auth import (authenticate_user, create_access_token, get_current_user, set_session_cookies,
                          set_csrf_cookie, clear_session_cookies, SESSION_COOKIE, CSRF_COOKIE)
from backend.db import get_db
from backend.models.user import User
from backend.config import settings
from backend.audit import log_action
from backend.security import is_locked, record_failure, clear_failures

router = APIRouter(prefix="/auth", tags=["auth"])

_redis = None


def _redis_client():
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.redis_url, socket_timeout=2)
    return _redis


@router.post("/token")
def login(request: Request, response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    rc = _redis_client()
    if is_locked(rc, ip, form_data.username):
        log_action(db, form_data.username[:64], "login_locked", ip_address=ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        record_failure(rc, ip, form_data.username)
        log_action(db, form_data.username[:64], "login_failed", ip_address=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    clear_failures(rc, ip, form_data.username)
    log_action(db, user.username, "login_success", ip_address=ip)
    token = create_access_token({"sub": user.username})
    set_session_cookies(response, token)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username
    }

@router.get("/me")
def get_me(request: Request, response: Response, current_user: User = Depends(get_current_user)):
    # Self-heal: a valid session cookie but a missing CSRF cookie (cleared or expired on its own)
    # would make every state-changing call fail, so hand out a fresh CSRF cookie here.
    if request.cookies.get(SESSION_COOKIE) and not request.cookies.get(CSRF_COOKIE):
        set_csrf_cookie(response)
    return {"username": current_user.username, "role": current_user.role}


@router.post("/logout")
def logout(response: Response):
    """Clears the session cookies. Safe to call without a session."""
    clear_session_cookies(response)
    return {"ok": True}
