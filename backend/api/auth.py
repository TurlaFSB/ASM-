import hmac
from datetime import datetime, timezone

import jwt
import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend import sessions
from backend.user_policy import validate_password, validate_username
from backend.auth import (pwd_context, verify_password, authenticate_user, create_access_token, get_current_user, set_session_cookies,
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
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    token = create_access_token({"sub": user.username, "ver": user.token_version or 0})
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


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Ends the session for real: the token is put on a deny-list until it would have expired, so a copy of it
    (stolen cookie, leaked header) stops working too. Safe to call without a session."""
    token = request.cookies.get(SESSION_COOKIE)
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if token:
        try:
            claims = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
            sessions.revoke(claims.get("jti"), claims.get("exp"))
            if claims.get("sub"):
                log_action(db, str(claims["sub"])[:64], "logout", ip_address=_client_ip(request))
        except jwt.PyJWTError:
            pass
    clear_session_cookies(response)
    return {"ok": True}


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(payload: PasswordChange, request: Request, response: Response,
                    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Changes your own password. Every other session of yours is signed out; this one stays signed in."""
    ip = _client_ip(request)
    rc = _redis_client()
    if is_locked(rc, ip, current_user.username):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed attempts. Try again in 15 minutes.",
                            headers={"Retry-After": "900"})
    if not verify_password(payload.current_password, current_user.hashed_password):
        record_failure(rc, ip, current_user.username)
        log_action(db, current_user.username, "password_change_failed", ip_address=ip)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")
    err = validate_password(payload.new_password, current_user.username)
    if err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)
    if verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Choose a password you have not used just now.")
    current_user.hashed_password = pwd_context.hash(payload.new_password)
    current_user.token_version = (current_user.token_version or 0) + 1
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, current_user.username, "password_changed", ip_address=ip)
    set_session_cookies(response, create_access_token({"sub": current_user.username, "ver": current_user.token_version}))
    return {"ok": True}


# First-run setup. Until the first account exists the app offers a setup screen. To stop a stranger who reaches
# the page first from claiming the platform, setup needs a code that is printed in the server log at start-up.
@router.get("/setup-status")
def setup_status(db: Session = Depends(get_db)):
    return {"needs_setup": db.query(User.id).first() is None}


class SetupPayload(BaseModel):
    setup_code: str
    username: str
    password: str


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def first_run_setup(payload: SetupPayload, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    rc = _redis_client()
    if db.query(User.id).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Setup is already complete.")
    if is_locked(rc, ip, "setup"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed attempts. Try again in 15 minutes.",
                            headers={"Retry-After": "900"})
    if not hmac.compare_digest(payload.setup_code.strip().lower().encode(), sessions.setup_code().encode()):
        record_failure(rc, ip, "setup")
        log_action(db, "setup", "setup_failed", ip_address=ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="That setup code is not right. Find it in the backend log.")
    err = validate_username(payload.username) or validate_password(payload.password, payload.username)
    if err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)
    user = User(username=payload.username, hashed_password=pwd_context.hash(payload.password), role="admin", is_active=True,
                token_version=0, last_login_at=datetime.now(timezone.utc), password_changed_at=datetime.now(timezone.utc))
    db.add(user)
    try:
        db.commit()
    except Exception:  # noqa: BLE001  two people racing: the unique username index lets only one win
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Setup is already complete.")
    log_action(db, user.username, "setup_completed", ip_address=ip)
    set_session_cookies(response, create_access_token({"sub": user.username, "ver": 0}))
    return {"username": user.username, "role": user.role}
