import hmac
from datetime import datetime, timedelta, timezone

import jwt
import redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend import mfa, sessions
from backend.user_policy import validate_password, validate_username
from backend.auth import (pwd_context, verify_password, authenticate_user, create_access_token, get_current_user, set_session_cookies,
                          set_csrf_cookie, clear_session_cookies, SESSION_COOKIE, CSRF_COOKIE)
from backend.db import get_db
from backend.models.user import User
from backend.config import settings
from backend.audit import log_action
from backend.security import is_locked, record_failure, clear_failures

router = APIRouter(prefix="/auth", tags=["auth"])

MFA_CHALLENGE_MINUTES = 5

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
    if user.mfa_enabled:
        # Password accepted, second step pending: no session yet. The challenge only works at /auth/mfa/verify.
        log_action(db, user.username, "login_mfa_required", ip_address=ip)
        challenge = create_access_token({"sub": user.username, "purpose": "mfa", "ver": user.token_version or 0},
                                        expires_delta=timedelta(minutes=MFA_CHALLENGE_MINUTES))
        return {"mfa_required": True, "mfa_token": challenge, "username": user.username}
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
    return {"username": current_user.username, "role": current_user.role, "mfa_enabled": bool(current_user.mfa_enabled)}


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
    from backend import api_tokens
    api_tokens.revoke_all(db, current_user.id)       # a new password also ends every script credential
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


# ---------------------------------------------------------------- two-step sign-in (authenticator app)
class MfaVerify(BaseModel):
    mfa_token: str
    code: str


def _too_many():
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed attempts. Try again in 15 minutes.",
                         headers={"Retry-After": "900"})


def _check_second_factor(user: User, code: str) -> bool:
    """True if `code` is a fresh authenticator code or an unused recovery code. Updates the user; caller commits."""
    secret = mfa.decrypt_secret(user.mfa_secret)
    if mfa.looks_like_recovery(code):
        remaining = mfa.consume_recovery(user.mfa_recovery, code)
        if remaining is None:
            return False
        user.mfa_recovery = remaining
        return True
    if not secret:
        return False
    step = mfa.verify_code(secret, code, user.mfa_last_step)
    if step is None:
        return False
    user.mfa_last_step = step
    return True


@router.post("/mfa/verify")
def mfa_verify(payload: MfaVerify, request: Request, response: Response, db: Session = Depends(get_db)):
    """Second step of sign-in: the challenge from /auth/token plus a code from the authenticator app (or a recovery code)."""
    ip = _client_ip(request)
    rc = _redis_client()
    bad = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That sign-in has expired or the code is wrong. Start again.")
    try:
        claims = jwt.decode(payload.mfa_token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.PyJWTError:
        raise bad
    if claims.get("purpose") != "mfa" or not claims.get("sub"):
        raise bad
    username = str(claims["sub"])
    if is_locked(rc, ip, username):
        raise _too_many()
    user = db.query(User).filter(User.username == username, User.is_active == True).first()  # noqa: E712
    if user is None or not user.mfa_enabled or int(claims.get("ver", 0)) != int(user.token_version or 0):
        raise bad
    if not _check_second_factor(user, payload.code):
        db.rollback()
        record_failure(rc, ip, username)
        log_action(db, username, "mfa_failed", ip_address=ip)
        raise bad
    clear_failures(rc, ip, username)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, username, "login_success", detail={"mfa": True}, ip_address=ip)
    token = create_access_token({"sub": user.username, "ver": user.token_version or 0})
    set_session_cookies(response, token)
    return {"access_token": token, "token_type": "bearer", "username": user.username,
            "recovery_codes_left": len(user.mfa_recovery or [])}


class PasswordOnly(BaseModel):
    password: str


class CodeOnly(BaseModel):
    code: str


class PasswordAndCode(BaseModel):
    password: str
    code: str


def _reauth(user: User, password: str, request: Request, db: Session) -> None:
    ip, rc = _client_ip(request), _redis_client()
    if is_locked(rc, ip, user.username):
        raise _too_many()
    if not verify_password(password, user.hashed_password):
        record_failure(rc, ip, user.username)
        log_action(db, user.username, "mfa_reauth_failed", ip_address=ip)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is incorrect.")


@router.post("/mfa/setup")
def mfa_setup(payload: PasswordOnly, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Starts enrolment: returns a new secret and the otpauth link for the authenticator app. Nothing is
    switched on until /auth/mfa/enable confirms a code from the app."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Two-step sign-in is already on. Turn it off first to enrol again.")
    _reauth(current_user, payload.password, request, db)
    secret = mfa.new_secret()
    current_user.mfa_secret = mfa.encrypt_secret(secret)
    current_user.mfa_last_step = None
    db.commit()
    return {"secret": secret, "otpauth_uri": mfa.provisioning_uri(current_user.username, secret), "issuer": mfa.ISSUER}


@router.post("/mfa/enable")
def mfa_enable(payload: CodeOnly, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Two-step sign-in is already on.")
    secret = mfa.decrypt_secret(current_user.mfa_secret)
    if not secret:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Start setup first.")
    ip, rc = _client_ip(request), _redis_client()
    if is_locked(rc, ip, current_user.username):
        raise _too_many()
    step = mfa.verify_code(secret, payload.code)
    if step is None:
        record_failure(rc, ip, current_user.username)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That code is not right. Check the app and the time on your phone.")
    codes, hashes = mfa.new_recovery_codes()
    current_user.mfa_enabled = True
    current_user.mfa_last_step = step
    current_user.mfa_recovery = hashes
    db.commit()
    log_action(db, current_user.username, "mfa_enabled", ip_address=ip)
    return {"ok": True, "recovery_codes": codes}


def _require_enabled_and_code(user: User, payload: PasswordAndCode, request: Request, db: Session) -> None:
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Two-step sign-in is not on.")
    _reauth(user, payload.password, request, db)
    if not _check_second_factor(user, payload.code):
        db.rollback()
        record_failure(_redis_client(), _client_ip(request), user.username)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That code is not right.")


@router.post("/mfa/disable")
def mfa_disable(payload: PasswordAndCode, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_enabled_and_code(current_user, payload, request, db)
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_last_step = None
    current_user.mfa_recovery = None
    db.commit()
    log_action(db, current_user.username, "mfa_disabled", ip_address=_client_ip(request))
    return {"ok": True}


@router.post("/mfa/recovery-codes")
def mfa_new_recovery_codes(payload: PasswordAndCode, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Replaces all recovery codes (the old ones stop working) and shows the new set once."""
    _require_enabled_and_code(current_user, payload, request, db)
    codes, hashes = mfa.new_recovery_codes()
    current_user.mfa_recovery = hashes
    db.commit()
    log_action(db, current_user.username, "mfa_recovery_regenerated", ip_address=_client_ip(request))
    return {"recovery_codes": codes}
