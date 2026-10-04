from datetime import datetime, timedelta, timezone
from typing import Optional
import hmac
import secrets
import uuid
import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from backend import api_tokens, sessions
from backend.config import settings
from backend.db import get_db
from backend.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)

SESSION_COOKIE = "asm_session"   # httpOnly: JavaScript (and so any XSS) cannot read it
CSRF_COOKIE = "asm_csrf"         # readable on purpose: the page echoes it in X-CSRF-Token (double submit)
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _cookie_opts() -> dict:
    return dict(max_age=settings.access_token_expire_minutes * 60, path="/", secure=settings.cookie_secure, samesite="lax")


def set_csrf_cookie(response: Response) -> None:
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, **_cookie_opts())


def set_session_cookies(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **_cookie_opts())
    set_csrf_cookie(response)


def clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=settings.cookie_secure, samesite="lax")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# A real bcrypt hash of a random value, used so unknown/inactive users cost the same
# time as a wrong password (no username enumeration via response timing).
_DUMMY_HASH = pwd_context.hash("asm-timing-equaliser")


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        pwd_context.verify(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire, "jti": uuid.uuid4().hex})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def get_current_user(request: Request, bearer: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = bearer
    if token is None:
        token = request.cookies.get(SESSION_COOKIE)
        if token and request.method not in SAFE_METHODS:
            # Cookies are sent automatically by the browser, so state-changing calls must prove
            # they came from our own page. A Bearer header cannot be forged cross-site, so it is exempt.
            sent, expected = request.headers.get(CSRF_HEADER), request.cookies.get(CSRF_COOKIE)
            if not sent or not expected or not hmac.compare_digest(sent, expected):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed")
    if not token:
        raise credentials_exception
    if api_tokens.is_api_token(token):
        found = api_tokens.lookup(db, token)
        if found is None:
            raise credentials_exception
        row, owner = found
        if row.scope != "write" and request.method not in SAFE_METHODS:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This API token is read-only")
        request.state.via_api_token = True
        return owner
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    if sessions.is_revoked(payload.get("jti")):          # signed out
        raise credentials_exception
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    # Password changed/reset or account deactivated since this token was issued. Tokens from before the
    # upgrade carry no version and count as version 0.
    if int(payload.get("ver", 0)) != int(getattr(user, "token_version", 0) or 0):
        raise credentials_exception
    return user


ROLES = ("admin", "viewer")


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Gate for mutating routes. Viewers are read-only. A missing role (legacy rows
    created before roles existed) counts as admin so upgrades do not lock anyone out."""
    if (getattr(current_user, "role", None) or "admin") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user
