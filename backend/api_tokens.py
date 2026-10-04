"""API tokens: creation, lookup and revocation.

Format `asm_<random>`; only a SHA-256 of it is stored, so a database leak does not leak usable tokens (the secret
has 256 bits of entropy, so a fast hash is appropriate). A token acts as its owner: it stops working when the
owner is deactivated, and every token of a user is revoked when their password changes or is reset.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from backend.models.api_token import ApiToken
from backend.models.user import User

PREFIX = "asm_"
SCOPES = ("read", "write")
MAX_DAYS = 365
MAX_PER_USER = 25
LAST_USED_RESOLUTION = timedelta(minutes=5)       # avoid a database write on every request


def is_api_token(value: Optional[str]) -> bool:
    return bool(value) and value.startswith(PREFIX)


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create(db: Session, user: User, name: str, scope: str, expires_in_days: Optional[int]) -> Tuple[ApiToken, str]:
    secret = PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        user_id=user.id, name=name.strip()[:80], prefix=secret[:12], token_hash=hash_token(secret), scope=scope,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=expires_in_days)) if expires_in_days else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, secret


def lookup(db: Session, secret: str, now: Optional[datetime] = None) -> Optional[Tuple[ApiToken, User]]:
    """The (token, active owner) for a presented secret, or None if unknown, revoked, expired or the owner is inactive."""
    now = now or datetime.now(timezone.utc)
    row = db.query(ApiToken).filter(ApiToken.token_hash == hash_token(secret)).first()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at is not None and _aware(row.expires_at) <= now:
        return None
    user = db.query(User).filter(User.id == row.user_id, User.is_active == True).first()  # noqa: E712
    if user is None:
        return None
    last = _aware(row.last_used_at)
    if last is None or now - last > LAST_USED_RESOLUTION:
        row.last_used_at = now
        db.commit()
    return row, user


def revoke_all(db: Session, user_id: int) -> int:
    n = db.query(ApiToken).filter(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None)).update(
        {ApiToken.revoked_at: datetime.now(timezone.utc)}, synchronize_session=False)
    db.commit()
    return n


def view(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "scope": t.scope, "created_at": t.created_at,
            "last_used_at": t.last_used_at, "expires_at": t.expires_at, "revoked_at": t.revoked_at}
