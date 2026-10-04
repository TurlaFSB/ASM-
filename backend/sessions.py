"""Server-side session control on top of stateless JWTs.

A signed token cannot be recalled by itself, so two things make sign-out real:
  * every token carries a unique `jti`; logging out puts it on a Redis deny-list until it would have expired anyway
  * every token carries the user's `ver` (token_version); changing a password, resetting one or deactivating an
    account bumps the version in the database and so invalidates all of that user's tokens at once
If Redis is unreachable the deny-list check fails open (the version check, which lives in the database, still
applies), and the problem is logged.
"""
import hashlib
import hmac
import logging
import time
from typing import Optional

import redis

from backend.config import settings

logger = logging.getLogger(__name__)

_client = None


def redis_client():
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.redis_url, socket_timeout=2)
    return _client


def _key(jti: str) -> str:
    return f"asm:revoked:{jti}"


def revoke(jti: Optional[str], exp: Optional[int]) -> None:
    """Deny-list a token until its own expiry."""
    if not jti:
        return
    ttl = max(1, int((exp or 0) - time.time())) if exp else settings.access_token_expire_minutes * 60
    try:
        redis_client().setex(_key(jti), ttl, "1")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[sessions] could not record sign-out: {e}")


def is_revoked(jti: Optional[str]) -> bool:
    if not jti:
        return False
    try:
        return bool(redis_client().get(_key(jti)))
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[sessions] sign-out list unavailable: {e}")
        return False


def setup_code() -> str:
    """Code that proves the person doing first-run setup can read the server's logs. Derived from SECRET_KEY, so it
    is stable across restarts and workers and needs no storage."""
    h = hmac.new(settings.secret_key.encode(), b"asm-first-run-setup-v1", hashlib.sha256).hexdigest()[:12]
    return "-".join(h[i:i + 4] for i in range(0, 12, 4))
