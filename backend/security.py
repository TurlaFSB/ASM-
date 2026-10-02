"""Security helpers: login throttling (Redis) and security headers."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

MAX_FAILURES = 5
WINDOW_SECONDS = 900  # 15 minutes


def _key(ip: str, username: str) -> str:
    return f"login_fail:{ip}:{(username or '').lower()[:64]}"


def is_locked(client, ip: str, username: str, max_failures: int = MAX_FAILURES) -> bool:
    """True if this ip+username already hit the failure limit. Fails OPEN if Redis is down
    (availability of login beats throttling, and the failure is logged)."""
    try:
        val = client.get(_key(ip, username))
        return int(val or 0) >= max_failures
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[security] throttle check unavailable: {e}")
        return False


def record_failure(client, ip: str, username: str, window: int = WINDOW_SECONDS) -> Optional[int]:
    try:
        k = _key(ip, username)
        n = client.incr(k)
        if n == 1:
            client.expire(k, window)
        return int(n)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[security] could not record login failure: {e}")
        return None


def clear_failures(client, ip: str, username: str) -> None:
    try:
        client.delete(_key(ip, username))
    except Exception:  # noqa: BLE001
        pass


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
