"""Security helpers: login throttling (Redis) and security headers.

Three counters guard the login endpoint:
  * per (ip, username)  - strict, stops focused guessing from one client
  * per IP              - stops one client spraying many usernames
  * per username        - stops a distributed attack on one account (higher limit so an
                          attacker cannot trivially lock the real owner out)
Any counter at its limit locks the attempt. A successful login only clears the
(ip, username) counter, never the IP-wide or username-wide ones.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

MAX_FAILURES = 5          # per (ip, username)
MAX_FAILURES_PER_IP = 30  # per IP across all usernames
MAX_FAILURES_PER_USER = 20  # per username across all IPs
WINDOW_SECONDS = 900  # 15 minutes


def _norm(username: str) -> str:
    return (username or "").lower()[:64]


def _key(ip: str, username: str) -> str:
    return f"login_fail:{ip}:{_norm(username)}"


def _ip_key(ip: str) -> str:
    return f"login_fail_ip:{ip}"


def _user_key(username: str) -> str:
    return f"login_fail_user:{_norm(username)}"


def _count(client, key: str) -> int:
    return int(client.get(key) or 0)


def is_locked(client, ip: str, username: str, max_failures: int = MAX_FAILURES) -> bool:
    """True if any throttle counter hit its limit. Fails OPEN if Redis is down
    (availability of login beats throttling, and the failure is logged)."""
    try:
        return (
            _count(client, _key(ip, username)) >= max_failures
            or _count(client, _ip_key(ip)) >= MAX_FAILURES_PER_IP
            or _count(client, _user_key(username)) >= MAX_FAILURES_PER_USER
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[security] throttle check unavailable: {e}")
        return False


def _bump(client, key: str, window: int) -> int:
    n = client.incr(key)
    if n == 1:
        client.expire(key, window)
    return int(n)


def record_failure(client, ip: str, username: str, window: int = WINDOW_SECONDS) -> Optional[int]:
    """Count a failed login on all three counters. Returns the (ip, username) count."""
    try:
        n = _bump(client, _key(ip, username), window)
        _bump(client, _ip_key(ip), window)
        _bump(client, _user_key(username), window)
        return n
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
