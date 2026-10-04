"""Global per-client API rate limit (fixed one-minute window, counted in Redis).

This is a blunt safety net against floods and scripted abuse; login attempts have their own, much stricter
throttle. If Redis is unreachable the limiter fails open and logs the problem, so an outage never locks users out.
Behind a reverse proxy, start uvicorn with --proxy-headers and FORWARDED_ALLOW_IPS set to the proxy address so the
real client address is used instead of the proxy's.
"""
import logging
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from backend import sessions
from backend.config import settings

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {"/health", "/ready"}
WINDOW_SECONDS = 60


def check(client: str, now: float | None = None) -> int:
    """Count this request; return 0 if allowed, otherwise the seconds to wait."""
    limit = settings.api_rate_limit_per_minute
    if limit <= 0:
        return 0
    now = time.time() if now is None else now
    window = int(now // WINDOW_SECONDS)
    try:
        r = sessions.redis_client()
        key = f"asm:rl:{client}:{window}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, WINDOW_SECONDS + 5)
        if count > limit:
            return max(1, int((window + 1) * WINDOW_SECONDS - now))
    except Exception:  # noqa: BLE001  fail open
        logger.warning("rate limiter unavailable; allowing request", exc_info=True)
    return 0


async def rate_limit_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in EXEMPT_PATHS:
        return await call_next(request)
    client = request.client.host if request.client else "unknown"
    wait = check(client)
    if wait:
        return JSONResponse({"detail": "Too many requests. Slow down and retry shortly."}, status_code=429,
                            headers={"Retry-After": str(wait)})
    return await call_next(request)
