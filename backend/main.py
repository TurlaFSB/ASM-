import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from backend.config import settings
from backend.db import engine, Base, get_db
from backend.models import Target, Asset, Scan, Vulnerability
from backend.models.asset import Asset
from backend.api.targets import router as targets_router
from backend.api.scans import router as scans_router
from backend.api.alerts import router as alerts_router
from backend.api.vulnerabilities import router as vulnerabilities_router
from backend.api.auth import router as auth_router
from backend.api.schedules import router as schedules_router
from backend.api.audit import router as audit_router
from backend.api.assets import router as assets_router
from backend.api.changes import router as changes_router
from backend.api.exposure import router as exposure_router
from backend.api.integrity import router as integrity_router
from backend.api.users import router as users_router
from backend.auth import get_current_user, require_admin
from backend.observability import configure_logging, render_metrics
from fastapi.responses import PlainTextResponse
from backend.security import SECURITY_HEADERS
from backend.ratelimit import rate_limit_middleware
from starlette.middleware.base import BaseHTTPMiddleware

def _announce_first_run():
    """With no accounts yet, print the code the web setup screen asks for."""
    try:
        from backend.db import SessionLocal
        from backend.models.user import User
        from backend.sessions import setup_code
        db = SessionLocal()
        try:
            if db.query(User.id).first() is None:
                logging.getLogger("uvicorn.error").warning(
                    "FIRST RUN: no accounts exist yet. Open the web app and create the first admin with setup code %s "
                    "(or run: python3 -m backend.scripts.create_admin).", setup_code())
        finally:
            db.close()
    except Exception:  # noqa: BLE001  never block start-up on this
        pass


@asynccontextmanager
async def lifespan(app):
    # Schema is owned by Alembic (the `migrate` compose service / `alembic upgrade head`),
    # not create_all: create_all silently skips changes to existing tables.
    _announce_first_run()
    yield


configure_logging()
_is_prod = settings.app_env.lower() in ("production", "prod")

app = FastAPI(
    lifespan=lifespan,
    # Interactive API docs/schema are a free map of the attack surface; off in production.
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
    title="ASM Platform",
    description="Attack Surface Management Platform",
    version="0.1.0"
)

# Added before CORS so that CORS wraps it: a 429 must still carry CORS headers or the browser hides it.
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

app.include_router(auth_router)
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(alerts_router)
app.include_router(vulnerabilities_router)
app.include_router(schedules_router)
app.include_router(audit_router)
app.include_router(assets_router)
app.include_router(changes_router)
app.include_router(exposure_router)
app.include_router(integrity_router)
app.include_router(users_router)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "env": settings.app_env,
        "version": "0.1.0"
    }

@app.get("/ready")
def readiness(db: Session = Depends(get_db)):
    """Dependency check for orchestrators: DB and Redis must both answer."""
    import redis as _redis
    from sqlalchemy import text
    checks = {}
    try:
        db.execute(text("select 1")); checks["database"] = "ok"
    except Exception:
        checks["database"] = "down"
    try:
        _redis.Redis.from_url(settings.redis_url, socket_timeout=2).ping(); checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "down"
    if "down" in checks.values():
        raise HTTPException(status_code=503, detail=checks)
    return {"status": "ready", **checks}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(db: Session = Depends(get_db), admin=Depends(require_admin)):
    """Prometheus text format; admin only (scrape with an admin bearer token)."""
    depth = None
    try:
        import redis as _redis
        depth = int(_redis.Redis.from_url(settings.redis_url, socket_timeout=2).llen("celery"))
    except Exception:  # noqa: BLE001
        pass
    return PlainTextResponse(render_metrics(db, depth), media_type="text/plain; version=0.0.4")
