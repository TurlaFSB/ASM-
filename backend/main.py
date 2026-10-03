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
from backend.auth import get_current_user
from backend.security import SECURITY_HEADERS

@asynccontextmanager
async def lifespan(app):
    # Schema is owned by Alembic (the `migrate` compose service / `alembic upgrade head`),
    # not create_all: create_all silently skips changes to existing tables.
    yield


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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
