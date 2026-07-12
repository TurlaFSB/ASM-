from fastapi import FastAPI
from backend.config import settings
from backend.db import engine, Base
from backend.models import Target, Asset, Scan
from backend.api.targets import router as targets_router
from backend.api.scans import router as scans_router

app = FastAPI(
    title="ASM Platform",
    description="Attack Surface Management Platform",
    version="0.1.0"
)

app.include_router(targets_router)
app.include_router(scans_router)

@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "env": settings.app_env,
        "version": "0.1.0"
    }