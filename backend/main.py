from fastapi import FastAPI
from backend.config import settings
from backend.db import engine, Base
from backend.models import Target, Asset, Scan

app = FastAPI(
    title="ASM Platform",
    description="Attack Surface Management Platform",
    version="0.1.0"
)

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