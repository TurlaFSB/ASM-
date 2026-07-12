from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from backend.config import settings
from backend.db import engine, Base, get_db
from backend.models import Target, Asset, Scan
from backend.models.asset import Asset
from backend.api.targets import router as targets_router
from backend.api.scans import router as scans_router
from backend.api.alerts import router as alerts_router

app = FastAPI(
    title="ASM Platform",
    description="Attack Surface Management Platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(alerts_router)

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

@app.get("/assets/")
def list_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return assets