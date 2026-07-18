from fastapi import FastAPI, Depends, HTTPException
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
from backend.auth import get_current_user

app = FastAPI(
    title="ASM Platform",
    description="Attack Surface Management Platform",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000", "http://192.168.16.130:3000", "http://192.168.75.129:3000"],
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
def list_assets(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return assets


@app.get("/targets/{target_id}/history")
def get_target_history(target_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target_id, Scan.status == "completed")
        .order_by(Scan.created_at.asc())
        .all()
    )

    history = []
    for scan in scans:
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        for v in vulns:
            if v.severity in vuln_counts:
                vuln_counts[v.severity] += 1

        history.append({
            "scan_id": scan.id,
            "date": (scan.completed_at or scan.created_at).isoformat(),
            "total_assets": scan.total_assets or 0,
            "new_assets": scan.new_assets or 0,
            "changed_assets": scan.changed_assets or 0,
            "disappeared_assets": scan.disappeared_assets or 0,
            "vuln_counts": vuln_counts,
        })

    return {
        "target_id": target.id,
        "domain": target.domain,
        "history": history,
    }
