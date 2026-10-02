from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.db import get_db
from backend.auth import get_current_user
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.discovered_path import DiscoveredPath
from backend.path_flags import is_sensitive_path

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/")
def list_assets(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return db.query(Asset).order_by(Asset.created_at.desc()).all()


@router.get("/{asset_id}/paths")
def asset_paths(asset_id: int, scan_id: int = Query(None), db: Session = Depends(get_db),
                current_user: dict = Depends(get_current_user)):
    """Directory-discovery results for one asset: from `scan_id`, or by default from the most
    recent completed scan that found anything for it. Sensitive-looking paths come first."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    q = db.query(DiscoveredPath).filter(DiscoveredPath.asset_id == asset_id)
    if scan_id is None:
        latest = (db.query(DiscoveredPath.scan_id).join(Scan, Scan.id == DiscoveredPath.scan_id)
                  .filter(DiscoveredPath.asset_id == asset_id, Scan.status == "completed")
                  .order_by(DiscoveredPath.scan_id.desc()).first())
        if not latest:
            return {"scan_id": None, "paths": []}
        scan_id = latest[0]
    rows = q.filter(DiscoveredPath.scan_id == scan_id).all()
    paths = [{
        "path": r.path, "status_code": r.status_code, "content_length": r.content_length,
        "redirect_location": r.redirect_location,
        "sensitive": is_sensitive_path(r.path, r.status_code),
    } for r in rows]
    paths.sort(key=lambda p: (not p["sensitive"], p["path"]))
    return {"scan_id": scan_id, "paths": paths}
