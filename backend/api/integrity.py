from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend import integrity
from backend.auth import get_current_user
from backend.db import get_db
from backend.models.target import Target

router = APIRouter(prefix="/integrity", tags=["integrity"])


@router.get("/public-key")
def public_key(current_user=Depends(get_current_user)):
    """Ed25519 public key that scan seals verify against (derived from this server's SECRET_KEY)."""
    return integrity.public_key_info()


@router.get("/scans/{scan_id}")
def scan_seal(scan_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    res = integrity.verify_scan_seal(db, scan_id)
    if res is None:
        raise HTTPException(status_code=404, detail="This scan has no integrity seal")
    return res


@router.get("/targets/{target_id}")
def target_chain(target_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if not db.query(Target).filter(Target.id == target_id).first():
        raise HTTPException(status_code=404, detail="Target not found")
    return integrity.verify_target_chain(db, target_id)
