"""Tamper-evident scan history.

Every completed scan is sealed:

    seal_hash = SHA-256( canonical JSON of {version, scan_id, target_id, profile, seq,
                                            snapshot_hash, prev_seal_hash, sealed_at} )
    signature = Ed25519( seal_hash )

`snapshot_hash` is the hash of the stored scan snapshot (what the scan observed), and
`prev_seal_hash` links each seal to the one before it for the same target, so editing a snapshot,
editing a seal, deleting one from the middle or reordering them is detectable by anyone who holds
the public key. The signing key is derived from SECRET_KEY, so no extra secret has to be managed;
if SECRET_KEY is rotated, older seals still verify structurally but report a key mismatch.

Limits (also in the README): this proves the stored record has not been altered since sealing. It does not
prove the scanners saw the truth, and someone who controls both the database and SECRET_KEY could
re-seal history. Export the public key and periodic head-of-chain hashes if you need protection against that.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.orm import Session

from backend.config import settings
from backend.diffing.snapshot import snapshot_hash
from backend.models.scan import Scan
from backend.models.scan_seal import ScanSeal
from backend.models.scan_snapshot import ScanSnapshot

SEAL_VERSION = 1


def _private_key() -> Ed25519PrivateKey:
    seed = hmac.new(settings.secret_key.encode(), b"asm-scan-seal-ed25519-v1", hashlib.sha256).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_info() -> Dict:
    raw = _raw_public(_private_key().public_key())
    return {"algorithm": "Ed25519", "public_key": raw.hex(), "key_id": hashlib.sha256(raw).hexdigest()[:16]}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def compute_seal_hash(*, scan_id: int, target_id: int, profile: str, seq: int, snapshot_hash_: str,
                      prev_seal_hash: Optional[str], sealed_at: str) -> str:
    payload = {"v": SEAL_VERSION, "scan_id": scan_id, "target_id": target_id, "profile": profile, "seq": seq,
               "snapshot_hash": snapshot_hash_, "prev_seal_hash": prev_seal_hash, "sealed_at": sealed_at}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def seal_scan(db: Session, scan: Scan) -> Optional[ScanSeal]:
    """Seal a scan whose snapshot is stored. Idempotent. Returns None if there is nothing to seal."""
    existing = db.query(ScanSeal).filter(ScanSeal.scan_id == scan.id).first()
    if existing:
        return existing
    snap = db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == scan.id).first()
    if snap is None:
        return None
    prev = (db.query(ScanSeal).filter(ScanSeal.target_id == scan.target_id)
            .order_by(ScanSeal.seq.desc()).first())
    seq = (prev.seq + 1) if prev else 1
    sealed_at = _iso(datetime.now(timezone.utc))
    seal_hash = compute_seal_hash(scan_id=scan.id, target_id=scan.target_id, profile=snap.profile, seq=seq,
                                  snapshot_hash_=snap.content_hash,
                                  prev_seal_hash=prev.seal_hash if prev else None, sealed_at=sealed_at)
    key = _private_key()
    row = ScanSeal(scan_id=scan.id, target_id=scan.target_id, seq=seq, profile=snap.profile,
                   snapshot_hash=snap.content_hash, prev_seal_hash=prev.seal_hash if prev else None,
                   seal_hash=seal_hash, signature=key.sign(bytes.fromhex(seal_hash)).hex(),
                   key_id=hashlib.sha256(_raw_public(key.public_key())).hexdigest()[:16],
                   sealed_at=datetime.fromisoformat(sealed_at))
    db.add(row)
    db.commit()
    return row


def _verify_one(db: Session, row: ScanSeal, previous: Optional[ScanSeal]) -> Dict:
    snap = db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == row.scan_id).first()
    checks = {
        "snapshot_intact": bool(snap) and snapshot_hash(snap.data) == row.snapshot_hash == snap.content_hash,
        "seal_hash_ok": compute_seal_hash(
            scan_id=row.scan_id, target_id=row.target_id, profile=row.profile, seq=row.seq,
            snapshot_hash_=row.snapshot_hash, prev_seal_hash=row.prev_seal_hash,
            sealed_at=_iso(row.sealed_at if row.sealed_at.tzinfo else row.sealed_at.replace(tzinfo=timezone.utc)),
        ) == row.seal_hash,
        "chain_link_ok": (row.prev_seal_hash is None and row.seq == 1) if previous is None
        else (row.prev_seal_hash == previous.seal_hash and row.seq == previous.seq + 1),
    }
    current = public_key_info()
    key_match = row.key_id == current["key_id"]
    try:
        _private_key().public_key().verify(bytes.fromhex(row.signature), bytes.fromhex(row.seal_hash))
        checks["signature_ok"] = True
    except (InvalidSignature, ValueError):
        checks["signature_ok"] = False
    # A signature made with a retired key is not a tamper signal, but it cannot be confirmed here.
    signature_unverifiable = (not checks["signature_ok"]) and not key_match
    ok = checks["snapshot_intact"] and checks["seal_hash_ok"] and checks["chain_link_ok"] and (
        checks["signature_ok"] or signature_unverifiable)
    return {"scan_id": row.scan_id, "seq": row.seq, "seal_hash": row.seal_hash, "key_id": row.key_id,
            "sealed_at": _iso(row.sealed_at if row.sealed_at.tzinfo else row.sealed_at.replace(tzinfo=timezone.utc)),
            "checks": checks, "signing_key_current": key_match,
            "status": ("valid" if ok and key_match else "valid_unverified_signature" if ok else "tampered")}


def verify_target_chain(db: Session, target_id: int) -> Dict:
    rows: List[ScanSeal] = (db.query(ScanSeal).filter(ScanSeal.target_id == target_id)
                            .order_by(ScanSeal.seq).all())
    results, prev = [], None
    for r in rows:
        results.append(_verify_one(db, r, prev))
        prev = r
    bad = [r for r in results if r["status"] == "tampered"]
    return {"target_id": target_id, "seals": len(rows), "intact": not bad, "broken_at_seq": bad[0]["seq"] if bad else None,
            "head_hash": rows[-1].seal_hash if rows else None, "results": results}


def verify_scan_seal(db: Session, scan_id: int) -> Optional[Dict]:
    row = db.query(ScanSeal).filter(ScanSeal.scan_id == scan_id).first()
    if row is None:
        return None
    prev = (db.query(ScanSeal).filter(ScanSeal.target_id == row.target_id, ScanSeal.seq == row.seq - 1).first()
            if row.seq > 1 else None)
    res = _verify_one(db, row, prev)
    # also catch seals deleted from the middle of the chain
    if row.seq > 1 and prev is None:
        res["checks"]["chain_link_ok"] = False
        res["status"] = "tampered"
    return res
