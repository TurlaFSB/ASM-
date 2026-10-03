import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import integrity
from backend.db import Base
from backend.diffing.snapshot import build_snapshot, snapshot_hash
from backend.models.scan import Scan
from backend.models.scan_seal import ScanSeal
from backend.models.scan_snapshot import ScanSnapshot
from backend.models.target import Target


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="example.org", is_active=True)
    s.add(t)
    s.commit()
    s.tid = t.id
    yield s
    s.close()


def make_scan(db, n_assets=1):
    sc = Scan(target_id=db.tid, status="completed", profile="standard")
    db.add(sc)
    db.commit()
    assets = [{"subdomain": f"h{i}.example.org", "ip": "1.1.1.1", "open_ports": [{"port": 80}],
               "technologies": [], "http_status": 200, "http_title": "t"} for i in range(n_assets)]
    snap = build_snapshot("standard", {"dns": "ok", "subfinder": "ok"}, assets, [], [])
    db.add(ScanSnapshot(scan_id=sc.id, target_id=db.tid, profile="standard", schema_version=2,
                        content_hash=snapshot_hash(snap), data=snap))
    db.commit()
    return sc


def test_seals_chain_and_verify(db):
    a, b, c = (make_scan(db, n) for n in (1, 2, 3))
    sa, sb, sc = (integrity.seal_scan(db, s) for s in (a, b, c))
    assert (sa.seq, sb.seq, sc.seq) == (1, 2, 3)
    assert sa.prev_seal_hash is None and sb.prev_seal_hash == sa.seal_hash and sc.prev_seal_hash == sb.seal_hash
    chain = integrity.verify_target_chain(db, db.tid)
    assert chain["intact"] and chain["seals"] == 3 and chain["head_hash"] == sc.seal_hash
    assert all(r["status"] == "valid" for r in chain["results"])
    assert integrity.verify_scan_seal(db, b.id)["status"] == "valid"


def test_sealing_is_idempotent_and_needs_a_snapshot(db):
    sc = make_scan(db)
    assert integrity.seal_scan(db, sc).id == integrity.seal_scan(db, sc).id
    bare = Scan(target_id=db.tid, status="completed", profile="standard")
    db.add(bare)
    db.commit()
    assert integrity.seal_scan(db, bare) is None
    assert integrity.verify_scan_seal(db, bare.id) is None


def test_editing_a_snapshot_is_detected(db):
    a, b = make_scan(db), make_scan(db, 2)
    integrity.seal_scan(db, a)
    integrity.seal_scan(db, b)
    snap = db.query(ScanSnapshot).filter_by(scan_id=a.id).one()
    data = dict(snap.data)
    data["assets"] = {}                      # quietly make an exposed host vanish from history
    snap.data = data
    db.commit()
    res = integrity.verify_target_chain(db, db.tid)
    assert not res["intact"] and res["broken_at_seq"] == 1
    assert res["results"][0]["checks"]["snapshot_intact"] is False


def test_editing_a_seal_or_signature_is_detected(db):
    a = make_scan(db)
    row = integrity.seal_scan(db, a)
    row.snapshot_hash = "0" * 64
    db.commit()
    assert integrity.verify_scan_seal(db, a.id)["status"] == "tampered"


def test_forged_signature_is_detected(db):
    a = make_scan(db)
    row = integrity.seal_scan(db, a)
    row.signature = "00" * 64
    db.commit()
    res = integrity.verify_scan_seal(db, a.id)
    assert res["status"] == "tampered" and res["checks"]["signature_ok"] is False


def test_deleting_a_middle_seal_breaks_the_chain(db):
    scans = [make_scan(db, n + 1) for n in range(3)]
    for s in scans:
        integrity.seal_scan(db, s)
    db.query(ScanSeal).filter_by(scan_id=scans[1].id).delete()
    db.commit()
    assert integrity.verify_scan_seal(db, scans[2].id)["status"] == "tampered"
    assert not integrity.verify_target_chain(db, db.tid)["intact"]


def test_rotated_secret_key_is_reported_not_called_tampering(db, monkeypatch):
    a = make_scan(db)
    integrity.seal_scan(db, a)
    monkeypatch.setattr(integrity.settings, "secret_key", "z" * 40)
    res = integrity.verify_scan_seal(db, a.id)
    assert res["status"] == "valid_unverified_signature" and res["signing_key_current"] is False


def test_public_key_is_stable():
    info = integrity.public_key_info()
    assert info == integrity.public_key_info() and len(info["public_key"]) == 64 and len(info["key_id"]) == 16


def test_api_endpoints(db):
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from backend.auth import get_current_user
    from backend.db import get_db
    from backend.main import app

    sc = make_scan(db)
    integrity.seal_scan(db, sc)
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="x", role="viewer")
    try:
        c = TestClient(app)
        assert c.get("/integrity/public-key").json()["algorithm"] == "Ed25519"
        assert c.get(f"/integrity/scans/{sc.id}").json()["status"] == "valid"
        assert c.get("/integrity/scans/9999").status_code == 404
        assert c.get(f"/integrity/targets/{db.tid}").json()["intact"] is True
        assert c.get("/integrity/targets/9999").status_code == 404
    finally:
        app.dependency_overrides.clear()
