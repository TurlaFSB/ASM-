import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base, get_db
from backend.main import app
from backend.auth import get_current_user
from backend.models import Target
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.discovered_path import DiscoveredPath
from backend.path_flags import is_sensitive_path


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def client():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me"); db.add(t); db.commit()
    a = Asset(target_id=t.id, subdomain="10.0.0.5"); db.add(a)
    s1, s2, s3 = (Scan(target_id=t.id, status=st) for st in ("completed", "completed", "running"))
    db.add_all([s1, s2, s3]); db.commit()
    def p(scan, path, code): db.add(DiscoveredPath(asset_id=a.id, scan_id=scan.id, path=path, status_code=code, content_length=1))
    p(s1, "/old-only", 200)
    p(s2, "/images", 200); p(s2, "/backup.zip", 200); p(s2, "/admin", 404); p(s2, "/phpmyadmin/", 403)
    p(s3, "/running-scan", 200)
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_sensitive_rule():
    assert is_sensitive_path("/backup.zip", 200) and is_sensitive_path("/phpmyadmin/", 403)
    assert not is_sensitive_path("/admin", 404) and not is_sensitive_path("/images", 200)
    assert not is_sensitive_path("/admin", 301)


def test_defaults_to_latest_completed_scan_sensitive_first(client):
    r = client.get("/assets/1/paths").json()
    assert r["scan_id"] == 2                       # not the running scan 3, not the older scan 1
    assert [p["path"] for p in r["paths"]] == ["/backup.zip", "/phpmyadmin/", "/admin", "/images"]
    assert [p["sensitive"] for p in r["paths"]] == [True, True, False, False]


def test_explicit_scan_and_missing(client):
    assert [p["path"] for p in client.get("/assets/1/paths?scan_id=1").json()["paths"]] == ["/old-only"]
    assert client.get("/assets/99/paths").status_code == 404


def test_list_assets_still_works(client):
    assert len(client.get("/assets/").json()) == 1
