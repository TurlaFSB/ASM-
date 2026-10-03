from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend.db import Base, get_db
from backend.main import app
from backend.auth import get_current_user, require_admin
from backend.models import Target
import backend.models.schedule  # noqa: F401


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


def _client(role):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me", is_active=True)
    db.add(t); db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="u", role=role)
    return TestClient(app), t


@pytest.fixture(autouse=True)
def _clean():
    yield
    app.dependency_overrides.clear()


MUTATIONS = [
    ("post", "/targets/", {"domain": "10.0.0.9", "authorized": True, "authorized_by": "x"}),
    ("patch", "/targets/{t}/profile", {"default_profile": "quick"}),
    ("patch", "/targets/{t}/dirbuster-toggle", {"dirbuster_enabled": True}),
    ("put", "/targets/{t}/notifications", {}),
    ("post", "/targets/{t}/notifications/test", None),
    ("delete", "/targets/{t}", None),
    ("post", "/scans/", {"target_id": 1}),
    ("patch", "/scans/1/cancel", None),
    ("post", "/schedules/", {"target_id": 1, "preset": "daily"}),
    ("patch", "/schedules/1", {"cron_expression": "0 3 * * *"}),
    ("patch", "/schedules/1/toggle", None),
    ("delete", "/schedules/1", None),
    ("get", "/audit/", None),
]


@pytest.mark.parametrize("method,path,body", MUTATIONS)
def test_viewer_cannot_mutate(method, path, body):
    c, t = _client("viewer")
    r = getattr(c, method)(path.format(t=t.id), **({"json": body} if body is not None else {}))
    assert r.status_code == 403, (method, path, r.status_code)


def test_viewer_can_read():
    c, t = _client("viewer")
    assert c.get("/targets/").status_code == 200
    assert c.get("/scans/").status_code == 200
    assert c.get("/schedules/").status_code == 200


def test_admin_and_legacy_null_role_pass():
    c, t = _client("admin")
    assert c.post("/schedules/", json={"target_id": t.id, "preset": "daily"}).status_code == 200
    c, t = _client(None)  # rows created before roles existed
    assert c.post("/schedules/", json={"target_id": t.id, "preset": "daily"}).status_code == 200


def test_require_admin_function():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        require_admin(SimpleNamespace(role="viewer"))
    assert require_admin(SimpleNamespace(role="admin")).role == "admin"
