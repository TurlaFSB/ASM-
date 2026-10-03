import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import auth as auth_api
from backend.auth import pwd_context
from backend.db import Base, get_db
from backend.main import app
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.security import MAX_FAILURES


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


class FakeRedis:
    def __init__(self): self.d = {}
    def get(self, k): return self.d.get(k)
    def incr(self, k): self.d[k] = int(self.d.get(k, 0)) + 1; return self.d[k]
    def expire(self, k, s): pass
    def delete(self, k): self.d.pop(k, None)


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    db.add_all([
        User(username="admin1", hashed_password=pwd_context.hash("correct horse battery"), role="admin", is_active=True),
        User(username="view1", hashed_password=pwd_context.hash("another long password"), role="viewer", is_active=True),
        User(username="gone", hashed_password=pwd_context.hash("whatever long pw 1"), role="admin", is_active=False),
    ])
    db.commit()
    r = FakeRedis()
    monkeypatch.setattr(auth_api, "_redis_client", lambda: r)
    app.dependency_overrides[get_db] = lambda: (yield db)
    yield db, r, TestClient(app)
    app.dependency_overrides.clear()


def login(c, u, p):
    return c.post("/auth/token", data={"username": u, "password": p})


def test_login_success_returns_token_and_me_shows_role(env):
    db, _, c = env
    r = login(c, "view1", "another long password")
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"
    me = c.get("/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.json() == {"username": "view1", "role": "viewer"}
    assert db.query(AuditLog).filter_by(action="login_success").count() == 1


def test_wrong_password_unknown_and_inactive_users_look_identical(env):
    db, _, c = env
    responses = [login(c, "admin1", "nope"), login(c, "ghost", "nope"), login(c, "gone", "whatever long pw 1")]
    assert {r.status_code for r in responses} == {401}
    assert len({r.text for r in responses}) == 1               # same body: no username enumeration
    assert db.query(AuditLog).filter_by(action="login_failed").count() == 3


def test_lockout_after_repeated_failures_blocks_even_the_right_password(env):
    db, _, c = env
    for _ in range(MAX_FAILURES):
        assert login(c, "admin1", "bad").status_code == 401
    r = login(c, "admin1", "correct horse battery")
    assert r.status_code == 429 and r.headers["retry-after"] == "900"
    assert db.query(AuditLog).filter_by(action="login_locked").count() == 1


def test_success_clears_only_the_pair_counter(env):
    _, redis, c = env
    for _ in range(MAX_FAILURES - 1):
        login(c, "admin1", "bad")
    assert login(c, "admin1", "correct horse battery").status_code == 200
    assert not any(k.startswith("login_fail:") for k in redis.d)          # pair counter reset
    assert redis.d["login_fail_ip:testclient"] == MAX_FAILURES - 1         # IP-wide counter is not


def test_protected_routes_need_a_valid_token(env):
    _, _, c = env
    assert c.get("/targets/").status_code == 401
    assert c.get("/targets/", headers={"Authorization": "Bearer junk"}).status_code == 401
