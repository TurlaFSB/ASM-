import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import sessions
from backend.api import auth as auth_api
from backend.auth import pwd_context
from backend.db import Base, get_db
from backend.main import app
from backend.models.user import User
from backend.tests.test_auth_api import FakeRedis, login  # noqa: F401  (reuse the JSONB shim and helpers)

PW = "correct horse battery"
NEW_PW = "another long password 9"


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    db.add_all([
        User(username="admin1", hashed_password=pwd_context.hash(PW), role="admin", is_active=True),
        User(username="admin2", hashed_password=pwd_context.hash(PW), role="admin", is_active=True),
        User(username="view1", hashed_password=pwd_context.hash(PW), role="viewer", is_active=True),
    ])
    db.commit()
    shared = FakeRedis()
    monkeypatch.setattr(auth_api, "_redis_client", lambda: shared)
    app.dependency_overrides[get_db] = lambda: (yield db)
    yield db, TestClient(app)
    app.dependency_overrides.clear()


def bearer(c, user="admin1", pw=PW):
    r = login(c, user, pw)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_logout_really_ends_a_bearer_token(env):
    _, c = env
    h = bearer(c)
    assert c.get("/auth/me", headers=h).status_code == 200
    assert c.post("/auth/logout", headers=h).status_code == 200
    assert c.get("/auth/me", headers=h).status_code == 401          # the copied token no longer works


def test_logout_ends_a_cookie_session_too(env):
    _, c = env
    login(c, "admin1", PW)
    stolen = c.cookies.get("asm_session")
    c.post("/auth/logout", headers={"X-CSRF-Token": c.cookies.get("asm_csrf") or ""})
    other = TestClient(app)
    assert other.get("/auth/me", headers={"Authorization": f"Bearer {stolen}"}).status_code == 401


def test_change_password_rules_and_signs_out_other_sessions(env):
    db, c = env
    old = bearer(c)
    h = {**old}
    bad = c.post("/auth/change-password", json={"current_password": "wrong", "new_password": NEW_PW}, headers=h)
    assert bad.status_code == 400
    weak = c.post("/auth/change-password", json={"current_password": PW, "new_password": "short"}, headers=h)
    assert weak.status_code == 422
    same = c.post("/auth/change-password", json={"current_password": PW, "new_password": PW}, headers=h)
    assert same.status_code == 422
    ok = c.post("/auth/change-password", json={"current_password": PW, "new_password": NEW_PW}, headers=h)
    assert ok.status_code == 200
    assert c.get("/auth/me", headers=old).status_code == 401           # old token is dead
    assert c.get("/auth/me").status_code == 200                        # this browser session stays signed in
    assert login(c, "admin1", PW).status_code == 401
    assert login(c, "admin1", NEW_PW).status_code == 200


def test_first_run_setup_needs_the_code_and_works_once(env):
    db, c = env
    db.query(User).delete(); db.commit()
    assert c.get("/auth/setup-status").json() == {"needs_setup": True}
    body = {"username": "owner", "password": PW}
    assert c.post("/auth/setup", json={**body, "setup_code": "0000-0000-0000"}).status_code == 403
    assert c.post("/auth/setup", json={"setup_code": sessions.setup_code(), "username": "x", "password": PW}).status_code == 422
    r = c.post("/auth/setup", json={**body, "setup_code": sessions.setup_code()})
    assert r.status_code == 201 and r.json()["role"] == "admin"
    assert c.get("/auth/me").status_code == 200                         # signed in straight away
    assert c.get("/auth/setup-status").json() == {"needs_setup": False}
    assert c.post("/auth/setup", json={**body, "username": "second", "setup_code": sessions.setup_code()}).status_code == 409


def test_setup_is_throttled(env):
    db, c = env
    db.query(User).delete(); db.commit()
    codes = [c.post("/auth/setup", json={"setup_code": "bad", "username": "owner", "password": PW}).status_code for _ in range(7)]
    assert 429 in codes


def test_only_admins_manage_users(env):
    _, c = env
    assert c.get("/users/", headers=bearer(c, "view1")).status_code == 403
    r = c.get("/users/", headers=bearer(c))
    assert r.status_code == 200 and {u["username"] for u in r.json()} == {"admin1", "admin2", "view1"}
    assert "hashed_password" not in r.text


def test_create_user_validates_and_rejects_duplicates(env):
    _, c = env
    h = bearer(c)
    assert c.post("/users/", json={"username": "ab", "password": PW}, headers=h).status_code == 422
    assert c.post("/users/", json={"username": "newbie", "password": "short"}, headers=h).status_code == 422
    assert c.post("/users/", json={"username": "newbie", "password": PW, "role": "root"}, headers=h).status_code == 422
    ok = c.post("/users/", json={"username": "newbie", "password": PW}, headers=h)
    assert ok.status_code == 201 and ok.json()["role"] == "viewer"
    assert c.post("/users/", json={"username": "NEWBIE", "password": PW}, headers=h).status_code == 409
    assert login(c, "newbie", PW).status_code == 200


def test_deactivate_signs_the_person_out_and_protects_the_last_admin(env):
    db, c = env
    h = bearer(c)
    viewer_token = bearer(c, "view1")
    vid = db.query(User).filter_by(username="view1").one().id
    assert c.patch(f"/users/{vid}", json={"is_active": False}, headers=h).status_code == 200
    assert c.get("/auth/me", headers=viewer_token).status_code == 401
    assert login(c, "view1", PW).status_code == 401
    me = db.query(User).filter_by(username="admin1").one().id
    assert c.patch(f"/users/{me}", json={"is_active": False}, headers=h).status_code == 409      # not yourself
    assert c.patch(f"/users/{me}", json={"role": "viewer"}, headers=h).status_code == 409
    other = db.query(User).filter_by(username="admin2").one().id
    assert c.patch(f"/users/{other}", json={"is_active": False}, headers=h).status_code == 200   # a second admin may go
    assert c.patch(f"/users/{other}", json={"role": "viewer"}, headers=h).status_code == 200


def test_reset_password_signs_the_person_out(env):
    db, c = env
    h = bearer(c)
    vtoken = bearer(c, "view1")
    vid = db.query(User).filter_by(username="view1").one().id
    assert c.post(f"/users/{vid}/reset-password", json={"new_password": "short"}, headers=h).status_code == 422
    assert c.post(f"/users/{vid}/reset-password", json={"new_password": NEW_PW}, headers=h).status_code == 200
    assert c.get("/auth/me", headers=vtoken).status_code == 401
    assert login(c, "view1", NEW_PW).status_code == 200
    me = db.query(User).filter_by(username="admin1").one().id
    assert c.post(f"/users/{me}/reset-password", json={"new_password": NEW_PW}, headers=h).status_code == 409
