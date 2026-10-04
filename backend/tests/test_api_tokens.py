from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import api_tokens
from backend.main import app
from backend.models.api_token import ApiToken
from backend.models.user import User
from backend.tests.test_accounts import PW, bearer, env  # noqa: F401  (fixtures and helpers)


def make(c, h, **body):
    body.setdefault("name", "ci")
    return c.post("/auth/tokens/", json=body, headers=h)


def tok(secret):
    return {"Authorization": f"Bearer {secret}"}


def test_create_returns_secret_once_and_stores_only_a_hash(env):
    db, c = env
    h = bearer(c)
    r = make(c, h, scope="write", expires_in_days=30)
    assert r.status_code == 201
    secret = r.json()["token"]
    assert secret.startswith("asm_") and len(secret) > 40
    row = db.query(ApiToken).one()
    assert row.token_hash != secret and secret not in (row.token_hash, row.prefix) and row.prefix == secret[:12]
    listed = c.get("/auth/tokens/", headers=h).json()
    assert listed[0]["prefix"] == secret[:12] and "token" not in listed[0]


def test_read_token_reads_but_cannot_write(env):
    _, c = env
    secret = make(c, bearer(c), scope="read").json()["token"]
    assert c.get("/targets/", headers=tok(secret)).status_code == 200
    r = c.post("/targets/", json={"domain": "example.com"}, headers=tok(secret))
    assert r.status_code == 403 and "read-only" in r.json()["detail"]


def test_write_token_has_the_owners_rights(env):
    _, c = env
    secret = make(c, bearer(c), scope="write").json()["token"]
    r = c.post("/targets/", json={"domain": "example.com", "authorized": True, "authorized_by": "me"}, headers=tok(secret))
    assert r.status_code in (200, 201)


def test_viewers_cannot_make_write_tokens_and_tokens_cannot_make_tokens(env):
    _, c = env
    assert make(c, bearer(c, "view1"), scope="write").status_code == 403
    secret = make(c, bearer(c), scope="write").json()["token"]
    assert make(c, tok(secret)).status_code == 403
    # a viewer's read token still works
    assert c.get("/targets/", headers=tok(make(c, bearer(c, "view1")).json()["token"])).status_code == 200


def test_validation(env):
    _, c = env
    h = bearer(c)
    assert make(c, h, name="  ").status_code == 422
    assert make(c, h, scope="root").status_code == 422
    assert make(c, h, expires_in_days=0).status_code == 422
    assert make(c, h, expires_in_days=9999).status_code == 422
    assert make(c, h, expires_in_days=None).status_code == 201          # never expires is allowed


def test_revoke_and_isolation_between_users(env):
    db, c = env
    h1, h2 = bearer(c), bearer(c, "admin2")
    r = make(c, h1).json()
    assert c.delete(f"/auth/tokens/{r['id']}", headers=h2).status_code == 404       # not yours
    assert c.get("/auth/tokens/", headers=h2).json() == []
    assert c.delete(f"/auth/tokens/{r['id']}", headers=h1).status_code == 200
    assert c.get("/targets/", headers=tok(r["token"])).status_code == 401


def test_expired_unknown_and_inactive_owner_are_rejected(env):
    db, c = env
    r = make(c, bearer(c)).json()
    row = db.get(ApiToken, r["id"])
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1); db.commit()
    assert c.get("/targets/", headers=tok(r["token"])).status_code == 401
    assert c.get("/targets/", headers=tok("asm_notarealtoken")).status_code == 401
    r2 = make(c, bearer(c)).json()
    db.query(User).filter(User.username == "admin1").update({"is_active": False}); db.commit()
    assert c.get("/targets/", headers=tok(r2["token"])).status_code == 401


def test_password_change_and_admin_reset_revoke_tokens(env):
    db, c = env
    h = bearer(c)
    secret = make(c, h).json()["token"]
    r = c.post("/auth/change-password", json={"current_password": PW, "new_password": "another long password 9"}, headers=h)
    assert r.status_code == 200
    assert c.get("/targets/", headers=tok(secret)).status_code == 401
    admin = bearer(c, "admin2")
    victim = make(c, bearer(c, "view1")).json()["token"]
    vid = db.query(User).filter(User.username == "view1").one().id
    assert c.post(f"/users/{vid}/reset-password", json={"new_password": "yet another long one 5"}, headers=admin).status_code == 200
    assert c.get("/targets/", headers=tok(victim)).status_code == 401


def test_limit_per_user(env, monkeypatch):
    _, c = env
    monkeypatch.setattr(api_tokens, "MAX_PER_USER", 2)
    h = bearer(c)
    assert make(c, h).status_code == 201 and make(c, h).status_code == 201
    assert make(c, h).status_code == 409


def test_last_used_is_updated_but_not_on_every_call(env):
    db, c = env
    r = make(c, bearer(c)).json()
    c.get("/targets/", headers=tok(r["token"]))
    first = db.get(ApiToken, r["id"]).last_used_at
    assert first is not None
    c.get("/targets/", headers=tok(r["token"]))
    assert db.get(ApiToken, r["id"]).last_used_at == first
