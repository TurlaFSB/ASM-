"""Two-step sign-in: RFC 6238 vectors, enrolment, the two-step login, replay, recovery codes, lockout and admin reset."""
import base64
import time

import pytest
from fastapi.testclient import TestClient

from backend import mfa
from backend.auth import create_access_token
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.security import MAX_FAILURES
from backend.tests.test_auth_api import FakeRedis, _j, env, login  # noqa: F401  (env fixture + sqlite JSONB shim)

PW = "correct horse battery"


def now_code(secret, offset=0):
    return mfa._code_at(secret, int(time.time() // 30) + offset)


def test_totp_matches_rfc6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa._code_at(secret, 59 // 30) == "287082"              # RFC 6238 appendix B, SHA-1, T=59 -> 94287082
    assert mfa._code_at(secret, 1111111109 // 30) == "081804"
    assert mfa._code_at(secret, 20000000000 // 30) == "353130"


def test_verify_window_and_replay():
    s = mfa.new_secret()
    t = 1_700_000_000
    step = t // 30
    assert mfa.verify_code(s, mfa._code_at(s, step), now=t) == step
    assert mfa.verify_code(s, mfa._code_at(s, step - 1), now=t) == step - 1      # one step of clock drift
    assert mfa.verify_code(s, mfa._code_at(s, step + 3), now=t) is None          # too far off
    assert mfa.verify_code(s, mfa._code_at(s, step), last_step=step, now=t) is None   # replay refused
    assert mfa.verify_code(s, "12345", now=t) is None and mfa.verify_code(s, "abcdef", now=t) is None


def test_secret_is_encrypted_at_rest():
    s = mfa.new_secret()
    stored = mfa.encrypt_secret(s)
    assert s not in stored and mfa.decrypt_secret(stored) == s
    assert mfa.decrypt_secret("garbage") is None


def enrol(c, headers):
    r = c.post("/auth/mfa/setup", json={"password": PW}, headers=headers)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/") and secret in r.json()["otpauth_uri"]
    r = c.post("/auth/mfa/enable", json={"code": now_code(secret)}, headers=headers)
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


def bearer(c, user="admin1", pw=PW):
    return {"Authorization": f"Bearer {login(c, user, pw).json()['access_token']}"}


def test_setup_needs_the_password_and_enable_needs_a_correct_code(env):
    _, _, c = env
    h = bearer(c)
    assert c.post("/auth/mfa/setup", json={"password": "wrong"}, headers=h).status_code == 400
    assert c.post("/auth/mfa/enable", json={"code": "123456"}, headers=h).status_code == 409     # no setup yet
    secret = c.post("/auth/mfa/setup", json={"password": PW}, headers=h).json()["secret"]
    assert c.post("/auth/mfa/enable", json={"code": "000000"}, headers=h).status_code == 400
    assert not env[0].query(User).filter_by(username="admin1").one().mfa_enabled
    assert c.post("/auth/mfa/enable", json={"code": now_code(secret)}, headers=h).status_code == 200


def test_login_becomes_two_step_and_challenge_is_not_a_session(env):
    db, _, c = env
    secret, _ = enrol(c, bearer(c))
    r = login(c, "admin1", PW)
    body = r.json()
    assert r.status_code == 200 and body["mfa_required"] is True and "access_token" not in body
    assert "asm_session" not in r.cookies
    # the challenge must not work as a session anywhere
    assert c.get("/auth/me", headers={"Authorization": f"Bearer {body['mfa_token']}"}).status_code == 401
    # next step of the same authenticator window was used by enable(), so use the next step
    ok = c.post("/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": now_code(secret, 1)})
    assert ok.status_code == 200 and ok.json()["token_type"] == "bearer"
    assert c.get("/auth/me", headers={"Authorization": f"Bearer {ok.json()['access_token']}"}).json()["mfa_enabled"] is True


def test_a_code_cannot_be_used_twice(env):
    _, _, c = env
    secret, _ = enrol(c, bearer(c))
    code = now_code(secret, 1)
    t1 = login(c, "admin1", PW).json()["mfa_token"]
    assert c.post("/auth/mfa/verify", json={"mfa_token": t1, "code": code}).status_code == 200
    t2 = login(c, "admin1", PW).json()["mfa_token"]
    assert c.post("/auth/mfa/verify", json={"mfa_token": t2, "code": code}).status_code == 401


def test_wrong_codes_are_throttled_and_audited(env):
    db, _, c = env
    enrol(c, bearer(c))
    token = login(c, "admin1", PW).json()["mfa_token"]
    for _ in range(MAX_FAILURES):
        assert c.post("/auth/mfa/verify", json={"mfa_token": token, "code": "000000"}).status_code == 401
    assert c.post("/auth/mfa/verify", json={"mfa_token": token, "code": "000000"}).status_code == 429
    assert db.query(AuditLog).filter_by(action="mfa_failed").count() == MAX_FAILURES


def test_recovery_code_signs_in_once_and_burns(env):
    _, _, c = env
    _, codes = enrol(c, bearer(c))
    assert len(codes) == 10
    t = login(c, "admin1", PW).json()["mfa_token"]
    ok = c.post("/auth/mfa/verify", json={"mfa_token": t, "code": codes[0]})
    assert ok.status_code == 200 and ok.json()["recovery_codes_left"] == 9
    t = login(c, "admin1", PW).json()["mfa_token"]
    assert c.post("/auth/mfa/verify", json={"mfa_token": t, "code": codes[0]}).status_code == 401


def test_bad_or_foreign_challenges_are_refused(env):
    _, _, c = env
    enrol(c, bearer(c))
    assert c.post("/auth/mfa/verify", json={"mfa_token": "nonsense", "code": "123456"}).status_code == 401
    session_token = create_access_token({"sub": "admin1", "ver": 0})              # a normal session token is no challenge
    assert c.post("/auth/mfa/verify", json={"mfa_token": session_token, "code": "123456"}).status_code == 401


def test_disable_needs_password_and_code_and_regenerating_replaces_codes(env):
    db, _, c = env
    h = bearer(c)
    secret, codes = enrol(c, h)
    h = {"Authorization": f"Bearer {c.post('/auth/mfa/verify', json={'mfa_token': login(c, 'admin1', PW).json()['mfa_token'], 'code': now_code(secret, 1)}).json()['access_token']}"}
    assert c.post("/auth/mfa/disable", json={"password": PW, "code": "000000"}, headers=h).status_code == 400
    new = c.post("/auth/mfa/recovery-codes", json={"password": PW, "code": codes[1]}, headers=h)
    assert new.status_code == 200 and set(new.json()["recovery_codes"]).isdisjoint(codes)
    r = c.post("/auth/mfa/disable", json={"password": PW, "code": new.json()["recovery_codes"][0]}, headers=h)
    assert r.status_code == 200
    u = db.query(User).filter_by(username="admin1").one()
    assert not u.mfa_enabled and u.mfa_secret is None and u.mfa_recovery is None
    assert "access_token" in login(c, "admin1", PW).json()                      # back to one-step


def test_admin_can_reset_someone_elses_mfa_but_not_their_own(env):
    db, _, c = env
    # make view1 an MFA user
    h = bearer(c, "view1", "another long password")
    c.post("/auth/mfa/setup", json={"password": "another long password"}, headers=h)
    s = mfa.decrypt_secret(db.query(User).filter_by(username="view1").one().mfa_secret)
    c.post("/auth/mfa/enable", json={"code": now_code(s)}, headers=h)
    admin = bearer(c)
    uid = db.query(User).filter_by(username="view1").one().id
    me = db.query(User).filter_by(username="admin1").one().id
    assert c.post(f"/users/{me}/reset-mfa", headers=admin).status_code == 409
    assert c.post(f"/users/{uid}/reset-mfa", headers=admin).status_code == 200
    db.expire_all()
    assert not db.query(User).filter_by(username="view1").one().mfa_enabled
    assert "access_token" in login(c, "view1", "another long password").json()
    assert c.get("/auth/me", headers=h).status_code == 401                        # old session ended
