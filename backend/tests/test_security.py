import pytest
from backend.security import is_locked, record_failure, clear_failures
from backend.validators import validate_webhook_url


class FakeRedis:
    def __init__(self): self.d, self.ttl = {}, {}
    def get(self, k): return self.d.get(k)
    def incr(self, k): self.d[k] = int(self.d.get(k, 0)) + 1; return self.d[k]
    def expire(self, k, s): self.ttl[k] = s
    def delete(self, k): self.d.pop(k, None)


class DeadRedis:
    def get(self, k): raise ConnectionError("down")
    incr = expire = delete = get


def test_lockout_after_five_failures_then_clear():
    r = FakeRedis()
    for _ in range(4):
        record_failure(r, "1.2.3.4", "Admin")
    assert not is_locked(r, "1.2.3.4", "admin")
    record_failure(r, "1.2.3.4", "admin")
    assert is_locked(r, "1.2.3.4", "ADMIN")           # case-insensitive username
    assert not is_locked(r, "9.9.9.9", "admin")        # other IP unaffected
    assert set(r.ttl.values()) == {900}
    clear_failures(r, "1.2.3.4", "admin")
    assert not is_locked(r, "1.2.3.4", "admin")


def test_ip_wide_limit_locks_username_spraying():
    from backend.security import MAX_FAILURES_PER_IP
    r = FakeRedis()
    for i in range(MAX_FAILURES_PER_IP):
        record_failure(r, "5.5.5.5", f"user{i}")  # each pair stays under its own limit
    assert is_locked(r, "5.5.5.5", "brand-new-user")
    assert not is_locked(r, "6.6.6.6", "brand-new-user")


def test_username_wide_limit_locks_distributed_attack():
    from backend.security import MAX_FAILURES_PER_USER
    r = FakeRedis()
    for i in range(MAX_FAILURES_PER_USER):
        record_failure(r, f"10.0.0.{i}", "Admin")
    assert is_locked(r, "172.16.0.1", "admin")      # a fresh IP is still blocked for this user
    assert not is_locked(r, "172.16.0.1", "someone-else")


def test_success_does_not_reset_ip_or_user_counters():
    from backend.security import MAX_FAILURES_PER_USER
    r = FakeRedis()
    for i in range(MAX_FAILURES_PER_USER):
        record_failure(r, f"10.0.1.{i}", "admin")
    clear_failures(r, "10.0.1.0", "admin")
    assert is_locked(r, "10.0.1.0", "admin")


def test_unknown_user_still_runs_a_bcrypt_verify(monkeypatch):
    from backend import auth

    calls = []
    real = auth.pwd_context.verify
    monkeypatch.setattr(auth.pwd_context, "verify", lambda p, h: calls.append(h) or real(p, h))

    class Q:
        def filter(self, *a): return self
        def first(self): return None

    class DB:
        def query(self, *a): return Q()

    assert auth.authenticate_user(DB(), "ghost", "pw") is None
    assert calls == [auth._DUMMY_HASH]


def test_throttle_fails_open_when_redis_down():
    assert is_locked(DeadRedis(), "1.1.1.1", "x") is False
    assert record_failure(DeadRedis(), "1.1.1.1", "x") is None


@pytest.mark.parametrize("url", [
    "http://example.com/hook", "ftp://x.com", "", "https://", "https://127.0.0.1/x",
    "https://169.254.169.254/latest/meta-data", "https://10.0.0.5/x", "https://[::1]/x",
])
def test_webhook_blocked(url):
    with pytest.raises(ValueError):
        validate_webhook_url(url)


def test_webhook_public_ip_allowed():
    assert validate_webhook_url("https://8.8.8.8/hook") == "https://8.8.8.8/hook"


def test_app_headers_and_auth_required():
    from fastapi.testclient import TestClient
    from backend.main import app
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert c.get("/targets/").status_code == 401
    assert c.get("/audit/").status_code == 401
