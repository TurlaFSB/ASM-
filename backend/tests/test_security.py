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
    assert list(r.ttl.values()) == [900]
    clear_failures(r, "1.2.3.4", "admin")
    assert not is_locked(r, "1.2.3.4", "admin")


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
