from fastapi.testclient import TestClient

from backend import ratelimit
from backend.config import settings
from backend.main import app


def test_blocks_after_limit_then_reopens(monkeypatch):
    monkeypatch.setattr(settings, "api_rate_limit_per_minute", 3)
    results = [ratelimit.check("1.2.3.4", now=1000.0) for _ in range(5)]
    assert results[:3] == [0, 0, 0]
    assert results[3] > 0 and results[4] > 0
    assert ratelimit.check("1.2.3.4", now=1000.0 + 61) == 0       # next window
    assert ratelimit.check("5.6.7.8", now=1000.0) == 0            # other client unaffected


def test_zero_disables(monkeypatch):
    monkeypatch.setattr(settings, "api_rate_limit_per_minute", 0)
    assert all(ratelimit.check("x") == 0 for _ in range(50))


def test_fails_open_when_redis_down(monkeypatch):
    monkeypatch.setattr(settings, "api_rate_limit_per_minute", 1)
    def boom(): raise RuntimeError("down")
    monkeypatch.setattr(ratelimit.sessions, "redis_client", boom)
    assert ratelimit.check("x") == 0


def test_http_429_with_retry_after_and_exempt_health(monkeypatch):
    monkeypatch.setattr(settings, "api_rate_limit_per_minute", 2)
    c = TestClient(app)
    codes = [c.get("/targets/").status_code for _ in range(4)]
    assert codes[-1] == 429
    r = c.get("/targets/")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert c.get("/health").status_code == 200
