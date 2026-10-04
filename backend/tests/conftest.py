import os

# Settings are read at import time; provide safe throwaway values for tests.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost:5432/asm_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-0123456789abcdef0123456789")


import pytest


class _FakeRedis:
    def __init__(self): self.d = {}
    def get(self, k): return self.d.get(k)
    def setex(self, k, ttl, v): self.d[k] = v
    def incr(self, k): self.d[k] = int(self.d.get(k, 0)) + 1; return self.d[k]
    def expire(self, k, s): pass
    def delete(self, k): self.d.pop(k, None)
    def exists(self, k): return 1 if k in self.d else 0


@pytest.fixture(autouse=True)
def _no_real_redis_for_sessions(monkeypatch):
    """Sign-out tracking talks to Redis; tests get an in-memory stand-in so none of them needs a server."""
    fake = _FakeRedis()
    from backend import sessions
    monkeypatch.setattr(sessions, "redis_client", lambda: fake)
    yield fake
