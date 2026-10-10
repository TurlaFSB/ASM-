"""REDIS_PASSWORD is folded into REDIS_URL, and the production overlay refuses to run Redis without one."""
import subprocess
import shutil
import socket
import time
from pathlib import Path
from urllib.parse import quote

import pytest

from backend.config import Settings
from backend.tests.test_compose_beat import _load

KEY = "k" * 40


def _settings(**kw):
    return Settings(database_url="postgresql+psycopg://u:p@h/d", secret_key=KEY, _env_file=None, **kw)


def test_password_is_added_to_a_plain_url():
    assert _settings(redis_url="redis://redis:6379/0", redis_password="abc123").redis_url == "redis://:abc123@redis:6379/0"


def test_special_characters_are_percent_encoded():
    pw = "p@ss/w:rd"
    assert _settings(redis_url="redis://redis:6379/0", redis_password=pw).redis_url == f"redis://:{quote(pw, safe='')}@redis:6379/0"


def test_url_that_already_has_credentials_is_left_alone():
    url = "redis://:already@redis:6379/0"
    assert _settings(redis_url=url, redis_password="other").redis_url == url


def test_no_password_leaves_url_unchanged():
    assert _settings(redis_url="redis://redis:6379/0").redis_url == "redis://redis:6379/0"


def test_prod_overlay_requires_and_applies_the_password():
    redis = _load("docker-compose.prod.yml")["services"]["redis"]
    script = " ".join(redis["command"])
    assert "--requirepass" in script and "REDIS_PASSWORD" in script and "exit 1" in script
    assert ".env.docker" in redis["env_file"]
    assert "PONG" in redis["healthcheck"]["test"][1]


@pytest.mark.skipif(not shutil.which("redis-server"), reason="redis-server not installed")
def test_real_redis_rejects_unauthenticated_clients(tmp_path):
    import redis
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    proc = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--requirepass", "s3cret", "--dir", str(tmp_path)],
                            stdout=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                redis.Redis(port=port, password="s3cret").ping(); break
            except Exception:
                time.sleep(0.1)
        with pytest.raises(redis.exceptions.AuthenticationError):
            redis.Redis(port=port).ping()
        assert redis.Redis.from_url(f"redis://:s3cret@127.0.0.1:{port}/0").ping()
    finally:
        proc.terminate(); proc.wait(5)
