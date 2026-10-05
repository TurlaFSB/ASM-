"""The Redis service must keep the task queue and scan locks across a restart or crash.

Starts a real redis-server with the exact flags from docker-compose.yml, writes the keys the app depends on, kills
or restarts it, and checks they come back. Skipped when redis-server is not installed.
"""
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import redis
import yaml

COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
pytestmark = pytest.mark.skipif(shutil.which("redis-server") is None, reason="redis-server not installed")


def _flags():
    svc = yaml.safe_load(COMPOSE.read_text())["services"]["redis"]
    cmd = svc["command"]
    assert cmd[0] == "redis-server"
    return cmd[1:]


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp_path):
        self.dir, self.port, self.proc = tmp_path, _free_port(), None

    def start(self):
        self.proc = subprocess.Popen(["redis-server", "--port", str(self.port), "--bind", "127.0.0.1", "--dir",
                                      str(self.dir), "--save", "", *_flags()],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                return self.client()
            except redis.ConnectionError:
                time.sleep(0.1)
        raise RuntimeError("redis did not start")

    def client(self):
        c = redis.Redis(port=self.port, decode_responses=True)
        c.ping()
        return c

    def crash(self):
        self.proc.kill()                     # SIGKILL: no shutdown save
        self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)


@pytest.fixture()
def server(tmp_path):
    s = Server(tmp_path)
    yield s
    s.stop()


def test_compose_enables_persistence_and_noeviction():
    flags = _flags()
    assert flags[flags.index("--appendonly") + 1] == "yes"
    assert flags[flags.index("--maxmemory-policy") + 1] == "noeviction"
    compose = yaml.safe_load(COMPOSE.read_text())
    assert any(v.endswith(":/data") for v in compose["services"]["redis"]["volumes"])
    assert "redis_data" in compose["volumes"]


def test_queue_and_lock_survive_a_crash(server):
    from backend import cancellation as cx
    r = server.start()
    lock = r.lock(cx.lock_key(7), timeout=cx.LOCK_TTL, thread_local=False)
    assert lock.acquire(blocking=False)
    r.set(cx.owner_key(7), "42", ex=cx.LOCK_TTL)
    r.lpush("celery", '{"task": "run_scan"}')
    time.sleep(1.3)                          # appendfsync everysec: let the second tick
    server.crash()

    r = server.start()
    assert r.llen("celery") == 1, "queued scan was lost"
    assert r.get(cx.owner_key(7)) == "42"
    assert 0 < r.ttl(cx.lock_key(7)) <= cx.LOCK_TTL
    # the worker that owns the lock keeps its token and can still renew and release it after the restart
    assert lock.extend(cx.LOCK_TTL, replace_ttl=True)
    lock.release()
    assert not r.exists(cx.lock_key(7))


def test_cancel_flag_survives_graceful_restart(server):
    from backend import cancellation as cx
    r = server.start()
    cx.request_cancel(r, 9)
    server.stop()                            # SIGTERM: Redis flushes the AOF on a clean shutdown
    r = server.start()
    assert cx.is_flagged(r, 9)
