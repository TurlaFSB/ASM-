import subprocess
import sys
import time

import pytest

from backend import cancellation as c


class FakeRedis:
    def __init__(self): self.d = {}
    def get(self, k): return self.d.get(k)
    def setex(self, k, ttl, v): self.d[k] = v


class FakeLock:
    def __init__(self): self.extended = 0
    def extend(self, ttl, replace_ttl=False): self.extended += 1


def test_flag_roundtrip():
    r = FakeRedis()
    assert not c.is_flagged(r, 7) and not c.is_flagged(r, None)
    c.request_cancel(r, 7)
    assert c.is_flagged(r, 7) and not c.is_flagged(r, 8)


def test_redis_failure_is_not_a_cancel():
    class Broken:
        def get(self, k): raise RuntimeError("down")
    assert c.is_flagged(Broken(), 1) is False


def test_checkpoint_raises_only_after_flag():
    r = FakeRedis()
    g = c.ScanGuard(r, 5)
    g.checkpoint()                                   # fine
    c.request_cancel(r, 5)
    with pytest.raises(c.ScanCancelled):
        g.checkpoint()


def test_kill_descendants_kills_real_children_and_grandchildren():
    # a child that itself spawns a grandchild in its own session, like a detached scanner tool
    child = subprocess.Popen([sys.executable, "-c",
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True);"
        "time.sleep(60)"])
    time.sleep(0.8)
    killed = c.kill_descendants(grace=2)
    assert len(killed) >= 2                          # child and grandchild
    child.wait(timeout=5)
    assert child.returncode is not None


def test_guard_kills_tools_when_flag_appears_and_keeps_reaping():
    r, calls = FakeRedis(), []
    g = c.ScanGuard(r, 9, poll=0.02, killer=lambda: calls.append(1) or [])
    g.start()
    time.sleep(0.1); assert not g.cancelled.is_set() and not calls
    c.request_cancel(r, 9)
    time.sleep(0.2)
    assert g.cancelled.is_set() and len(calls) >= 2   # killed, then kept reaping newly spawned tools
    g.stop(); g.join(timeout=2)


def test_guard_renews_lock_while_alive():
    lock = FakeLock()
    g = c.ScanGuard(FakeRedis(), 1, lock=lock, poll=0.02, renew=0.05)
    g.start(); time.sleep(0.3); g.stop(); g.join(timeout=2)
    assert lock.extended >= 2


# --- lock renewal from the guard thread (real Redis; fakes hid the thread-local token bug) ---------
import shutil
import socket
import subprocess
import time

import pytest


@pytest.fixture()
def real_redis(tmp_path):
    exe = shutil.which("redis-server")
    if not exe:
        pytest.skip("redis-server not installed")
    redis = pytest.importorskip("redis")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([exe, "--port", str(port), "--save", "", "--dir", str(tmp_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client = redis.Redis(port=port, decode_responses=True)
    for _ in range(50):
        try:
            client.ping()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    yield client
    proc.terminate()
    proc.wait(timeout=5)


def test_guard_thread_can_renew_real_lock(real_redis):
    from cancellation import ScanGuard, lock_key
    lock = real_redis.lock(lock_key(1), timeout=20, thread_local=False)
    assert lock.acquire(blocking=False)
    guard = ScanGuard(real_redis, 1, lock=lock, poll=0.05, renew=0.1)
    guard.start()
    time.sleep(0.5)
    guard.stop()
    guard.join(timeout=2)
    assert real_redis.ttl(lock_key(1)) > 100        # extended to LOCK_TTL by the guard thread
    lock.release()
