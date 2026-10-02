"""Cooperative scan cancellation.

Revoking a Celery task with terminate=True only SIGTERMs the pool process: the `finally` blocks never
run (the per-target lock leaks, so the next scan sits in 'pending' for up to 30 minutes) and the
scanner tools it started (nmap, nuclei, feroxbuster ...) keep running as orphans.

Instead the API sets a flag; a guard thread inside the running task sees it within ~1s, kills every
child process of the task, and the pipeline raises ScanCancelled at its next checkpoint, so cleanup
(lock release, status) always runs. The same thread keeps the per-target lock alive (short TTL,
renewed) so a worker that dies hard can never block a target for long.
"""
import logging
import threading
from typing import Callable, List, Optional

import psutil

logger = logging.getLogger(__name__)

FLAG_TTL = 3600
LOCK_TTL = 300             # seconds; renewed while the task is alive
POLL_SECONDS = 1.0
RENEW_SECONDS = 30.0


class ScanCancelled(Exception):
    pass


def flag_key(scan_id: int) -> str:
    return f"asm:cancel:{scan_id}"


def lock_key(target_id: int) -> str:
    return f"scan_lock:{target_id}"


def owner_key(target_id: int) -> str:
    return f"scan_lock_owner:{target_id}"


def request_cancel(redis_client, scan_id: int) -> None:
    redis_client.setex(flag_key(scan_id), FLAG_TTL, "1")


def is_flagged(redis_client, scan_id: Optional[int]) -> bool:
    if not scan_id:
        return False
    try:
        return bool(redis_client.get(flag_key(scan_id)))
    except Exception:  # noqa: BLE001  redis hiccup: the DB status check is the fallback
        return False


def kill_descendants(grace: float = 3.0, pid: Optional[int] = None) -> List[int]:
    """Terminate (then kill) every descendant of this process, including tools that detached into
    their own process group. Returns the pids it signalled."""
    try:
        procs = psutil.Process(pid).children(recursive=True)
    except psutil.Error:
        return []
    for p in procs:
        try:
            p.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(procs, timeout=grace)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass
    return [p.pid for p in procs]


class ScanGuard(threading.Thread):
    """Runs beside the pipeline: watches the cancel flag, kills child tools on cancel, renews the lock."""

    def __init__(self, redis_client, scan_id: Optional[int], lock=None,
                 poll: float = POLL_SECONDS, renew: float = RENEW_SECONDS,
                 killer: Callable[[], List[int]] = kill_descendants):
        super().__init__(daemon=True, name=f"scan-guard-{scan_id}")
        self.redis, self.scan_id, self.lock = redis_client, scan_id, lock
        self.poll, self.renew, self.killer = poll, renew, killer
        self.cancelled = threading.Event()
        self._stop = threading.Event()

    def run(self) -> None:
        since_renew = 0.0
        while not self._stop.wait(self.poll):
            if self.cancelled.is_set():
                self.killer()                      # keep reaping: the pipeline may spawn its next tool
                continue
            if is_flagged(self.redis, self.scan_id):
                logger.warning(f"[cancel] scan {self.scan_id}: cancellation requested, stopping tools")
                self.cancelled.set()
                self.killer()
                continue
            since_renew += self.poll
            if self.lock is not None and since_renew >= self.renew:
                since_renew = 0.0
                try:
                    self.lock.extend(LOCK_TTL, replace_ttl=True)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"[cancel] could not renew scan lock: {e}")

    def stop(self) -> None:
        self._stop.set()

    def checkpoint(self) -> None:
        """Call between stages: raise if the scan was cancelled."""
        if self.cancelled.is_set() or is_flagged(self.redis, self.scan_id):
            self.cancelled.set()
            raise ScanCancelled()
