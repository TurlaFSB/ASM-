"""deploy/backup.sh with stub pg_dump / pg_restore on PATH (no database needed)."""
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "backup.sh"


def _stub(bin_dir: Path, name: str, body: str):
    p = bin_dir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def env(tmp_path):
    bin_dir, out = tmp_path / "bin", tmp_path / "out"
    bin_dir.mkdir()
    # pg_dump -F c -f FILE : writes FILE. pg_restore --list FILE : succeeds if the file starts with PGDMP
    _stub(bin_dir, "pg_dump", 'while [ $# -gt 0 ]; do [ "$1" = "-f" ] && f="$2"; shift; done; printf "PGDMP-data" > "$f"')
    _stub(bin_dir, "pg_restore", 'for a; do f="$a"; done; head -c 5 "$f" | grep -q PGDMP')
    e = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", BACKUP_DIR=str(out), BACKUP_ONCE="1", BACKUP_KEEP="3")
    return e, out, bin_dir


def run(e):
    return subprocess.run(["sh", str(SCRIPT)], env=e, capture_output=True, text=True, timeout=30)


def test_creates_verified_dump_with_checksum(env):
    e, out, _ = env
    r = run(e)
    assert r.returncode == 0, r.stderr
    dumps = list(out.glob("asm_db_*.dump"))
    assert len(dumps) == 1 and dumps[0].read_bytes().startswith(b"PGDMP")
    sums = list(out.glob("asm_db_*.dump.sha256"))
    assert len(sums) == 1
    assert subprocess.run(["sha256sum", "-c", sums[0].name], cwd=out, capture_output=True).returncode == 0
    assert not list(out.glob(".*.part"))


def test_prunes_to_keep_newest(env):
    e, out, _ = env
    out.mkdir()
    for i in range(5):
        d = out / f"asm_db_2026010{i}T000000Z.dump"
        d.write_text("x"); (out / (d.name + ".sha256")).write_text("x")
        t = time.time() - (100 - i) * 86400
        os.utime(d, (t, t))
    assert run(e).returncode == 0
    left = sorted(p.name for p in out.glob("asm_db_*.dump"))
    assert len(left) == 3 and "asm_db_20260100T000000Z.dump" not in left and "asm_db_20260101T000000Z.dump" not in left
    assert not (out / "asm_db_20260100T000000Z.dump.sha256").exists()


def test_failed_dump_leaves_no_file_and_exits_nonzero(env):
    e, out, bin_dir = env
    _stub(bin_dir, "pg_dump", "exit 1")
    r = run(e)
    assert r.returncode == 1 and "pg_dump failed" in r.stdout
    assert not list(out.glob("*"))


def test_unreadable_dump_is_discarded(env):
    e, out, bin_dir = env
    _stub(bin_dir, "pg_dump", 'while [ $# -gt 0 ]; do [ "$1" = "-f" ] && f="$2"; shift; done; printf "garbage" > "$f"')
    r = run(e)
    assert r.returncode == 1 and "unreadable" in r.stdout
    assert not list(out.glob("asm_db_*")) and not list(out.glob(".*.part"))
