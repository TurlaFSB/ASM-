"""deploy/restore.sh with stub psql / pg_restore on PATH (no database needed)."""
import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "restore.sh"


def _stub(bin_dir: Path, name: str, body: str):
    p = bin_dir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def env(tmp_path):
    bin_dir, backups, calls = tmp_path / "bin", tmp_path / "backups", tmp_path / "calls.log"
    bin_dir.mkdir()
    backups.mkdir()
    # pg_restore: --list succeeds for PGDMP files; real restores are logged. A dump containing "BAD" fails to restore.
    _stub(bin_dir, "pg_restore",
          f'for a; do f="$a"; done\n'
          f'if [ "$1" = "--list" ]; then head -c 5 "$f" | grep -q PGDMP; exit $?; fi\n'
          f'echo "pg_restore $*" >> {calls}\n'
          f'grep -q BAD "$f" && exit 1; exit 0')
    # psql: table list -> two tables, counts -> 3, everything else logged
    _stub(bin_dir, "psql",
          f'sql=""; while [ $# -gt 0 ]; do [ "$1" = "-c" ] && sql="$2"; shift; done\n'
          f'echo "psql $sql" >> {calls}\n'
          f'case "$sql" in *information_schema*) printf "scans\\nusers\\n";; *"count(*)"*) echo 3;; '
          f'*version_num*) echo 0016;; *"SELECT 1"*) echo 1;; esac')
    e = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", BACKUP_DIR=str(backups), PGDATABASE="asm_db")
    return e, backups, calls


def make_dump(d: Path, name="asm_db_20260101T000000Z.dump", body=b"PGDMP-ok", checksum=True) -> Path:
    p = d / name
    p.write_bytes(body)
    if checksum:
        subprocess.run(f"sha256sum {name} > {name}.sha256", shell=True, cwd=d, check=True)
    return p


def run(e, *args):
    return subprocess.run(["sh", str(SCRIPT), *args], env=e, capture_output=True, text=True, timeout=30)


def test_verify_restores_into_scratch_and_drops_it(env):
    e, backups, calls = env
    make_dump(backups)
    r = run(e, "verify")
    assert r.returncode == 0, r.stdout + r.stderr
    log = calls.read_text()
    assert "CREATE DATABASE" in log and "DROP DATABASE IF EXISTS" in log
    assert "asm_restore_check_" in log and "--clean" not in log          # never touches the live database
    assert "scans 3" in r.stdout and "revision 0016" in r.stdout and "restores cleanly" in r.stdout


def test_verify_picks_the_newest_dump(env):
    e, backups, calls = env
    old = make_dump(backups, "asm_db_20260101T000000Z.dump")
    new = make_dump(backups, "asm_db_20260102T000000Z.dump")
    os.utime(old, (1, 1))
    assert run(e, "verify").returncode == 0
    assert "asm_db_20260102T000000Z.dump" in calls.read_text()


def test_checksum_mismatch_is_refused(env):
    e, backups, calls = env
    d = make_dump(backups)
    d.write_bytes(b"PGDMP-tampered")
    r = run(e, "verify", str(d))
    assert r.returncode == 1 and "checksum mismatch" in r.stdout
    assert not calls.exists()


def test_unreadable_dump_is_refused(env):
    e, backups, calls = env
    d = make_dump(backups, body=b"garbage", checksum=False)
    r = run(e, "verify", str(d))
    assert r.returncode == 1 and "not a readable" in r.stdout


def test_failed_restore_still_drops_scratch_database(env):
    e, backups, calls = env
    d = make_dump(backups, body=b"PGDMP-BAD")
    r = run(e, "verify", str(d))
    assert r.returncode == 1 and "does not restore" in r.stdout
    assert "DROP DATABASE IF EXISTS" in calls.read_text()


def test_apply_requires_explicit_file_and_confirmation(env):
    e, backups, calls = env
    d = make_dump(backups)
    assert run(e, "apply").returncode == 1                       # no file: never guesses
    r = run(e, "apply", str(d))
    assert r.returncode == 1 and "--yes" in r.stdout
    assert not calls.exists()                                    # nothing ran


def test_apply_runs_one_transaction_with_clean(env):
    e, backups, calls = env
    d = make_dump(backups)
    r = run(e, "apply", str(d), "--yes")
    assert r.returncode == 0, r.stdout
    line = [ln for ln in calls.read_text().splitlines() if ln.startswith("pg_restore")][0]
    assert "--single-transaction" in line and "--clean" in line and "-d asm_db" in line


def test_apply_failure_reports_rollback(env):
    e, backups, calls = env
    d = make_dump(backups, body=b"PGDMP-BAD")
    r = run(e, "apply", str(d), "--yes")
    assert r.returncode == 1 and "rolled back" in r.stdout


def test_usage_on_bad_mode(env):
    e, *_ = env
    assert run(e, "nonsense").returncode == 2
