import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import retention
from backend.db import Base
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.webhook_delivery import WebhookDelivery


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


def age(path, days):
    t = time.time() - days * 86400
    os.utime(path, (t, t))


def test_prune_older_than_matches_only_old_named_entries(tmp_path):
    old, new, other = tmp_path / "run-old", tmp_path / "run-new", tmp_path / "keepme"
    for d in (old, new, other):
        d.mkdir()
        (d / "a.png").write_bytes(b"x" * 10)
    age(old, 120); age(other, 500)
    out = retention.prune_older_than(tmp_path, 90, match=lambda n: n.startswith("run-"))
    assert out == {"removed": 1, "bytes": 10}
    assert not old.exists() and new.exists() and other.exists()


def test_zero_days_disables_and_missing_dir_is_fine(tmp_path):
    (tmp_path / "1").mkdir(); age(tmp_path / "1", 999)
    assert retention.prune_older_than(tmp_path, 0, match=str.isdigit)["removed"] == 0
    assert retention.prune_older_than(tmp_path / "nope", 5, match=str.isdigit)["removed"] == 0


def test_symlink_is_unlinked_not_followed(tmp_path):
    outside = tmp_path / "outside"; outside.mkdir(); (outside / "keep.txt").write_text("k")
    root = tmp_path / "root"; root.mkdir()
    link = root / "12"; link.symlink_to(outside, target_is_directory=True)
    os.utime(link, (1, 1), follow_symlinks=False)
    retention.prune_older_than(root, 1, match=str.isdigit)
    assert not link.exists() and (outside / "keep.txt").exists()


def test_run_retention_end_to_end(tmp_path, monkeypatch):
    shots, out = tmp_path / "shots", tmp_path / "scan_output"
    (shots / "run-a").mkdir(parents=True); (out / "7" / "dirbuster").mkdir(parents=True)
    (out / "reports").mkdir(); (out / "reports" / "r.pdf").write_bytes(b"pdf")
    (out / "ai_eval").mkdir()
    for p in (shots / "run-a", out / "7", out / "reports" / "r.pdf", out / "ai_eval"):
        age(p, 200)
    monkeypatch.setenv("SCREENSHOT_DIR", str(shots))
    monkeypatch.setenv("ASM_REPORT_CACHE_DIR", str(out / "reports"))
    monkeypatch.setenv("ASM_RETENTION_DAYS", "90")
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="example.org"); db.add(t); db.commit()
    sc = Scan(target_id=t.id, status="completed"); db.add(sc); db.commit()
    now = datetime.now(timezone.utc)
    db.add_all([WebhookDelivery(target_id=t.id, scan_id=sc.id, status="sent", created_at=now - timedelta(days=400)),
                WebhookDelivery(target_id=t.id, scan_id=sc.id, status="sent", created_at=now)])
    db.commit()
    s = retention.run_retention(db)
    assert s["screenshots"]["removed"] == 1 and s["scan_output"]["removed"] == 1
    assert s["reports"]["removed"] == 1 and s["webhook_deliveries"] == 1
    assert (out / "ai_eval").exists()                    # not a scan folder: left alone
    assert db.query(WebhookDelivery).count() == 1 and db.query(Scan).count() == 1


def test_bad_env_value_falls_back(monkeypatch):
    monkeypatch.setenv("ASM_RETENTION_DAYS", "soon")
    assert retention._days("ASM_RETENTION_DAYS", 90) == 90
