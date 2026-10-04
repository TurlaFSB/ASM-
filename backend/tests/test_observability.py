import json
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import observability
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.vulnerability import Vulnerability


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="example.org"); s.add(t); s.commit()
    sc = Scan(target_id=t.id, status="completed", completed_at=datetime.now(timezone.utc) - timedelta(seconds=90))
    s.add(sc); s.commit()
    s.add_all([Asset(target_id=t.id, subdomain="a", status="active"),
               Asset(target_id=t.id, subdomain="b", status="disappeared"),
               Vulnerability(target_id=t.id, scan_id=sc.id, severity="High", template_id="x", name="n", host="h"),
               Vulnerability(target_id=t.id, scan_id=sc.id, severity="high", template_id="y", name="n", host="h")])
    s.commit()
    yield s
    s.close()


def test_render_metrics_counts(db):
    text = observability.render_metrics(db, queue_depth=3)
    assert 'asm_scans{status="completed"} 1' in text and 'asm_scans{status="failed"} 0' in text
    assert "asm_assets 1" in text and 'asm_findings{severity="high"} 2' in text
    assert "asm_queue_depth 3" in text and "asm_last_completed_scan_age_seconds 9" in text
    assert "example.org" not in text


def test_no_completed_scan_omits_age(db):
    db.query(Scan).delete(); db.commit()
    assert "last_completed_scan_age" not in observability.render_metrics(db)


def test_metrics_endpoint_admin_only(db):
    app.dependency_overrides[get_db] = lambda: (yield db)
    try:
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="v", role="viewer", is_active=True)
        c = TestClient(app)
        assert c.get("/metrics").status_code == 403
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="a", role="admin", is_active=True)
        r = c.get("/metrics")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
        assert "asm_scans" in r.text
    finally:
        app.dependency_overrides.clear()


def test_json_formatter():
    rec = logging.LogRecord("x.y", logging.WARNING, __file__, 1, "hello %s", ("w",), None)
    data = json.loads(observability.JsonFormatter().format(rec))
    assert data["msg"] == "hello w" and data["level"] == "WARNING" and data["logger"] == "x.y"


def test_configure_logging_only_in_json_mode(monkeypatch):
    root = logging.getLogger()
    before = list(root.handlers)
    monkeypatch.setenv("ASM_LOG_FORMAT", "text")
    observability.configure_logging()
    assert root.handlers == before
    monkeypatch.setenv("ASM_LOG_FORMAT", "json")
    try:
        observability.configure_logging()
        assert isinstance(root.handlers[0].formatter, observability.JsonFormatter)
    finally:
        root.handlers = before
