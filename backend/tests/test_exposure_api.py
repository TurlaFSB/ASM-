from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.audit_log import AuditLog
from backend.models.exposure import ExposureFinding, CollectorRun


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="acme.com", authorized=True, authorized_by="me", is_active=True)
    db.add(t); db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="pranav", role="admin")
    monkeypatch.delenv("ASM_GITHUB_TOKEN", raising=False)
    yield db, t, TestClient(app)
    app.dependency_overrides.clear()


def test_sources_listing_never_leaks_the_token(env, monkeypatch):
    _, _, c = env
    monkeypatch.setenv("ASM_GITHUB_TOKEN", "ghp_supersecret")
    r = c.get("/exposure/sources")
    assert r.status_code == 200 and "ghp_supersecret" not in r.text
    by = {s["name"]: s for s in r.json()}
    assert by["github_code"]["configured"] is True and by["xposedornot"]["configured"] is True


def test_toggle_sources_validates_and_audits(env):
    db, t, c = env
    assert c.get(f"/exposure/targets/{t.id}/sources").json()[0]["enabled"] is False        # off by default
    assert c.put(f"/exposure/targets/{t.id}/sources", json={"sources": ["nope"]}).status_code == 422
    r = c.put(f"/exposure/targets/{t.id}/sources", json={"sources": ["xposedornot", "xposedornot"]})
    assert r.status_code == 200 and [s["name"] for s in r.json() if s["enabled"]] == ["xposedornot"]
    db.refresh(t)
    assert t.exposure_sources == ["xposedornot"]
    assert db.query(AuditLog).filter_by(action="exposure_sources_set").count() == 1
    assert c.put("/exposure/targets/999/sources", json={"sources": []}).status_code == 404


def test_run_now_needs_a_source_and_queues_forced_task(env, monkeypatch):
    db, t, c = env
    calls = []
    monkeypatch.setattr("backend.tasks.run_exposure_checks.delay", lambda *a: calls.append(a))
    assert c.post(f"/exposure/targets/{t.id}/run").status_code == 409
    t.exposure_sources = ["xposedornot"]; db.commit()
    assert c.post(f"/exposure/targets/{t.id}/run").status_code == 202
    assert calls == [(t.id, None, True)]


def _add(db, t, **kw):
    d = dict(target_id=t.id, source="github_code", kind="secret", fingerprint=str(len(kw)) + str(kw), title="x",
             summary="s", severity="high", status="open", evidence={"repo": "a/b"})
    d.update(kw)
    f = ExposureFinding(**d); db.add(f); db.commit()
    return f


def test_findings_list_filter_order_and_dismiss(env):
    db, t, c = env
    _add(db, t, fingerprint="1", severity="low", title="low")
    hi = _add(db, t, fingerprint="2", severity="high", title="high")
    _add(db, t, fingerprint="3", severity="critical", title="crit", source="xposedornot", kind="breach")
    r = c.get("/exposure/findings")
    assert [f["title"] for f in r.json()] == ["crit", "high", "low"] and r.headers["X-Total-Count"] == "3"
    assert [f["title"] for f in c.get("/exposure/findings?source=github_code&severity=high,low").json()] == ["high", "low"]
    assert c.get("/exposure/findings?status=bogus").status_code == 422
    assert c.patch(f"/exposure/findings/{hi.id}", json={"status": "dismissed"}).json()["status"] == "dismissed"
    assert [f["title"] for f in c.get("/exposure/findings?status=open").json()] == ["crit", "low"]
    assert c.patch(f"/exposure/findings/{hi.id}", json={"status": "resolved"}).status_code == 422
    assert c.patch("/exposure/findings/999", json={"status": "open"}).status_code == 404


def test_runs_listing(env):
    db, t, c = env
    db.add(CollectorRun(target_id=t.id, source="xposedornot", status="failed", error="timeout")); db.commit()
    r = c.get(f"/exposure/runs?target_id={t.id}").json()
    assert r[0]["error"] == "timeout" and r[0]["status"] == "failed"
