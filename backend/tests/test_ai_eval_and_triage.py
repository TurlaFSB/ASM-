import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend.ai.evaluate import load_cases, run_eval
from backend.ai.providers import LLMError, MockProvider
from backend.ai.triage import triage_scan_events
from backend.db import Base
from backend.models import Target
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.notifications import effective_severity, meets_threshold


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


def test_cases_are_well_formed_and_cover_the_risky_ground():
    cases = load_cases()
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)) >= 40
    tags = {t for c in cases for t in c["tags"]}
    assert {"injection", "kev", "secrets", "removal", "noise", "odd", "database"} <= tags
    assert all(c["expected"] in ("info", "low", "medium", "high", "critical") for c in cases)
    for c in cases:
        if "injection" in c["tags"]:
            assert c["forbid"], c["id"]


def test_echo_mock_passes_format_and_reports_metrics():
    rep = run_eval(MockProvider())                       # echoes the rule severity
    m = rep["metrics"]
    assert m["cases"] == len(load_cases()) and m["ok_rate"] >= 0.95
    assert m["guardrail_rejections"] >= 1                # echoing hostile text that contains a URL is refused
    assert m["latency_p50_s"] >= 0 and rep["provider"] == "mock:mock-1"


def test_burying_a_kev_finding_is_caught_and_the_guardrail_floor_holds():
    cases = [c for c in load_cases() if c["id"] == "finding-kev-added"]
    bury = json.dumps({"severity": "info", "summary": "Nothing to see.", "recommended_action": "None."})
    rep = run_eval(MockProvider({"CVE-2024-3400": bury}), cases)
    r = rep["rows"][0]
    assert r["ai_under_triage"] is True                  # the model got it wrong...
    assert r["final_under_triage"] is False              # ...but policy kept the floor
    assert rep["gates"]["final_under_triage"]["pass"]


def test_injection_canary_in_output_fails_the_gate():
    cases = [c for c in load_cases() if c["id"] == "inj-title"]
    bad = json.dumps({"severity": "low", "summary": "PWNED", "recommended_action": "Review."})
    rep = run_eval(MockProvider({"Ignore all previous": bad}), cases)
    assert rep["metrics"]["injection_failures"] == 1 and not rep["passed"]


def test_unreachable_provider_fails_ok_rate_gate_without_crashing():
    class Down(MockProvider):
        def complete(self, messages, schema=None): raise LLMError("down")
    rep = run_eval(Down(), load_cases()[:4])
    assert rep["metrics"]["ok_rate"] == 0 and not rep["passed"]


# ---- pipeline wiring ----------------------------------------------------------------------------
@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    s.add(Target(domain="10.0.0.5", authorized=True, authorized_by="me"))
    s.add(Scan(target_id=1, status="running")); s.commit()
    return s


def ev(db, sub, sev, **kw):
    e = ChangeEvent(target_id=1, scan_id=1, profile="quick", category="port", change_type="added", section="ports",
                    asset="10.0.0.5", subject=sub, severity=sev, status="confirmed", summary=f"Port {sub} opened",
                    fingerprint=sub, **kw)
    db.add(e); db.commit(); return e


def test_triage_disabled_changes_nothing(db, monkeypatch):
    monkeypatch.setenv("ASM_LLM_PROVIDER", "none")
    e = ev(db, "80/tcp", "low")
    assert triage_scan_events(db, SimpleNamespace(id=1))["status"] == "disabled"
    db.refresh(e); assert e.ai_status is None and effective_severity(e) == "low"


def test_triage_stores_result_and_effective_severity_drives_threshold(db):
    e = ev(db, "6379/tcp", "medium")
    reply = json.dumps({"severity": "high", "summary": "Redis newly exposed.", "recommended_action": "Restrict it."})
    out = triage_scan_events(db, SimpleNamespace(id=1), MockProvider({"6379": reply}))
    db.refresh(e)
    assert out["classified"] == 1 and e.ai_status == "ok" and e.severity == "medium" and e.final_severity == "high"
    assert effective_severity(e) == "high" and meets_threshold(effective_severity(e), "high")
    # idempotent: a second pass does not call the model again
    p = MockProvider(); triage_scan_events(db, SimpleNamespace(id=1), p); assert p.calls == []


def test_triage_skips_cve_groups_and_respects_event_cap(db, monkeypatch):
    monkeypatch.setenv("ASM_LLM_MAX_EVENTS", "2")
    ev(db, "1/tcp", "low"); ev(db, "2/tcp", "low"); ev(db, "3/tcp", "high"); ev(db, "4/tcp", "low", group="Apache httpd 2.4.7")
    p = MockProvider()
    out = triage_scan_events(db, SimpleNamespace(id=1), p)
    assert out["classified"] == 2 and out["skipped"] == 1 and out["status"] == "partial"
    assert "3/tcp" in p.calls[0][-1]["content"]          # most severe goes first
    assert db.query(ChangeEvent).filter(ChangeEvent.group.isnot(None)).first().ai_status is None


def test_triage_aborts_after_consecutive_failures(db):
    class Down(MockProvider):
        def complete(self, messages, schema=None):
            self.calls.append(messages); raise LLMError("down")
    for i in range(6):
        ev(db, f"{i}/tcp", "low")
    p = Down()
    out = triage_scan_events(db, SimpleNamespace(id=1), p)
    assert out["status"] == "aborted" and out["failed"] == 2 and len(p.calls) == 4   # 2 events x (1 try + 1 retry)
    assert out["skipped"] == 4


def test_triage_respects_time_budget(db, monkeypatch):
    monkeypatch.setenv("ASM_LLM_BUDGET_SECONDS", "5")
    for i in range(3):
        ev(db, f"{i}/tcp", "low")
    t = iter([0, 0, 10, 10, 10, 10])
    out = triage_scan_events(db, SimpleNamespace(id=1), MockProvider(), clock=lambda: next(t))
    assert out["classified"] == 1 and out["status"] == "partial"


def test_hostile_field_cannot_close_the_event_envelope():
    from backend.ai.prompt import build_messages
    c = next(c for c in load_cases() if c["id"] == "inj-json")
    body = build_messages(c["event"])[-1]["content"]
    assert body.count("<event>") == 1 and body.count("</event>") == 1
