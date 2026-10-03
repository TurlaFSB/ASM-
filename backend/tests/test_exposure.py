import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base
from backend.exposure import registry, runner
from backend.exposure.base import CollectorError, Finding, RateLimited, clean_text, safe_https_url
from backend.exposure.github_code import GitHubCodeCollector
from backend.exposure.http import Response
from backend.exposure.masking import mask_value, path_severity, scan_fragment
from backend.exposure.xposedornot import XposedOrNotCollector
from backend.models import Alert, Target
from backend.models.exposure import CollectorRun, ExposureFinding
from backend.models.webhook_delivery import WebhookDelivery


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


@pytest.fixture()
def target(db):
    t = Target(domain="acme.com", authorized=True, authorized_by="me", is_active=True,
               exposure_sources=["github_code", "xposedornot"])
    db.add(t); db.commit()
    return t


class FakeHttp:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, params=None, headers=None):
        self.calls.append((url, params, headers))
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def resp(data, status=200, headers=None):
    return Response(status, json.dumps(data).encode(), headers or {})


# ------------------------------------------------------------------ masking

SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_mask_value_never_shows_much():
    assert mask_value("short") == "***(5)"
    assert mask_value("0123456789ab") == "01***(12)"
    assert mask_value("A" * 30).startswith("AAAA***")


def test_scan_fragment_detects_and_masks():
    frag = (f'aws_secret = "{SECRET}"\nAKIAIOSFODNN7EXAMPLE\npassword: hunter2hunter2\n'
            "db = postgres://admin:S3cretPass99@db.acme.com/prod\n-----BEGIN RSA PRIVATE KEY-----")
    hits = scan_fragment(frag, "acme.com")
    rules = {h.rule for h in hits}
    assert {"aws_access_key_id", "private_key_block", "uri_credentials", "assignment:password"} <= rules
    blob = json.dumps([h.__dict__ for h in hits])
    for secret in (SECRET, "AKIAIOSFODNN7EXAMPLE", "hunter2hunter2", "S3cretPass99"):
        assert secret not in blob
    assert [h for h in hits if h.rule == "uri_credentials"][0].severity == "high"   # host is the target's


def test_placeholders_are_not_hits():
    for v in ("password = 'your_password_here'", "api_key: ${API_KEY_VALUE}", "secret=changeme123456",
              "token = process.env.TOKEN_VALUE", "password: ********"):
        assert scan_fragment(v) == [], v


def test_path_severity():
    assert path_severity("config/.env.production") == "medium"
    assert path_severity("deploy/credentials.json") == "medium"
    assert path_severity("settings.yml") == "low"
    assert path_severity("README.md") == "info"


def test_input_hygiene():
    assert clean_text("a\x00b‮c  d\n", 10) == "abc d"
    assert safe_https_url("https://github.com/x/y", ("github.com",)) == "https://github.com/x/y"
    assert safe_https_url("http://github.com/x", ("github.com",)) is None
    assert safe_https_url("https://evil.example/x", ("github.com",)) is None
    assert safe_https_url("javascript:alert(1)", ("github.com",)) is None


# ------------------------------------------------------------------ github collector

def gh_item(repo, path, fragment, fork=False):
    return {"path": path, "html_url": f"https://github.com/{repo}/blob/main/{path}",
            "repository": {"full_name": repo, "fork": fork},
            "text_matches": [{"fragment": fragment}]}


def test_github_requires_token(monkeypatch):
    monkeypatch.delenv("ASM_GITHUB_TOKEN", raising=False)
    c = GitHubCodeCollector()
    assert not c.configured()
    with pytest.raises(CollectorError):
        c.collect("acme.com", FakeHttp(resp({})), lambda s: None)


def test_github_collects_masks_and_filters(monkeypatch):
    monkeypatch.setenv("ASM_GITHUB_TOKEN", "ghp_dummy")
    items = [
        gh_item("bob/app", ".env", f"API=https://acme.com\nSECRET_KEY={SECRET}"),
        gh_item("bob/docs", "README.md", "visit acme.com for details"),
        gh_item("eve/fork", ".env", f"acme.com password={SECRET}", fork=True),     # forks skipped
        gh_item("zed/other", "x.py", "nothing relevant here"),                      # domain absent -> dropped
    ]
    http = FakeHttp(resp({"items": items}))
    slept = []
    out = GitHubCodeCollector().collect("acme.com", http, slept.append)
    by_key = {f.key: f for f in out}
    assert set(by_key) == {"bob/app|.env", "bob/docs|README.md"}
    assert by_key["bob/app|.env"].severity == "medium" and by_key["bob/app|.env"].kind == "secret"
    assert by_key["bob/docs|README.md"].severity == "info" and by_key["bob/docs|README.md"].kind == "mention"
    assert SECRET not in json.dumps([f.__dict__ for f in out])
    assert len(http.calls) == 4 and len(slept) == 3                       # paced
    assert http.calls[0][2]["Authorization"] == "Bearer ghp_dummy"


def test_github_rate_limit_and_errors(monkeypatch):
    monkeypatch.setenv("ASM_GITHUB_TOKEN", "t")
    c = GitHubCodeCollector()
    with pytest.raises(RateLimited):
        c.collect("acme.com", FakeHttp(resp({}, 403, {"x-ratelimit-remaining": "0"})), lambda s: None)
    with pytest.raises(RateLimited):
        c.collect("acme.com", FakeHttp(resp({}, 429)), lambda s: None)
    with pytest.raises(CollectorError) as e:
        c.collect("acme.com", FakeHttp(resp({}, 401)), lambda s: None)
    assert e.value.label == "token rejected"
    with pytest.raises(CollectorError):
        c.collect("acme.com", FakeHttp(resp({}, 502)), lambda s: None)


# ------------------------------------------------------------------ xposedornot collector

def test_xon_parses_and_rates_breaches():
    payload = {"status": "success", "exposedBreaches": [
        {"breachID": "AcmeLeak", "breachedDate": "2021-05-01", "exposedRecords": 120000,
         "exposedData": ["Email addresses", "Passwords"], "referenceURL": "https://xposedornot.com/b/AcmeLeak", "verified": True},
        {"breachID": "OldOne", "exposedData": ["Usernames"], "verified": False},
    ]}
    out = XposedOrNotCollector().collect("acme.com", FakeHttp(resp(payload)), lambda s: None)
    by = {f.key: f for f in out}
    assert by["AcmeLeak"].severity == "high" and by["AcmeLeak"].url.startswith("https://xposedornot.com/")
    assert by["OldOne"].severity == "low"
    assert "120,000 records" in by["AcmeLeak"].summary


def test_xon_not_found_is_clean_but_garbage_is_an_error():
    c = XposedOrNotCollector()
    assert c.collect("acme.com", FakeHttp(resp({"Error": "Not found"})), lambda s: None) == []
    assert c.collect("acme.com", FakeHttp(resp({}, 404)), lambda s: None) == []
    assert c.collect("acme.com", FakeHttp(resp({"exposedBreaches": []})), lambda s: None) == []
    with pytest.raises(CollectorError):
        c.collect("acme.com", FakeHttp(resp({"something": "else"})), lambda s: None)
    with pytest.raises(CollectorError):
        c.collect("acme.com", FakeHttp(Response(200, b"<html>", {})), lambda s: None)
    with pytest.raises(RateLimited):
        c.collect("acme.com", FakeHttp(resp({}, 429)), lambda s: None)


# ------------------------------------------------------------------ runner

class StubCollector:
    label = description = "stub"
    min_interval_seconds = 3600

    def __init__(self, name, findings=None, exc=None, configured=True):
        self.name, self._f, self._exc, self._cfg = name, findings or [], exc, configured

    def configured(self): return self._cfg

    def collect(self, domain, http, sleep):
        if self._exc:
            raise self._exc
        return list(self._f)


def F(key, sev="high", source="stub", kind="secret"):
    return Finding(source=source, kind=kind, key=key, title=f"t-{key}", summary="s", severity=sev,
                   url="https://github.com/x", evidence={"repo": "x"})


@pytest.fixture()
def stub(monkeypatch, target, db):
    c = StubCollector("stub")
    monkeypatch.setitem(registry.REGISTRY, "stub", c)
    target.exposure_sources = ["stub"]
    db.commit()
    return c


T0 = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def test_new_findings_alert_and_dedupe(db, target, stub):
    stub._f = [F("a", "high"), F("b", "info")]
    r = runner.run_collectors(db, target, now=T0)
    assert r["stub"] == {"status": "ok", "found": 2, "new": 2}
    alerts = db.query(Alert).all()
    assert len(alerts) == 1 and alerts[0].scan_id is None and alerts[0].category == "exposure"   # info is below the default threshold
    # same data later: nothing new
    r = runner.run_collectors(db, target, now=T0 + timedelta(hours=2))
    assert r["stub"]["new"] == 0 and db.query(Alert).count() == 1
    assert {f.seen_count for f in db.query(ExposureFinding).all()} == {2}


def test_min_interval_and_force(db, target, stub):
    runner.run_collectors(db, target, now=T0)
    assert runner.run_collectors(db, target, now=T0 + timedelta(minutes=10))["stub"]["status"] == "too_soon"
    assert runner.run_collectors(db, target, force=True, now=T0 + timedelta(minutes=10))["stub"]["status"] == "ok"
    assert runner.run_collectors(db, target, force=True, now=T0 + timedelta(minutes=11))["stub"]["status"] == "too_soon"


def test_failure_retries_sooner_than_success(db, target, stub):
    stub._exc = CollectorError("upstream error")
    assert runner.run_collectors(db, target, now=T0)["stub"]["status"] == "failed"
    stub._exc = None
    assert runner.run_collectors(db, target, now=T0 + timedelta(minutes=30))["stub"]["status"] == "too_soon"
    assert runner.run_collectors(db, target, now=T0 + timedelta(hours=1, minutes=1))["stub"]["status"] == "ok"
    assert db.query(CollectorRun).filter_by(status="failed").one().error == "upstream error"


def test_rate_limited_keeps_findings_and_does_not_resolve(db, target, stub):
    stub._f = [F("a")]
    runner.run_collectors(db, target, now=T0)
    stub._exc = RateLimited(60)
    assert runner.run_collectors(db, target, now=T0 + timedelta(hours=2))["stub"]["status"] == "rate_limited"
    f = db.query(ExposureFinding).one()
    assert f.status == "open" and f.missed_runs == 0


def test_resolve_after_misses_then_reappear_alerts_again(db, target, stub):
    stub._f = [F("a")]
    runner.run_collectors(db, target, now=T0)
    stub._f = []
    for i in range(1, 4):
        runner.run_collectors(db, target, now=T0 + timedelta(hours=2 * i))
    assert db.query(ExposureFinding).one().status == "resolved"
    stub._f = [F("a")]
    r = runner.run_collectors(db, target, now=T0 + timedelta(hours=10))
    f = db.query(ExposureFinding).one()
    assert f.status == "open" and r["stub"]["new"] == 1
    assert db.query(Alert).count() == 2


def test_dismissed_is_sticky_and_escalation_alerts(db, target, stub):
    stub._f = [F("a", "medium")]
    runner.run_collectors(db, target, now=T0)
    f = db.query(ExposureFinding).one()
    stub._f = [F("a", "high")]
    r = runner.run_collectors(db, target, now=T0 + timedelta(hours=2))
    assert r["stub"]["new"] == 1 and f.severity == "high"                    # escalated -> alert
    f.status = "dismissed"; db.commit()
    stub._f = [F("a", "critical")]
    r = runner.run_collectors(db, target, now=T0 + timedelta(hours=4))
    assert r["stub"]["new"] == 0 and db.query(ExposureFinding).one().status == "dismissed"


def test_sources_are_independent_and_unconfigured_is_reported(db, target, monkeypatch):
    good, bad, nocfg = StubCollector("good", [F("g", source="good")]), StubCollector("bad", exc=RuntimeError("boom")), \
        StubCollector("nocfg", configured=False)
    for c in (good, bad, nocfg):
        monkeypatch.setitem(registry.REGISTRY, c.name, c)
    target.exposure_sources = ["good", "bad", "nocfg", "not-a-source"]
    db.commit()
    r = runner.run_collectors(db, target, now=T0)
    assert r["good"]["status"] == "ok" and r["bad"]["status"] == "failed" and r["nocfg"]["status"] == "not_configured"
    assert "not-a-source" not in r
    assert db.query(CollectorRun).filter_by(source="bad").one().error == "internal error"


def test_off_by_default_and_inactive_target(db, target, stub):
    target.exposure_sources = None; db.commit()
    assert runner.run_collectors(db, target, now=T0) == {}
    target.exposure_sources = ["stub"]; target.is_active = False; db.commit()
    assert runner.run_collectors(db, target, now=T0) == {}


def test_already_running_guard_and_stale_cleanup(db, target, stub):
    db.add(CollectorRun(target_id=target.id, source="stub", status="running", started_at=T0 - timedelta(minutes=5)))
    db.commit()
    assert runner.run_collectors(db, target, now=T0)["stub"]["status"] == "already_running"
    # a run that has been 'running' for over 30 minutes is a crashed worker: closed, then the new run proceeds
    r = runner.run_collectors(db, target, now=T0 + timedelta(hours=1))
    assert r["stub"]["status"] == "ok"
    assert db.query(CollectorRun).filter_by(status="failed").one().error.startswith("stale")


def test_alert_cap_and_webhook(db, target, stub, monkeypatch):
    sent = []

    def fake_deliver(db_, tgt, payload, *, scan_id, kind, event_count, **kw):
        sent.append((kind, event_count, payload))
        rec = WebhookDelivery(target_id=tgt.id, kind=kind, status="sent", host="h", event_count=event_count)
        db_.add(rec); db_.commit()
        return rec

    monkeypatch.setattr("backend.exposure.notify.deliver", fake_deliver)
    target.webhook_url = "https://hooks.example/x"; db.commit()
    stub._f = [F(f"k{i}", "high") for i in range(14)]
    runner.run_collectors(db, target, now=T0)
    kinds = [a.alert_type for a in db.query(Alert).all()]
    assert kinds.count("exposure_secret") == 10 and kinds.count("exposure_summary") == 1
    assert sent[0][0] == "exposure" and sent[0][1] == 14
    assert sent[0][2]["event"] == "exposure.new" and len(sent[0][2]["findings"]) == 14


def test_evidence_in_db_has_no_full_secret(db, target, monkeypatch):
    monkeypatch.setenv("ASM_GITHUB_TOKEN", "t")
    items = [gh_item("bob/app", ".env", f"acme.com\nAWS_SECRET_ACCESS_KEY={SECRET}\nAKIAIOSFODNN7EXAMPLE")]
    r = runner.run_collectors(db, target, sources=["github_code"], http=FakeHttp(resp({"items": items})), sleep=lambda s: None, now=T0)
    assert r["github_code"]["status"] == "ok"
    f = db.query(ExposureFinding).one()
    stored = json.dumps([f.title, f.summary, f.url, f.evidence])
    assert SECRET not in stored and "AKIAIOSFODNN7EXAMPLE" not in stored
    assert f.severity == "high"
