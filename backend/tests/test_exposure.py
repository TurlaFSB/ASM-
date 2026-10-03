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


# ------------------------------------------------------------------ real responses recorded from the live services (2026-10-03)

REAL_XON_ADOBE = {"status": "success", "message": None, "exposedBreaches": [{
    "breachID": "Adobe", "breachedDate": "2013-10-01T00:00:00+00:00", "addedDate": "2023-11-08T06:30:03+00:00",
    "domain": "adobe.com", "industry": "Information Technology", "logo": "https://xposedornot.com/static/logos/Adobe.png",
    "passwordRisk": "easytocrack", "searchable": True, "sensitive": False, "verified": True, "breachType": "DataBreach",
    "exposedData": ["Usernames", "Passwords", "Email addresses"], "exposedRecords": 152403035,
    "exposureDescription": "Adobe ...", "referenceURL": "https://krebsonsecurity.com/2013/10/adobe-breach-impacted-at-least-38-million-users/"}]}
REAL_XON_NONE = {"status": "Not Found", "message": "No breaches found for the provided criteria", "exposedBreaches": None}


def test_xon_real_adobe_response():
    out = XposedOrNotCollector().collect("adobe.com", FakeHttp(resp(REAL_XON_ADOBE)), lambda s: None)
    assert len(out) == 1
    f = out[0]
    assert f.severity == "high" and f.key == "Adobe"
    assert f.url.startswith("https://krebsonsecurity.com/")          # third-party reference link is kept
    assert "2013-10-01," in f.summary and "152,403,035 records" in f.summary
    assert f.evidence["password_risk"] == "easytocrack"


def test_xon_real_not_found_response_is_clean():
    assert XposedOrNotCollector().collect("example.com", FakeHttp(resp(REAL_XON_NONE)), lambda s: None) == []


def test_reference_urls_never_carry_credentials_or_non_https():
    assert safe_https_url("https://user:pw@evil.example/x", None) is None
    assert safe_https_url("http://news.example/x", None) is None
    assert safe_https_url("https://news.example/x", None) == "https://news.example/x"


def test_docs_tests_and_examples_are_capped_but_real_tokens_are_not(monkeypatch):
    monkeypatch.setenv("ASM_GITHUB_TOKEN", "t")
    items = [
        gh_item("a/docs", "cli.md", "acme.com\npassword=Sup3rS3cretVal"),                    # docs: generic assignment -> low
        gh_item("a/svc", "tests/fixtures/x.py", "acme.com\npassword=Sup3rS3cretVal"),        # tests -> low
        gh_item("a/real", "docs/setup.md", "acme.com AKIAIOSFODNN7EXAMPLE"),                 # real token format keeps high
        gh_item("a/app", "config/prod.env", "acme.com\npassword=Sup3rS3cretVal"),           # real config stays medium
    ]
    out = {f.key: f.severity for f in GitHubCodeCollector().collect("acme.com", FakeHttp(resp({"items": items})), lambda s: None)}
    assert out == {"a/docs|cli.md": "low", "a/svc|tests/fixtures/x.py": "low",
                   "a/real|docs/setup.md": "high", "a/app|config/prod.env": "medium"}


# ------------------------------------------------------------------ ransomlook (shape recorded from the live API, names replaced)

from backend.exposure.ransomlook import RansomLookCollector  # noqa: E402


def rl_post(title, group="rhysida", desc="x", discovered="2026-10-03 15:50:36.915404"):
    return {"post_title": title, "discovered": discovered, "description": desc, "link": "archive.php?company=281",
            "magnet": "magnet:?xt=urn:btih:abc", "screen": "screenshots/rhysida/x.png", "private": False,
            "misp_uuid": "61861d23", "group_name": group}


RL_NONE = {"groups": [], "markets": [], "posts": [], "leaks": [], "notes": []}


def rl(posts):
    return {"groups": [], "markets": [], "posts": posts, "leaks": [], "notes": []}


def test_ransomlook_matching_rules_and_severity():
    posts = [
        rl_post("acmecorp.com"),                                             # domain in title -> critical
        rl_post("Acmecorp Industries", group="lockbit"),                      # name in title -> high
        rl_post("Some Other Firm", group="akira", desc="supplier to acmecorp.com and others"),   # description -> high
        rl_post("Acmecorpse Ltd", group="play"),                              # not a word-boundary match -> ignored
        rl_post("Unrelated", group="qilin", desc="mentions bank only"),       # keyword noise -> ignored
    ]
    http = FakeHttp(resp(rl(posts)), resp(rl([])))
    out = {f.key: f for f in RansomLookCollector().collect("acmecorp.com", http, lambda s: None)}
    assert set(out) == {"rhysida|acmecorp.com", "lockbit|acmecorp industries", "akira|some other firm"}
    assert out["rhysida|acmecorp.com"].severity == "critical"
    assert out["lockbit|acmecorp industries"].severity == "high"
    assert out["akira|some other firm"].severity == "high"
    assert http.calls[0][1] == {"q": "acmecorp.com"} and http.calls[1][1] == {"q": "acmecorp"}


def test_ransomlook_never_stores_links_or_attachments():
    out = RansomLookCollector().collect("acmecorp.com", FakeHttp(resp(rl([rl_post("acmecorp.com")])), resp(rl([]))), lambda s: None)
    blob = json.dumps([f.__dict__ for f in out])
    for forbidden in ("magnet", "archive.php", "screenshots/", "misp"):
        assert forbidden not in blob
    assert out[0].url == "https://www.ransomlook.io/" and out[0].evidence["credit"].startswith("RansomLook")
    assert out[0].evidence["discovered"] == "2026-10-03"


def test_ransomlook_short_names_only_query_the_domain():
    http = FakeHttp(resp(RL_NONE))
    out = RansomLookCollector().collect("acme.com", http, lambda s: None)
    assert out == [] and len(http.calls) == 1 and out.complete is True


def test_ransomlook_duplicates_across_queries_keep_the_worst_severity():
    a = rl_post("acmecorp.com")
    http = FakeHttp(resp(rl([a])), resp(rl([a])))
    assert len(RansomLookCollector().collect("acmecorp.com", http, lambda s: None)) == 1


def test_ransomlook_oversized_common_name_query_is_skipped_not_fatal():
    http = FakeHttp(resp(rl([rl_post("acmecorp.com")])), CollectorError("response too large"))
    out = RansomLookCollector().collect("acmecorp.com", http, lambda s: None)
    assert len(out) == 1 and out.complete is False
    with pytest.raises(CollectorError):                       # but a failure on the first (domain) query is an error
        RansomLookCollector().collect("acmecorp.com", FakeHttp(CollectorError("response too large")), lambda s: None)


def test_ransomlook_errors_and_garbage():
    c = RansomLookCollector()
    for bad in (resp({}, 500), Response(200, b"<html>", {}), resp({"unexpected": 1})):
        with pytest.raises(CollectorError):
            c.collect("acmecorp.com", FakeHttp(bad), lambda s: None)
    with pytest.raises(RateLimited):
        c.collect("acmecorp.com", FakeHttp(resp({}, 429)), lambda s: None)
    from backend.exposure.base import NotApplicable
    with pytest.raises(NotApplicable):
        c.collect("10.0.0.5", FakeHttp(resp(RL_NONE)), lambda s: None)


# ------------------------------------------------------------------ hudson rock (shape recorded from the live endpoint; personal data never present)

from backend.exposure.hudsonrock import HudsonRockCollector, rate  # noqa: E402

REAL_HR = {"total": 51022, "totalStealers": 47265, "employees": 1022, "users": 50000, "third_parties": 0, "logo": "x",
           "data": [{"url": "https://leak.example/a?token=SECRETVALUE", "type": "employee", "occurrence": 3,
                     "email": "someone@example.com", "password": "hunter2hunter2"}],
           "totalUrls": 13915,
           "stats": {"employees_urls": ["https://auth.services.example.com/login", "ftp://ftp.example.com",
                                          "https://user:pw@evil.example/x"], "clients_urls": []},
           "last_employee_compromised": "2026-09-30T22:04:47.493Z", "last_user_compromised": "2026-09-30T22:20:41.258Z",
           "employeePasswords": {"totalPass": 1022, "too_weak": {"qty": 94, "perc": 9.2}, "weak": {"qty": 610, "perc": 59.69},
                                 "medium": {"qty": 34, "perc": 3.33}, "strong": {"qty": 284, "perc": 27.79}},
           "stealerFamilies": {"total": 50000, "Vidar": 4612, "RedLine": 21706, "Raccoon": 11003, "KPOT": 27, "Azorult": 8917, "Taurus": 406}}
NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def test_hudsonrock_off_until_terms_acknowledged(monkeypatch):
    monkeypatch.delenv("ASM_HUDSONROCK_ACK", raising=False)
    c = HudsonRockCollector()
    assert not c.configured()
    with pytest.raises(CollectorError):
        c.collect("acme.com", FakeHttp(resp(REAL_HR)), lambda s: None)
    monkeypatch.setenv("ASM_HUDSONROCK_ACK", "true")
    assert c.configured()


def test_hudsonrock_real_response_aggregates_only(monkeypatch):
    monkeypatch.setenv("ASM_HUDSONROCK_ACK", "true")
    out = HudsonRockCollector().collect("www.acme.com", FakeHttp(resp(REAL_HR)), lambda s: None, now=NOW)
    assert len(out) == 1
    f = out[0]
    assert f.severity == "critical" and f.kind == "infostealer" and f.url == "https://www.hudsonrock.com/search/domain/acme.com"
    ev = f.evidence
    assert ev["employees"] == 1022 and ev["users"] == 50000 and ev["last_employee_compromised"] == "2026-09-30"
    assert ev["employee_password_strength"] == {"too_weak": 94, "weak": 610, "medium": 34, "strong": 284}
    assert [x["name"] for x in ev["stealer_families"]][:2] == ["RedLine", "Raccoon"]
    assert ev["employee_portal_urls"] == ["https://auth.services.example.com/login"]       # https only, no credentials in URLs
    blob = json.dumps([f.__dict__ for f in out])
    for forbidden in ("someone@example.com", "hunter2hunter2", "SECRETVALUE", "leak.example"):
        assert forbidden not in blob                                                         # per-credential data is never read


def test_hudsonrock_severity_rules():
    assert rate(5, 0, 10, None) == "critical" and rate(5, 0, 100, None) == "high" and rate(5, 0, 900, None) == "medium"
    assert rate(5, 0, None, None) == "medium"
    assert rate(0, 50, None, 30) == "medium" and rate(0, 50, None, 400) == "low" and rate(0, 0, None, None) is None


def test_hudsonrock_clean_domain_and_bad_responses(monkeypatch):
    monkeypatch.setenv("ASM_HUDSONROCK_ACK", "1")
    c = HudsonRockCollector()
    clean = {"total": 0, "employees": 0, "users": 0, "third_parties": 0, "data": [], "stats": {}}
    assert c.collect("acme.com", FakeHttp(resp(clean)), lambda s: None) == []
    for bad in (resp({}, 500), Response(200, b"<html>", {}), resp({"unrelated": 1}), resp([1, 2])):
        with pytest.raises(CollectorError):
            c.collect("acme.com", FakeHttp(bad), lambda s: None)
    with pytest.raises(RateLimited):
        c.collect("acme.com", FakeHttp(resp({}, 429)), lambda s: None)
    from backend.exposure.base import NotApplicable
    with pytest.raises(NotApplicable):
        c.collect("10.1.1.1", FakeHttp(resp(clean)), lambda s: None)


def test_every_source_skips_ip_and_internal_targets_without_a_request():
    import pytest as _pt
    from backend.exposure import registry
    from backend.exposure.base import NotApplicable

    class NoHttp:
        def get(self, *a, **k):
            raise AssertionError("a request was made for an IP target")

    import os
    os.environ["ASM_GITHUB_TOKEN"] = "x"
    os.environ["ASM_HUDSONROCK_ACK"] = "true"
    try:
        for c in registry.all_sources():
            for bad in ("192.168.16.128", "intranet.local", "localhost"):
                with _pt.raises(NotApplicable):
                    c.collect(bad, NoHttp(), lambda s: None)
    finally:
        os.environ.pop("ASM_GITHUB_TOKEN", None)
        os.environ.pop("ASM_HUDSONROCK_ACK", None)
