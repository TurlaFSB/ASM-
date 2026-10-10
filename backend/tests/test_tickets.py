"""Ticketing: who gets a ticket, never twice, retries, caps, credentials and text hygiene."""
import json
from datetime import datetime, timezone

import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import tickets as tk
from backend.auth import get_current_user, require_admin
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.models.ticket import Ticket


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


class Resp:
    def __init__(self, code, data=None):
        self.status_code, self._d = code, data

    def json(self):
        if self._d is None:
            raise ValueError("no json")
        return self._d


class FakeHttp:
    """Records calls; `plan` is a list of Resp (or exceptions) consumed in order, the last one repeats."""
    def __init__(self, *plan):
        self.plan, self.calls = list(plan), []

    def _next(self, method, url, kw):
        self.calls.append((method, url, kw))
        r = self.plan.pop(0) if len(self.plan) > 1 else self.plan[0]
        if isinstance(r, Exception):
            raise r
        return r

    def post(self, url, **kw):
        return self._next("post", url, kw)

    def get(self, url, **kw):
        return self._next("get", url, kw)


GH_OK = Resp(201, {"number": 7, "html_url": "https://github.com/acme/sec/issues/7"})


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("ASM_TICKETS_PROVIDER", "github")
    monkeypatch.setenv("ASM_TICKETS_GITHUB_TOKEN", "ghp_SECRETTOKEN123")
    for k in ("ASM_JIRA_URL", "ASM_JIRA_EMAIL", "ASM_JIRA_TOKEN", "ASM_PUBLIC_URL", "ASM_TICKETS_MAX_PER_SCAN"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="acme.com", authorized=True, authorized_by="me", ticket_destination="acme/sec", ticket_min_severity="high")
    s.add(t); s.commit()
    s.target = t
    return s


def scan(db):
    s = Scan(target_id=db.target.id, status="completed", profile="standard", completed_at=datetime.now(timezone.utc))
    db.add(s); db.commit()
    return s


def ev(db, sc, severity="high", subject="22/tcp", change_type="added", status="confirmed", summary=None, **kw):
    e = ChangeEvent(target_id=db.target.id, scan_id=sc.id, profile="standard", category="finding", change_type=change_type,
                    section="findings", asset="www.acme.com", subject=subject, severity=severity, confidence="confirmed",
                    status=status, summary=summary or f"finding {subject}", fingerprint=f"finding|{subject}|{change_type}", **kw)
    db.add(e); db.commit()
    return e


def run(db, sc, http, **kw):
    return tk.create_for_scan(db, sc, http=http, sleep=lambda s: None, **kw)


def test_opens_one_ticket_for_a_qualifying_event(db):
    sc = scan(db); ev(db, sc)
    http = FakeHttp(GH_OK)
    out = run(db, sc, http)
    assert out == {"status": "ok", "created": 1, "failed": 0, "omitted": 0}
    method, url, kw = http.calls[0]
    assert url == "https://api.github.com/repos/acme/sec/issues"
    assert kw["json"]["labels"] == ["asm", "severity:high"] and kw["json"]["title"].startswith("[ASM] High:")
    row = db.query(Ticket).one()
    assert (row.status, row.external_key, row.url) == ("created", "#7", "https://github.com/acme/sec/issues/7")


def test_only_confirmed_added_events_at_or_above_threshold(db):
    sc = scan(db)
    ev(db, sc, severity="medium", subject="a")
    ev(db, sc, severity="high", subject="b", change_type="removed")
    ev(db, sc, severity="critical", subject="c", status="pending")
    ev(db, sc, severity="critical", subject="d")
    http = FakeHttp(GH_OK)
    assert run(db, sc, http)["created"] == 1
    assert db.query(Ticket).one().fingerprint == "finding|d|added"


def test_threshold_follows_the_target(db):
    db.target.ticket_min_severity = "medium"; db.commit()
    sc = scan(db); ev(db, sc, severity="medium")
    assert run(db, sc, FakeHttp(GH_OK))["created"] == 1


def test_never_twice_even_across_scans_and_retries(db):
    s1 = scan(db); ev(db, s1)
    run(db, s1, FakeHttp(GH_OK))
    run(db, s1, FakeHttp(GH_OK))                       # the same task delivered again
    s2 = scan(db); ev(db, s2)                          # a later scan reports the same fingerprint
    http = FakeHttp(GH_OK)
    assert run(db, s2, http)["created"] == 0 and http.calls == []
    assert db.query(Ticket).count() == 1


def test_failed_attempt_is_kept_and_retried_on_the_next_scan(db):
    s1 = scan(db); ev(db, s1)
    out = run(db, s1, FakeHttp(Resp(500)))
    assert out["failed"] == 1
    row = db.query(Ticket).one()
    assert row.status == "failed" and row.attempts == 1 and "HTTP 500" in row.error
    s2 = scan(db)
    out = run(db, s2, FakeHttp(GH_OK))
    assert out["created"] == 1
    db.refresh(row)
    assert row.status == "created" and row.attempts == 2 and row.error is None


def test_gives_up_after_the_attempt_limit(db):
    sc = scan(db); ev(db, sc)
    run(db, sc, FakeHttp(Resp(500)))
    for _ in range(tk.MAX_ATTEMPTS + 2):
        run(db, scan(db), FakeHttp(Resp(500)))
    assert db.query(Ticket).one().attempts == tk.MAX_ATTEMPTS


def test_per_scan_cap_and_overflow_is_counted(db, monkeypatch):
    monkeypatch.setenv("ASM_TICKETS_MAX_PER_SCAN", "2")
    sc = scan(db)
    for i, sev in enumerate(["high", "critical", "high", "high"]):
        ev(db, sc, severity=sev, subject=f"s{i}")
    http = FakeHttp(GH_OK)
    out = run(db, sc, http)
    assert (out["created"], out["omitted"]) == (2, 2)
    assert db.query(Ticket).filter(Ticket.severity == "critical").count() == 1      # most severe first


def test_off_without_destination_provider_or_credentials(db, monkeypatch):
    sc = scan(db); ev(db, sc)
    http = FakeHttp(GH_OK)
    monkeypatch.setenv("ASM_TICKETS_PROVIDER", "")
    assert run(db, sc, http)["status"] == "off"
    monkeypatch.setenv("ASM_TICKETS_PROVIDER", "github")
    monkeypatch.delenv("ASM_TICKETS_GITHUB_TOKEN")
    assert run(db, sc, http)["status"] == "not configured"
    monkeypatch.setenv("ASM_TICKETS_GITHUB_TOKEN", "x")
    db.target.ticket_destination = None; db.commit()
    assert run(db, sc, http)["status"] == "off"
    assert http.calls == [] and db.query(Ticket).count() == 0


@pytest.mark.parametrize("exc,label", [(requests.exceptions.Timeout("u"), "timeout"),
                                       (requests.exceptions.SSLError("u"), "tls error"),
                                       (requests.exceptions.ConnectionError("https://api.github.com ghp_SECRETTOKEN123"), "connection error")])
def test_network_errors_are_labelled_and_leak_nothing(db, exc, label):
    sc = scan(db); ev(db, sc)
    run(db, sc, FakeHttp(exc))
    row = db.query(Ticket).one()
    assert row.error == label and "ghp_" not in row.error and "github.com" not in row.error


@pytest.mark.parametrize("code,expect", [(401, "rejected the credentials"), (403, "refused access"), (404, "not found"),
                                         (422, "refused the ticket"), (429, "rate limit")])
def test_http_errors_map_to_readable_labels(db, code, expect):
    sc = scan(db); ev(db, sc)
    run(db, sc, FakeHttp(Resp(code)))
    assert expect in db.query(Ticket).one().error


def test_link_that_is_not_a_github_https_url_is_refused(db):
    sc = scan(db); ev(db, sc)
    run(db, sc, FakeHttp(Resp(201, {"number": 1, "html_url": "javascript:alert(1)"})))
    row = db.query(Ticket).one()
    assert row.status == "failed" and row.url is None


def test_odd_success_body_is_a_failure_not_a_crash(db):
    sc = scan(db); ev(db, sc)
    run(db, sc, FakeHttp(Resp(201, {"unexpected": True})))
    assert db.query(Ticket).one().status == "failed"


def test_text_from_the_target_cannot_ping_people_or_smuggle_controls(db):
    sc = scan(db)
    ev(db, sc, summary="Title says @everyone and @octocat ‮\x00 evil", ai_summary="Look at @admin", ai_action="Fix it")
    http = FakeHttp(GH_OK)
    run(db, sc, http)
    sent = http.calls[0][2]["json"]
    blob = sent["title"] + sent["body"]
    assert "@everyone" not in blob and "@octocat" not in blob and "@admin" not in blob
    assert "‮" not in blob and "\x00" not in blob
    assert "Suggested action: Fix it" in sent["body"]


def test_token_goes_only_in_the_header(db):
    sc = scan(db); ev(db, sc)
    http = FakeHttp(GH_OK)
    run(db, sc, http)
    kw = http.calls[0][2]
    assert kw["headers"]["Authorization"] == "Bearer ghp_SECRETTOKEN123"
    assert "ghp_" not in json.dumps(kw["json"]) and kw["allow_redirects"] is False


def test_public_link_in_body_only_when_set(db, monkeypatch):
    sc = scan(db); ev(db, sc)
    http = FakeHttp(GH_OK)
    run(db, sc, http)
    assert "Details:" not in http.calls[0][2]["json"]["body"]
    monkeypatch.setenv("ASM_PUBLIC_URL", "https://asm.example.com/")
    ev(db, sc, subject="other")
    run(db, sc, http)
    assert "https://asm.example.com/changes" in http.calls[-1][2]["json"]["body"]


# ----------------------------------------------------------------------- Jira

@pytest.fixture()
def jira(monkeypatch):
    monkeypatch.setenv("ASM_TICKETS_PROVIDER", "jira")
    monkeypatch.setenv("ASM_JIRA_URL", "https://acme.atlassian.net/")
    monkeypatch.setenv("ASM_JIRA_EMAIL", "bot@acme.com")
    monkeypatch.setenv("ASM_JIRA_TOKEN", "jira-secret")


def test_jira_issue_payload_and_link(db, jira):
    db.target.ticket_destination = "SEC"; db.commit()
    sc = scan(db); ev(db, sc)
    http = FakeHttp(Resp(201, {"key": "SEC-45"}))
    assert run(db, sc, http)["created"] == 1
    _, url, kw = http.calls[0]
    assert url == "https://acme.atlassian.net/rest/api/3/issue" and kw["auth"] == ("bot@acme.com", "jira-secret")
    f = kw["json"]["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Task"} and f["description"]["type"] == "doc"
    assert db.query(Ticket).one().url == "https://acme.atlassian.net/browse/SEC-45"


def test_jira_needs_https_and_all_settings(monkeypatch, jira):
    assert tk.missing_settings("jira") == []
    monkeypatch.setenv("ASM_JIRA_URL", "http://acme.atlassian.net")
    assert "https" in tk.missing_settings("jira")[0]
    monkeypatch.setenv("ASM_JIRA_URL", "https://acme.atlassian.net")
    monkeypatch.delenv("ASM_JIRA_TOKEN")
    assert tk.missing_settings("jira") == ["ASM_JIRA_TOKEN"]


# ----------------------------------------------------------------------- destinations and API

@pytest.mark.parametrize("provider,value,ok", [
    ("github", "acme/sec", True), ("github", "acme", False), ("github", "a/b/c", False), ("github", "acme/sec space", False),
    ("github", "../x/y", False), ("github", "acme/..", False), ("github", "acme/.github", True), ("jira", "sec", True), ("jira", "S", False), ("jira", "SEC-1", False), ("jira", "ACME/SEC", False),
])
def test_destination_validation(provider, value, ok):
    if ok:
        assert tk.validate_destination(provider, value)
    else:
        with pytest.raises(ValueError):
            tk.validate_destination(provider, value)


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: (yield db)
    user = type("U", (), {"username": "tester", "role": "admin"})()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_admin] = lambda: user
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_api_view_never_contains_credentials(client, db):
    sc = scan(db); ev(db, sc); run(db, sc, FakeHttp(GH_OK))
    r = client.get(f"/targets/{db.target.id}/ticketing")
    body = r.json()
    assert body["provider"] == "github" and body["configured"] is True and body["destination"] == "acme/sec"
    assert body["recent"][0]["key"] == "#7"
    assert "ghp_" not in r.text


def test_api_update_validates_and_can_switch_off(client, db):
    tid = db.target.id
    assert client.put(f"/targets/{tid}/ticketing", json={"destination": "not valid"}).status_code == 422
    r = client.put(f"/targets/{tid}/ticketing", json={"destination": "acme/other", "min_severity": "critical"}).json()
    assert r["destination"] == "acme/other" and r["min_severity"] == "critical"
    assert client.put(f"/targets/{tid}/ticketing", json={"min_severity": "nope"}).status_code == 422
    assert client.put(f"/targets/{tid}/ticketing", json={"destination": ""}).json()["destination"] is None


def test_api_refuses_destination_when_server_is_not_set_up(client, db, monkeypatch):
    monkeypatch.setenv("ASM_TICKETS_PROVIDER", "")
    r = client.put(f"/targets/{db.target.id}/ticketing", json={"destination": "acme/sec"})
    assert r.status_code == 422 and "ASM_TICKETS_PROVIDER" in r.json()["detail"]


def test_api_check_connection_is_read_only(client, db, monkeypatch):
    import backend.tickets as mod
    fake = FakeHttp(Resp(200, {"has_issues": True}))
    monkeypatch.setattr("requests.get", fake.get)
    monkeypatch.setattr("requests.post", fake.post)
    r = client.post(f"/targets/{db.target.id}/ticketing/check").json()
    assert r["ok"] is True and fake.calls[0][0] == "get" and len(fake.calls) == 1
    fake2 = FakeHttp(Resp(404))
    monkeypatch.setattr("requests.get", fake2.get)
    r = client.post(f"/targets/{db.target.id}/ticketing/check").json()
    assert r["ok"] is False and "not found" in r["message"]
