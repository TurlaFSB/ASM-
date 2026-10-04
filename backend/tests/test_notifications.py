import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import notifications as n
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.alert import Alert
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.models.webhook_delivery import WebhookDelivery


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


class FakeResp:
    def __init__(self, code):
        self.status_code, self.ok = code, 200 <= code < 300


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me", alert_min_severity="medium")
    s.add(t); s.commit()
    s.target = t
    return s


@pytest.fixture()
def posts(monkeypatch):
    """Capture webhook POSTs; skip DNS validation and real sleeping."""
    class Sent(list):
        plan = {"codes": [200]}

    sent = Sent()
    plan = sent.plan

    def fake_post(url, body, headers):
        sent.append({"url": url, "body": body, "headers": headers})
        codes = plan["codes"]
        return FakeResp(codes[min(len(sent) - 1, len(codes) - 1)])

    monkeypatch.setattr(n, "_post", fake_post)
    monkeypatch.setattr("backend.validators.validate_webhook_url", lambda u: u)
    monkeypatch.setattr(n, "WEBHOOK_BACKOFF", 0)
    return sent


def mk_scan(db):
    s = Scan(target_id=db.target.id, status="completed", profile="standard",
             completed_at=datetime.now(timezone.utc))
    db.add(s); db.commit()
    return s


def ev(db, scan, severity="high", category="port", change_type="added", subject="22/tcp", status="confirmed",
       group=None, after=None):
    e = ChangeEvent(target_id=db.target.id, scan_id=scan.id, profile="standard", category=category,
                    change_type=change_type, section="ports", asset="10.0.0.5", subject=subject,
                    severity=severity, confidence="confirmed", status=status, summary=f"{category} {subject} {change_type}",
                    group=group, after=after, fingerprint=f"{category}|{subject}|{change_type}")
    db.add(e); db.commit()
    return e


# ---------------------------------------------------------------- threshold

@pytest.mark.parametrize("sev,minimum,ok", [
    ("critical", "medium", True), ("high", "medium", True), ("medium", "medium", True),
    ("low", "medium", False), ("info", "medium", False), ("info", "info", True),
    ("critical", "critical", True), ("high", "critical", False),
    ("weird", "info", False), (None, "info", False), ("high", "bogus", True), ("low", None, False),
])
def test_threshold(sev, minimum, ok):
    assert n.meets_threshold(sev, minimum) is ok


# ---------------------------------------------------------------- alerts

def test_only_confirmed_events_at_or_above_threshold_alert(db, posts):
    scan = mk_scan(db)
    ev(db, scan, "high", subject="22/tcp")
    ev(db, scan, "low", subject="23/tcp")                        # below threshold
    ev(db, scan, "critical", subject="/flag", category="path", status="pending")   # held removal never notifies
    out = n.notify_scan_changes(db, scan)
    assert out["alerts"] == 1 and out["qualifying"] == 1
    a = db.query(Alert).one()
    assert a.severity == "high" and a.alert_type == "port_added" and a.change_event_id is not None
    assert a.is_read is False


def test_baseline_scan_is_silent(db, posts):
    scan = mk_scan(db)
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    out = n.notify_scan_changes(db, scan)
    assert out["qualifying"] == 0 and db.query(Alert).count() == 0 and posts == []
    assert db.query(WebhookDelivery).count() == 0


def test_idempotent_per_event(db, posts):
    scan = mk_scan(db)
    ev(db, scan, "high")
    n.notify_scan_changes(db, scan)
    out = n.notify_scan_changes(db, scan)
    assert db.query(Alert).count() == 1 and out["alerts"] == 0


def test_per_scan_alert_cap_adds_one_summary_row(db, posts, monkeypatch):
    monkeypatch.setattr(n, "MAX_ALERTS_PER_SCAN", 3)
    scan = mk_scan(db)
    for i in range(7):
        ev(db, scan, "medium", subject=f"{8000 + i}/tcp")
    ev(db, scan, "critical", subject="445/tcp")
    n.notify_scan_changes(db, scan)
    rows = db.query(Alert).all()
    assert len(rows) == 4
    summary = [r for r in rows if r.alert_type == "changes_summary"][0]
    assert summary.detail["omitted"] == 5
    # the most severe event survived the cap
    assert any(r.severity == "critical" for r in rows if r.alert_type != "changes_summary")


def test_threshold_follows_target_setting(db, posts):
    db.target.alert_min_severity = "info"; db.commit()
    scan = mk_scan(db)
    ev(db, scan, "info", subject="/x", category="path", change_type="removed")
    assert n.notify_scan_changes(db, scan)["alerts"] == 1


# ---------------------------------------------------------------- webhook

def test_no_webhook_configured_sends_nothing(db, posts):
    scan = mk_scan(db); ev(db, scan, "high")
    out = n.notify_scan_changes(db, scan)
    assert out["webhook"] == "none" and posts == []


def test_one_digest_per_scan_not_per_event(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    scan = mk_scan(db)
    for i in range(5):
        ev(db, scan, "high", subject=f"{9000 + i}/tcp")
    out = n.notify_scan_changes(db, scan)
    assert out["webhook"] == "sent" and len(posts) == 1
    body = json.loads(posts[0]["body"])
    assert body["event"] == "scan.changes" and body["total"] == 5 and body["counts"] == {"high": 5}
    assert body["scan"]["id"] == scan.id and body["target"]["domain"] == "10.0.0.5"
    d = db.query(WebhookDelivery).one()
    assert d.status == "sent" and d.kind == "digest" and d.event_count == 5 and d.host == "hooks.example"


def test_digest_not_resent_after_success(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    scan = mk_scan(db); ev(db, scan, "high")
    n.notify_scan_changes(db, scan)
    n.notify_scan_changes(db, scan)
    assert len(posts) == 1


def test_signature_is_verifiable(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.target.webhook_secret = "s3cret"; db.commit()
    scan = mk_scan(db); ev(db, scan, "high")
    n.notify_scan_changes(db, scan)
    p = posts[0]
    ts = p["headers"]["X-ASM-Timestamp"]
    want = "sha256=" + hmac.new(b"s3cret", ts.encode() + b"." + p["body"], hashlib.sha256).hexdigest()
    assert p["headers"]["X-ASM-Signature"] == want
    assert p["headers"]["X-ASM-Event"] == "scan.changes"


def test_payload_is_bounded_and_cves_are_rolled_up(db, posts, monkeypatch):
    monkeypatch.setattr(n, "MAX_PAYLOAD_EVENTS", 3)
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    scan = mk_scan(db)
    for i in range(6):
        ev(db, scan, "high", subject=f"{7000 + i}/tcp")
    for i in range(30):                                          # a CVE flood for one component
        ev(db, scan, "high", category="finding", subject=f"cve{i}", group="Apache httpd 2.4.7",
           after={"cve": f"CVE-2017-{1000 + i}", "cvss": 7.5, "kev": i == 0})
    n.notify_scan_changes(db, scan)
    body = json.loads(posts[0]["body"])
    assert body["total"] == 36 and len(body["events"]) == 3 and body["truncated"]["events"] == 3
    assert len(body["cve_rollups"]) == 1
    r = body["cve_rollups"][0]
    assert r["component"] == "Apache httpd 2.4.7" and r["cves"] == 30 and r["kev"] == 1


def test_slack_and_discord_formats(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.target.webhook_format = "slack"; db.commit()
    scan = mk_scan(db); ev(db, scan, "critical", subject="445/tcp")
    n.notify_scan_changes(db, scan)
    body = json.loads(posts[0]["body"])
    assert list(body) == ["text"] and "1 change on 10.0.0.5" in body["text"] and "[critical]" in body["text"]
    assert "X-ASM-Signature" not in posts[0]["headers"]          # chat webhooks cannot verify it

    scan2 = mk_scan(db); ev(db, scan2, "high")
    db.target.webhook_format = "discord"; db.commit()
    n.notify_scan_changes(db, scan2)
    d = json.loads(posts[1]["body"])
    assert set(d) == {"content", "allowed_mentions"} and d["allowed_mentions"] == {"parse": []}


def test_retries_then_succeeds(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    posts.plan["codes"] = [503, 502, 200]
    scan = mk_scan(db); ev(db, scan, "high")
    assert n.notify_scan_changes(db, scan)["webhook"] == "sent"
    assert len(posts) == 3 and db.query(WebhookDelivery).one().attempts == 3


def test_client_error_is_not_retried(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    posts.plan["codes"] = [404]
    scan = mk_scan(db); ev(db, scan, "high")
    assert n.notify_scan_changes(db, scan)["webhook"] == "failed"
    d = db.query(WebhookDelivery).one()
    assert len(posts) == 1 and d.http_status == 404 and d.error == "HTTP 404"


def test_failed_delivery_keeps_alerts_and_can_retry_later(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    posts.plan["codes"] = [500, 500, 500]
    scan = mk_scan(db); ev(db, scan, "high")
    n.notify_scan_changes(db, scan)
    assert db.query(Alert).count() == 1 and db.query(WebhookDelivery).one().status == "failed"
    posts.plan["codes"] = [200]
    posts.clear()
    assert n.notify_scan_changes(db, scan)["webhook"] == "sent"
    assert db.query(Alert).count() == 1


def test_blocked_url_is_recorded_not_sent(db, monkeypatch):
    sent = []
    monkeypatch.setattr(n, "_post", lambda *a, **k: sent.append(1))
    db.target.webhook_url = "http://169.254.169.254/latest"; db.commit()
    scan = mk_scan(db); ev(db, scan, "high")
    assert n.notify_scan_changes(db, scan)["webhook"] == "blocked"
    assert sent == [] and "https" in db.query(WebhookDelivery).one().error


def test_network_exception_is_contained(db, monkeypatch):
    monkeypatch.setattr("backend.validators.validate_webhook_url", lambda u: u)
    monkeypatch.setattr(n, "WEBHOOK_BACKOFF", 0)

    def boom(*a, **k):
        raise ConnectionError("down")

    monkeypatch.setattr(n, "_post", boom)
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    scan = mk_scan(db); ev(db, scan, "high")
    assert n.notify_scan_changes(db, scan)["webhook"] == "failed"
    assert db.query(Alert).count() == 1


# ---------------------------------------------------------------- API

@pytest.fixture()
def client(db, monkeypatch):
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: type("U", (), {"username": "tester"})()
    monkeypatch.setattr("backend.validators.validate_webhook_url", lambda u: u if u.startswith("https://") else (_ for _ in ()).throw(ValueError("Webhook URL must be https")))
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_settings_defaults_hide_secret(client, db):
    r = client.get(f"/targets/{db.target.id}/notifications").json()
    assert r == {"target_id": db.target.id, "alert_min_severity": "medium", "webhook_configured": False,
                 "webhook_host": None, "webhook_format": "json", "has_secret": False,
                 "email_recipients": [], "smtp_configured": False}


def test_set_webhook_generates_secret_once(client, db):
    tid = db.target.id
    r = client.put(f"/targets/{tid}/notifications",
                   json={"webhook_url": "https://hooks.example/abc?token=zzz", "webhook_format": "json",
                         "alert_min_severity": "high"}).json()
    assert r["webhook_secret"] and r["webhook_host"] == "hooks.example" and r["alert_min_severity"] == "high"
    first = r["webhook_secret"]
    again = client.get(f"/targets/{tid}/notifications").json()
    assert "webhook_secret" not in again and again["has_secret"] is True
    assert "token=zzz" not in json.dumps(again)                  # the URL itself is never echoed back
    # saving again keeps the secret; rotating replaces it
    keep = client.put(f"/targets/{tid}/notifications", json={"webhook_url": "https://hooks.example/abc"}).json()
    assert "webhook_secret" not in keep and db.query(Target).get(tid).webhook_secret == first
    rot = client.put(f"/targets/{tid}/notifications",
                     json={"webhook_url": "https://hooks.example/abc", "rotate_secret": True}).json()
    assert rot["webhook_secret"] and rot["webhook_secret"] != first


def test_clear_webhook_removes_secret(client, db):
    tid = db.target.id
    client.put(f"/targets/{tid}/notifications", json={"webhook_url": "https://hooks.example/abc"})
    r = client.put(f"/targets/{tid}/notifications", json={"webhook_url": ""}).json()
    assert r["webhook_configured"] is False and r["has_secret"] is False


def test_omitting_url_keeps_webhook_and_changes_other_settings(client, db):
    tid = db.target.id
    client.put(f"/targets/{tid}/notifications", json={"webhook_url": "https://hooks.example/abc"})
    r = client.put(f"/targets/{tid}/notifications", json={"alert_min_severity": "critical", "webhook_format": "slack"}).json()
    assert r["webhook_configured"] is True and r["has_secret"] is True
    assert r["alert_min_severity"] == "critical" and r["webhook_format"] == "slack"
    rot = client.put(f"/targets/{tid}/notifications", json={"rotate_secret": True}).json()
    assert rot["webhook_secret"]
    assert client.put(f"/targets/{tid}/notifications", json={"webhook_url": ""}).json()["webhook_configured"] is False


@pytest.mark.parametrize("body", [
    {"webhook_url": "http://hooks.example/x"},
    {"webhook_url": "https://hooks.example/x", "webhook_format": "teams"},
    {"alert_min_severity": "urgent"},
])
def test_settings_validation(client, db, body):
    assert client.put(f"/targets/{db.target.id}/notifications", json=body).status_code == 422


def test_test_webhook_endpoint(client, db, posts):
    tid = db.target.id
    assert client.post(f"/targets/{tid}/notifications/test").status_code == 422     # nothing configured
    client.put(f"/targets/{tid}/notifications", json={"webhook_url": "https://hooks.example/abc"})
    r = client.post(f"/targets/{tid}/notifications/test").json()
    assert r["status"] == "sent" and json.loads(posts[0]["body"])["event"] == "webhook.test"
    assert db.query(WebhookDelivery).one().kind == "test"


def test_alert_list_filters_by_severity_and_lists_deliveries(client, db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.commit()
    scan = mk_scan(db)
    ev(db, scan, "critical", subject="445/tcp"); ev(db, scan, "medium", subject="8080/tcp")
    n.notify_scan_changes(db, scan)
    assert len(client.get("/alerts/").json()) == 2
    only = client.get("/alerts/?severity=critical").json()
    assert [a["severity"] for a in only] == ["critical"] and only[0]["summary"]
    d = client.get("/alerts/deliveries").json()
    assert d[0]["status"] == "sent" and d[0]["host"] == "hooks.example" and "url" not in d[0]


# ---------------------------------------------------------------- hardening

def test_error_label_never_contains_the_url(db, monkeypatch):
    import requests
    monkeypatch.setattr("backend.validators.validate_webhook_url", lambda u: u)
    monkeypatch.setattr(n, "WEBHOOK_BACKOFF", 0)

    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("HTTPSConnectionPool: Max retries exceeded with url: /services/T0/B0/SECRETTOKEN")

    monkeypatch.setattr(n, "_post", boom)
    db.target.webhook_url = "https://hooks.example/services/T0/B0/SECRETTOKEN"; db.commit()
    scan = mk_scan(db); ev(db, scan, "high")
    n.notify_scan_changes(db, scan)
    err = db.query(WebhookDelivery).one().error
    assert err == "connection error" and "SECRETTOKEN" not in err


def test_slack_text_is_defanged(db, posts):
    db.target.webhook_url = "https://hooks.example/x"; db.target.webhook_format = "slack"; db.commit()
    scan = mk_scan(db)
    e = ev(db, scan, "critical", subject="/x", category="path")
    e.summary = "Path <!channel> <http://evil|click> reachable"; db.commit()
    n.notify_scan_changes(db, scan)
    text = json.loads(posts[0]["body"])["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text


@pytest.mark.parametrize("ip", ["100.64.0.1", "10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1"])
def test_webhook_rejects_non_global_addresses(monkeypatch, ip):
    import socket
    from backend.validators import validate_webhook_url
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (ip, 443))])
    with pytest.raises(ValueError):
        validate_webhook_url("https://hooks.example/x")


def test_target_list_never_exposes_webhook_credentials(client, db):
    tid = db.target.id
    client.put(f"/targets/{tid}/notifications", json={"webhook_url": "https://hooks.example/abc?token=zzz"})
    for body in (client.get("/targets/").json()[0], client.get(f"/targets/{tid}").json()):
        text = json.dumps(body)
        assert "webhook_secret" not in text and "webhook_url" not in text and "token=zzz" not in text
