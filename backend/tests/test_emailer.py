import smtplib
from types import SimpleNamespace

import pytest

from backend import emailer
from backend.models import Target
from backend.models.webhook_delivery import WebhookDelivery
from backend.tests.test_notifications import db, client, mk_scan, ev, posts  # noqa: F401 (fixtures)
from backend import notifications as n


@pytest.fixture()
def smtp(monkeypatch):
    """Configure SMTP and capture what would be sent instead of opening a socket."""
    monkeypatch.setenv("ASM_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("ASM_SMTP_FROM", "asm@example.com")
    monkeypatch.setenv("ASM_PUBLIC_URL", "https://asm.example.com")
    box = SimpleNamespace(messages=[], fail=None, calls=0)

    def fake_send(msg, cfg):
        box.calls += 1
        if box.fail:
            raise box.fail
        box.messages.append(msg)

    monkeypatch.setattr(emailer, "_send", fake_send)
    return box


def with_recipients(db, *addrs):
    db.target.email_recipients = list(addrs) or ["sec@example.com"]
    db.commit()


# ---------------------------------------------------------------- validation

def test_recipients_are_normalised_and_deduplicated():
    assert emailer.validate_recipients([" Sec@Example.com ", "sec@example.com", "", "b@x.io"]) == ["sec@example.com", "b@x.io"]
    assert emailer.validate_recipients(None) == []


@pytest.mark.parametrize("bad", ["nope", "a@b", "a b@c.io", "a@b.io\nBcc: x@y.io", "@c.io", "a@@c.io", "x" * 260 + "@c.io"])
def test_invalid_recipients_rejected(bad):
    with pytest.raises(ValueError):
        emailer.validate_recipients([bad])


def test_recipient_cap():
    with pytest.raises(ValueError):
        emailer.validate_recipients([f"u{i}@c.io" for i in range(emailer.MAX_RECIPIENTS + 1)])


# ---------------------------------------------------------------- messages

def test_header_injection_is_neutralised():
    msg = emailer.build_message("Hi\r\nBcc: evil@x.io", "t", "<p>t</p>", ["a@b.io"], "asm@example.com")
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None


def test_html_escapes_scan_derived_text(db, smtp):
    scan = mk_scan(db)
    e = ev(db, scan, severity="high")
    e.summary = '<script>alert(1)</script> & "x"'
    db.commit()
    d = n.build_digest(db.target, scan, [n._view(e)])
    subject, text, html = emailer.render_scan_email(d)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<script>" in text                                   # plain text is not markup, kept verbatim
    assert "[ASM] 1 change on 10.0.0.5" in subject
    assert 'href="https://asm.example.com/changes"' in html


def test_link_only_with_http_public_url(monkeypatch):
    monkeypatch.setenv("ASM_PUBLIC_URL", "javascript:alert(1)")
    assert emailer._link("changes") is None


# ---------------------------------------------------------------- delivery

def test_digest_emailed_once_per_scan(db, smtp):
    with_recipients(db, "a@example.com", "b@example.com")
    scan = mk_scan(db)
    ev(db, scan, severity="high")
    out = n.notify_scan_changes(db, scan, sleep=lambda s: None)
    assert out["email"] == "sent" and len(smtp.messages) == 1
    assert smtp.messages[0]["To"] == "a@example.com, b@example.com"
    assert smtp.messages[0].get_body(("html",)) is not None
    n.notify_scan_changes(db, scan, sleep=lambda s: None)          # task retry
    assert len(smtp.messages) == 1
    rec = db.query(WebhookDelivery).filter_by(kind="email_digest").one()
    assert rec.status == "sent" and rec.host == "smtp.example.com" and rec.event_count == 1


def test_quiet_scan_sends_no_mail(db, smtp):
    with_recipients(db)
    scan = mk_scan(db)
    ev(db, scan, severity="low")                                  # below the target's "medium" threshold
    n.notify_scan_changes(db, scan, sleep=lambda s: None)
    assert smtp.messages == []


def test_no_recipients_or_no_smtp_sends_nothing(db, smtp, monkeypatch):
    scan = mk_scan(db)
    ev(db, scan, severity="high")
    n.notify_scan_changes(db, scan, sleep=lambda s: None)
    assert smtp.messages == []
    with_recipients(db)
    monkeypatch.delenv("ASM_SMTP_HOST")
    scan2 = mk_scan(db)
    ev(db, scan2, severity="high")
    n.notify_scan_changes(db, scan2, sleep=lambda s: None)
    assert smtp.messages == []


def test_email_failure_is_recorded_and_contained(db, smtp):
    with_recipients(db)
    smtp.fail = smtplib.SMTPDataError(451, b"try later secret-pass@x")
    scan = mk_scan(db)
    ev(db, scan, severity="high")
    out = n.notify_scan_changes(db, scan, sleep=lambda s: None)
    assert out["email"] == "failed" and smtp.calls == 2           # one retry
    rec = db.query(WebhookDelivery).filter_by(kind="email_digest").one()
    assert rec.error == "smtp error" and "secret" not in rec.error
    from backend.models.alert import Alert
    assert db.query(Alert).count() == 1                           # in-app alerts unaffected


def test_auth_failure_is_not_retried(db, smtp):
    with_recipients(db)
    smtp.fail = smtplib.SMTPAuthenticationError(535, b"bad credentials")
    rec = emailer.send_test_email(db, db.target, sleep=lambda s: None)
    assert rec.status == "failed" and rec.error == "authentication failed" and smtp.calls == 1


def test_webhook_and_email_independent(db, smtp, posts):
    with_recipients(db)
    db.target.webhook_url = "https://hooks.example/abc"
    db.commit()
    smtp.fail = smtplib.SMTPDataError(451, b"down")
    scan = mk_scan(db)
    ev(db, scan, severity="high")
    out = n.notify_scan_changes(db, scan, sleep=lambda s: None)
    assert out["webhook"] == "sent" and out["email"] == "failed"


def test_exposure_digest_emailed(db, smtp):
    from backend.exposure.notify import notify_exposure
    from backend.models.exposure import ExposureFinding
    with_recipients(db)
    f = ExposureFinding(target_id=db.target.id, source="github_code", kind="leak", severity="high",
                        title="Key in repo <b>x</b>", summary="s", url="https://github.com/x/y", fingerprint="fp1")
    db.add(f); db.commit()
    out = notify_exposure(db, db.target, [(f, "new")], sleep=lambda s: None)
    assert out["email"] == "sent"
    html = smtp.messages[0].get_body(("html",)).get_content()
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
    assert db.query(WebhookDelivery).filter_by(kind="email_exposure").count() == 1


# ---------------------------------------------------------------- API

def test_api_recipients_roundtrip_and_validation(client, db, smtp):
    tid = db.target.id
    r = client.put(f"/targets/{tid}/notifications", json={"email_recipients": ["A@Example.com", "a@example.com"]}).json()
    assert r["email_recipients"] == ["a@example.com"] and r["smtp_configured"] is True
    assert client.put(f"/targets/{tid}/notifications", json={"alert_min_severity": "high"}).json()["email_recipients"] == ["a@example.com"]
    assert client.put(f"/targets/{tid}/notifications", json={"email_recipients": ["bad"]}).status_code == 422
    assert client.put(f"/targets/{tid}/notifications", json={"email_recipients": []}).json()["email_recipients"] == []


def test_api_test_email(client, db, smtp, monkeypatch):
    tid = db.target.id
    assert client.post(f"/targets/{tid}/notifications/test-email").status_code == 422     # no recipients yet
    with_recipients(db)
    r = client.post(f"/targets/{tid}/notifications/test-email").json()
    assert r["status"] == "sent" and len(smtp.messages) == 1
    monkeypatch.delenv("ASM_SMTP_HOST")
    assert client.post(f"/targets/{tid}/notifications/test-email").status_code == 422


def test_real_smtp_transaction_over_a_local_server(db, monkeypatch):
    """End to end against a real in-process SMTP server (no TLS, no auth)."""
    import asyncio, threading
    from aiosmtpd.controller import Controller
    got = []

    class H:
        async def handle_DATA(self, server, session, envelope):
            got.append(envelope)
            return "250 OK"

    import socket
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    ctl = Controller(H(), hostname="127.0.0.1", port=free)
    ctl.start()
    try:
        monkeypatch.setenv("ASM_SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("ASM_SMTP_PORT", str(free))
        monkeypatch.setenv("ASM_SMTP_SECURITY", "none")
        monkeypatch.setenv("ASM_SMTP_FROM", "asm@example.com")
        with_recipients(db, "r@example.com")
        rec = emailer.send_test_email(db, db.target, sleep=lambda s: None)
        assert rec.status == "sent"
        assert got and got[0].rcpt_tos == ["r@example.com"]
    finally:
        ctl.stop()
