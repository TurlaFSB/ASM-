"""Email notifications: the same confirmed-change and exposure digests the webhook gets, by SMTP.

Design rules (mirroring notifications.py):
  * The mail server is a deployment setting (ASM_SMTP_* environment variables), never per-target and never
    stored in the database. Per-target config is only the recipient list.
  * ONE message per scan or exposure run, never one per event. Bodies are bounded.
  * Every value that came from a scan (hostnames, titles, summaries) is untrusted: the HTML part escapes it,
    and header values are stripped of line breaks so a hostile title cannot inject headers.
  * Every outcome is recorded in webhook_deliveries (kind email_digest | email_exposure | email_test) with the
    SMTP host as the label. Credentials and recipient addresses are never logged or stored in that row.
  * Nothing here may raise into the scan pipeline.
"""
import logging
import os
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.models.target import Target
from backend.models.webhook_delivery import WebhookDelivery

logger = logging.getLogger(__name__)

MAX_RECIPIENTS = 10
SECURITY_MODES = ("starttls", "ssl", "none")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


# --------------------------------------------------------------------------- configuration

def smtp_settings() -> Dict:
    """Read at call time so a changed environment (or a test) takes effect without a restart of this module."""
    security = os.getenv("ASM_SMTP_SECURITY", "starttls").strip().lower()
    if security not in SECURITY_MODES:
        security = "starttls"
    default_port = {"ssl": 465, "starttls": 587, "none": 25}[security]
    try:
        port = int(os.getenv("ASM_SMTP_PORT", "") or default_port)
    except ValueError:
        port = default_port
    try:
        timeout = float(os.getenv("ASM_SMTP_TIMEOUT", "10"))
    except ValueError:
        timeout = 10.0
    return {
        "host": os.getenv("ASM_SMTP_HOST", "").strip(), "port": port, "security": security,
        "user": os.getenv("ASM_SMTP_USER", ""), "password": os.getenv("ASM_SMTP_PASSWORD", ""),
        "sender": os.getenv("ASM_SMTP_FROM", "").strip(), "timeout": timeout,
        "public_url": os.getenv("ASM_PUBLIC_URL", "").strip().rstrip("/"),
    }


def smtp_configured() -> bool:
    s = smtp_settings()
    return bool(s["host"] and s["sender"])


def validate_recipients(values) -> List[str]:
    """Normalise a recipient list: trimmed, lower-cased, de-duplicated, syntactically valid, at most 10.
    Raises ValueError with a message the user can act on."""
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise ValueError("recipients must be a list of email addresses")
    out: List[str] = []
    for raw in values:
        addr = str(raw or "").strip().lower()
        if not addr:
            continue
        if len(addr) > 254 or not _EMAIL_RE.match(addr):
            raise ValueError(f"'{str(raw)[:60]}' is not a valid email address")
        if addr not in out:
            out.append(addr)
    if len(out) > MAX_RECIPIENTS:
        raise ValueError(f"at most {MAX_RECIPIENTS} recipients per target")
    return out


# --------------------------------------------------------------------------- message building

def _header(value: str, limit: int = 200) -> str:
    """Header values are single-line: drop CR/LF and other control characters."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()[:limit]


def build_message(subject: str, text: str, html: str, recipients: List[str], sender: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = _header(subject)
    msg["From"] = _header(sender)
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(sender.rsplit("@", 1)[-1] or "asm.local"))
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


_SEV_COLOR = {"critical": "#b42318", "high": "#b54708", "medium": "#8a6d00", "low": "#175cd3", "info": "#475467"}


def _page(title: str, intro: str, rows: List[Tuple[str, str]], footer: str, link: Optional[Tuple[str, str]]) -> str:
    """Small inline-styled HTML (mail clients ignore stylesheets). Every dynamic string is escaped."""
    body = "".join(
        f'<tr><td style="padding:6px 10px 6px 0;vertical-align:top;white-space:nowrap">'
        f'<b style="color:{_SEV_COLOR.get(sev, "#475467")}">{escape(sev)}</b></td>'
        f'<td style="padding:6px 0">{escape(line)}</td></tr>' for sev, line in rows)
    cta = (f'<p><a href="{escape(link[0], quote=True)}" style="color:#175cd3">{escape(link[1])}</a></p>' if link else "")
    return (f'<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;color:#101828;font-size:14px;line-height:1.5">'
            f'<h2 style="margin:0 0 8px;font-size:17px">{escape(title)}</h2><p style="margin:0 0 12px">{escape(intro)}</p>'
            f'<table style="border-collapse:collapse">{body}</table>{cta}'
            f'<p style="color:#667085;font-size:12px;margin-top:20px">{escape(footer)}</p></body></html>')


def _link(path: str) -> Optional[Tuple[str, str]]:
    base = smtp_settings()["public_url"]
    return (f"{base}/{path}", "Open in ASM Platform") if base.startswith(("http://", "https://")) else None


FOOTER = "You get this because this address is on the target's notification list. Change it under the target's Notifications settings."


def render_scan_email(d: Dict) -> Tuple[str, str, str]:
    """(subject, text, html) for a scan.changes digest built by notifications.build_digest."""
    total, domain, sid = d["total"], d["target"]["domain"], d["scan"]["id"]
    order = ", ".join(f"{n} {s}" for s, n in d["counts"].items())
    subject = f"[ASM] {total} change{'s' if total != 1 else ''} on {domain}: {order}"
    rows = [(e["severity"], e["summary"] + (f" Suggested action: {e['ai_action']}" if e.get("ai_action") else ""))
            for e in d["events"]]
    for r in d["cve_rollups"]:
        kev = f", {r['kev']} actively exploited" if r["kev"] else ""
        rows.append((r["severity"], f"{r['cves']} CVEs {r['change_type']} for {r['component']} on {r['asset']}{kev}"))
    hidden = d["truncated"]["events"]
    if hidden:
        rows.append(("info", f"...and {hidden} more. Open the Changes page for the full list."))
    intro = f"Scan #{sid} confirmed {total} change{'s' if total != 1 else ''} on {domain} at or above {d['min_severity']} severity."
    text = "\n".join([intro, ""] + [f"[{s}] {line}" for s, line in rows] + ["", FOOTER])
    return subject, text, _page(f"{domain}: {total} change{'s' if total != 1 else ''}", intro, rows, FOOTER, _link("changes"))


def render_exposure_email(target: Target, items) -> Tuple[str, str, str]:
    """items: (ExposureFinding, reason) pairs, already filtered by severity."""
    from backend.rollup import sev_rank
    ordered = sorted(items, key=lambda x: (sev_rank(x[0].severity), x[0].id))
    n = len(ordered)
    counts: Dict[str, int] = {}
    for f, _ in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ", ".join(f"{c} {s}" for s, c in counts.items())
    subject = f"[ASM] {n} new exposure finding{'s' if n != 1 else ''} for {target.domain}: {order}"
    rows = [(f.severity, f.title + ("" if r == "new" else f" ({r})") + (f" {f.url}" if f.url else "")) for f, r in ordered[:20]]
    if n > 20:
        rows.append(("info", f"...and {n - 20} more. Open the Exposure page for the full list."))
    intro = f"{n} exposure finding{'s' if n != 1 else ''} turned up for {target.domain}."
    text = "\n".join([intro, ""] + [f"[{s}] {line}" for s, line in rows] + ["", FOOTER])
    return subject, text, _page(f"{target.domain}: new exposure", intro, rows, FOOTER, _link("exposure"))


# --------------------------------------------------------------------------- delivery

def _smtp_error_label(e: Exception) -> str:
    # smtplib.SMTPException subclasses OSError, so the protocol errors are checked before the socket ones
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return "authentication failed"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return "recipients refused"
    if isinstance(e, smtplib.SMTPSenderRefused):
        return "sender refused"
    if isinstance(e, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)):
        return "connection error"
    if isinstance(e, smtplib.SMTPException):
        return "smtp error"
    if isinstance(e, ssl.SSLError):
        return "tls error"
    if isinstance(e, TimeoutError):
        return "timeout"
    if isinstance(e, OSError):
        return "connection error"
    return "send error"


def _send(msg: EmailMessage, cfg: Dict) -> None:
    """One SMTP transaction. TLS certificates are always verified when TLS is on."""
    ctx = ssl.create_default_context()
    if cfg["security"] == "ssl":
        client = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=cfg["timeout"], context=ctx)
    else:
        client = smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"])
    with client:
        client.ehlo()
        if cfg["security"] == "starttls":
            client.starttls(context=ctx)
            client.ehlo()
        if cfg["user"]:
            client.login(cfg["user"], cfg["password"])
        client.send_message(msg)


def deliver_email(db: Session, target: Target, subject: str, text: str, html: str, *, scan_id: Optional[int],
                  kind: str, event_count: int, attempts: int = 2, sleep=time.sleep) -> WebhookDelivery:
    """Send one message to the target's recipients with a retry. Always records a WebhookDelivery."""
    cfg = smtp_settings()
    rec = WebhookDelivery(target_id=target.id, scan_id=scan_id, host=cfg["host"], kind=kind, status="failed",
                          attempts=0, event_count=event_count)
    recipients = list(target.email_recipients or [])
    if not (cfg["host"] and cfg["sender"]):
        rec.status, rec.error = "blocked", "email is not set up on this server"
    elif not recipients:
        rec.status, rec.error = "blocked", "no recipients"
    else:
        msg = build_message(subject, text, html, recipients, cfg["sender"])
        for attempt in range(1, max(1, attempts) + 1):
            rec.attempts = attempt
            try:
                _send(msg, cfg)
                rec.status, rec.error = "sent", None
                break
            except Exception as e:  # noqa: BLE001 - network/protocol errors of every kind
                rec.error = _smtp_error_label(e)      # a label only: server replies can echo addresses or secrets
                if isinstance(e, (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused)):
                    break                             # retrying cannot fix these
            if attempt < attempts:
                sleep(2 * attempt)
    if rec.status != "sent":
        logger.warning("[email] delivery %s for target %s: %s", rec.status, target.id, rec.error)
    db.add(rec)
    db.commit()
    return rec


def send_test_email(db: Session, target: Target, sleep=time.sleep) -> WebhookDelivery:
    text = (f"This is a test from ASM Platform for {target.domain}. "
            "Real scans send one message listing the confirmed changes.")
    html = _page("ASM Platform test", text, [], FOOTER, None)
    return deliver_email(db, target, f"[ASM] Test message for {target.domain}", text, html,
                         scan_id=None, kind="email_test", event_count=0, sleep=sleep)
