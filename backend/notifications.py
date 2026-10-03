"""Alerts and webhooks driven by confirmed change events.

Rules:
  * Only CONFIRMED change events notify. Pending removals (seen once, held back) never do, and a
    baseline scan has no events, so a first scan is silent.
  * Each target has a minimum severity; quieter events are still recorded in Changes, just not announced.
  * In-app alerts: one per qualifying event, capped per scan (an overflow row says how many were left out).
  * Webhook: ONE digest per scan, never one request per event. That is the rate cap. Payloads are
    bounded (top events by severity, CVE roll-ups folded into one line per component).
  * Delivery is signed (HMAC-SHA256 over the exact body), SSRF-checked, never follows redirects, retried
    a few times, and every outcome is recorded in webhook_deliveries.
  * Nothing here may raise into the scan pipeline.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.webhook_delivery import WebhookDelivery
from backend.rollup import SEVERITY_ORDER, rollup_events, sev_rank

logger = logging.getLogger(__name__)

SEVERITIES = list(SEVERITY_ORDER)                    # critical, high, medium, low, info
WEBHOOK_FORMATS = ("json", "slack", "discord")
DEFAULT_MIN_SEVERITY = "medium"

MAX_ALERTS_PER_SCAN = int(os.getenv("ALERTS_MAX_PER_SCAN", "50"))
MAX_PAYLOAD_EVENTS = int(os.getenv("WEBHOOK_MAX_EVENTS", "20"))
MAX_PAYLOAD_ROLLUPS = int(os.getenv("WEBHOOK_MAX_ROLLUPS", "10"))
WEBHOOK_ATTEMPTS = int(os.getenv("WEBHOOK_ATTEMPTS", "3"))
WEBHOOK_BACKOFF = float(os.getenv("WEBHOOK_BACKOFF", "2"))   # seconds, doubled each retry
WEBHOOK_TIMEOUT = float(os.getenv("WEBHOOK_TIMEOUT", "5"))


def meets_threshold(severity: Optional[str], minimum: Optional[str]) -> bool:
    """True when `severity` is at least as severe as `minimum`. Unknown severities never qualify."""
    s = (severity or "").lower()
    if s not in SEVERITIES:
        return False
    m = (minimum or DEFAULT_MIN_SEVERITY).lower()
    if m not in SEVERITIES:
        m = DEFAULT_MIN_SEVERITY
    return sev_rank(s) <= sev_rank(m)


def _view(e: ChangeEvent) -> Dict:
    return {"id": e.id, "scan_id": e.scan_id, "category": e.category, "change_type": e.change_type,
            "asset": e.asset, "subject": e.subject, "severity": e.severity, "confidence": e.confidence,
            "summary": e.summary, "group": e.group, "before": e.before, "after": e.after}


def sign(secret: str, body: bytes, timestamp: str) -> str:
    """HMAC-SHA256 over '<timestamp>.<body>' so a captured request cannot be replayed with a new time."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


# --------------------------------------------------------------------------- payloads

def build_digest(target: Target, scan: Scan, events: List[Dict]) -> Dict:
    """Bounded, machine-readable summary of what changed in one scan."""
    counts = {s: 0 for s in SEVERITIES}
    for e in events:
        counts[e["severity"]] = counts.get(e["severity"], 0) + 1
    rest, rollups = rollup_events(events)
    rest = sorted(rest, key=lambda e: (sev_rank(e["severity"]), e["category"], e["asset"], e["subject"]))
    shown = rest[:MAX_PAYLOAD_EVENTS]
    lines = [{"component": r["component"], "asset": r["asset"], "change_type": r["change_type"],
              "severity": r["severity"], "cves": r["total"], "kev": r["kev_count"], "max_cvss": r["max_cvss"]}
             for r in rollups[:MAX_PAYLOAD_ROLLUPS]]
    return {
        "event": "scan.changes",
        "version": 1,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "target": {"id": target.id, "domain": target.domain},
        "scan": {"id": scan.id, "profile": scan.profile},
        "min_severity": target.alert_min_severity or DEFAULT_MIN_SEVERITY,
        "total": len(events),
        "counts": {k: v for k, v in counts.items() if v},
        "events": [{"id": e["id"], "severity": e["severity"], "category": e["category"],
                    "change_type": e["change_type"], "asset": e["asset"], "subject": e["subject"],
                    "summary": e["summary"], "confidence": e["confidence"]} for e in shown],
        "cve_rollups": lines,
        "truncated": {"events": max(0, len(rest) - len(shown)), "cve_rollups": max(0, len(rollups) - len(lines))},
    }


def _headline(d: Dict) -> str:
    order = ", ".join(f"{n} {s}" for s, n in d["counts"].items())
    return f"ASM: {d['total']} change{'s' if d['total'] != 1 else ''} on {d['target']['domain']} (scan #{d['scan']['id']}): {order}"


def _slack_safe(text: str) -> str:
    """Slack treats & < > as control characters (<!channel>, <http://x|label>); defang them."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_text(d: Dict) -> str:
    """Plain-text body for chat webhooks (Slack/Discord); kept well under their size limits."""
    out = [_headline(d)]
    for e in d["events"][:10]:
        out.append(f"- [{e['severity']}] {e['summary']}")
    for r in d["cve_rollups"][:5]:
        kev = f", {r['kev']} KEV" if r["kev"] else ""
        out.append(f"- [{r['severity']}] {r['cves']} CVEs {r['change_type']} for {r['component']}{kev}")
    hidden = max(0, d["total"] - min(len(d["events"]), 10) - sum(r["cves"] for r in d["cve_rollups"][:5]))
    if hidden:
        out.append(f"...and {hidden} more. Open the Changes page for the full list.")
    return "\n".join(out)[:1800]


def render_body(fmt: str, digest: Dict) -> Dict:
    if fmt == "slack":
        return {"text": _slack_safe(render_text(digest))}
    if fmt == "discord":
        # target-controlled text must never ping @everyone or a role
        return {"content": render_text(digest), "allowed_mentions": {"parse": []}}
    return digest


# --------------------------------------------------------------------------- delivery

def _error_label(e: Exception) -> str:
    import requests
    if isinstance(e, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(e, requests.exceptions.SSLError):
        return "tls error"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "connection error"
    return "request error"


def _post(url: str, body: bytes, headers: Dict[str, str]):
    import requests
    return requests.post(url, data=body, headers=headers, timeout=WEBHOOK_TIMEOUT, allow_redirects=False)


def deliver(db: Session, target: Target, payload: Dict, *, scan_id: Optional[int], kind: str,
            event_count: int, sleep=time.sleep) -> WebhookDelivery:
    """POST one payload to the target's webhook with retries. Always records a WebhookDelivery."""
    from backend.validators import validate_webhook_url

    url = (target.webhook_url or "").strip()
    host = urlparse(url).hostname or ""
    rec = WebhookDelivery(target_id=target.id, scan_id=scan_id, host=host, kind=kind, status="failed",
                          attempts=0, event_count=event_count)
    try:
        validate_webhook_url(url)
    except ValueError as e:
        rec.status, rec.error = "blocked", str(e)
        logger.warning("[webhook] blocked for target %s: %s", target.id, e)
        db.add(rec)
        db.commit()
        return rec

    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ts = str(int(time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": "ASM-Platform-Webhook/1",
               "X-ASM-Event": str(payload.get("event", "scan.changes")), "X-ASM-Timestamp": ts}
    if target.webhook_secret and (target.webhook_format or "json") == "json":
        headers["X-ASM-Signature"] = sign(target.webhook_secret, body, ts)

    for attempt in range(1, max(1, WEBHOOK_ATTEMPTS) + 1):
        rec.attempts = attempt
        try:
            resp = _post(url, body, headers)
            rec.http_status = resp.status_code
            if resp.ok:
                rec.status, rec.error = "sent", None
                break
            rec.error = f"HTTP {resp.status_code}"
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                break                      # the receiver rejected it; retrying will not help
        except Exception as e:  # noqa: BLE001 - network errors of every kind
            # requests puts the full URL (which may embed a token) in its messages, so store a label only
            rec.error = _error_label(e)
        if attempt < WEBHOOK_ATTEMPTS:
            sleep(WEBHOOK_BACKOFF * (2 ** (attempt - 1)))
    if rec.status != "sent":
        logger.warning("[webhook] delivery failed for target %s: %s", target.id, rec.error)
    db.add(rec)
    db.commit()
    return rec


# --------------------------------------------------------------------------- entry point

def notify_scan_changes(db: Session, scan: Scan, sleep=time.sleep) -> Dict:
    """Create in-app alerts and send the webhook digest for one scan's confirmed changes.
    Idempotent: an event that already has an alert is never alerted twice. Never raises."""
    summary = {"alerts": 0, "webhook": "none", "qualifying": 0}
    try:
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        if target is None:
            return summary
        minimum = target.alert_min_severity or DEFAULT_MIN_SEVERITY
        rows = (db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id, ChangeEvent.status == "confirmed")
                .order_by(ChangeEvent.id).all())
        rows = [r for r in rows if meets_threshold(r.severity, minimum)]
        summary["qualifying"] = len(rows)
        if not rows:
            return summary

        already = {a[0] for a in db.query(Alert.change_event_id)
                   .filter(Alert.scan_id == scan.id, Alert.change_event_id.isnot(None)).all()}
        fresh = [r for r in rows if r.id not in already]
        fresh.sort(key=lambda r: (sev_rank(r.severity), r.category, r.asset, r.subject))
        for r in fresh[:MAX_ALERTS_PER_SCAN]:
            db.add(Alert(target_id=scan.target_id, scan_id=scan.id, change_event_id=r.id,
                         alert_type=f"{r.category}_{r.change_type}", severity=r.severity, category=r.category,
                         asset_subdomain=r.asset or "", summary=r.summary,
                         detail={"subject": r.subject, "confidence": r.confidence, "group": r.group,
                                 "before": r.before, "after": r.after}))
            summary["alerts"] += 1
        left_out = len(fresh) - summary["alerts"]
        if left_out > 0:
            db.add(Alert(target_id=scan.target_id, scan_id=scan.id, alert_type="changes_summary",
                         severity=fresh[summary["alerts"]].severity, category="summary", asset_subdomain="",
                         summary=f"{left_out} more change{'s' if left_out != 1 else ''} not listed individually. "
                                 f"Open the Changes page for scan #{scan.id}.",
                         detail={"omitted": left_out}))
        db.commit()

        # The webhook digest is sent once per scan, even if the task is retried (the deliveries table is the guard).
        if target.webhook_url:
            sent_before = (db.query(WebhookDelivery).filter(WebhookDelivery.scan_id == scan.id,
                                                            WebhookDelivery.kind == "digest",
                                                            WebhookDelivery.status == "sent").first())
            if sent_before is None:
                digest = build_digest(target, scan, [_view(r) for r in rows])
                rec = deliver(db, target, render_body(target.webhook_format or "json", digest),
                              scan_id=scan.id, kind="digest", event_count=len(rows), sleep=sleep)
                summary["webhook"] = rec.status
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("[notify] failed to create alerts or deliver webhook")
        summary["webhook"] = "error"
    return summary


def send_test(db: Session, target: Target, sleep=time.sleep) -> WebhookDelivery:
    """Send a small sample so the user can verify the URL, format and signature before a real scan."""
    sample = {
        "event": "webhook.test", "version": 1, "sent_at": datetime.now(timezone.utc).isoformat(),
        "target": {"id": target.id, "domain": target.domain}, "total": 0, "counts": {},
        "message": "This is a test from ASM Platform. Real scans send a digest of confirmed changes.",
    }
    fmt = target.webhook_format or "json"
    body = ({"text": sample["message"]} if fmt == "slack"
            else {"content": sample["message"], "allowed_mentions": {"parse": []}} if fmt == "discord" else sample)
    return deliver(db, target, body, scan_id=None, kind="test", event_count=0, sleep=sleep)
