"""Alerts and webhook for newly found (or escalated / reappeared) exposure findings."""
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.exposure import ExposureFinding
from backend.models.target import Target
from backend.notifications import (DEFAULT_MIN_SEVERITY, SEVERITIES, _slack_safe, deliver, meets_threshold, sev_rank)

logger = logging.getLogger(__name__)

MAX_ALERTS_PER_RUN = 10
MAX_PAYLOAD_FINDINGS = 20


def _text(target: Target, items: List[Tuple[ExposureFinding, str]]) -> str:
    n = len(items)
    lines = [f"ASM: {n} new exposure finding{'s' if n != 1 else ''} for {target.domain}"]
    for f, reason in items[:10]:
        tag = "" if reason == "new" else f" ({reason})"
        lines.append(f"- [{f.severity}] {f.title}{tag}")
    if n > 10:
        lines.append(f"...and {n - 10} more. Open the Exposure page for the full list.")
    return "\n".join(lines)[:1800]


def build_payload(target: Target, items: List[Tuple[ExposureFinding, str]]) -> Dict:
    counts = {s: 0 for s in SEVERITIES}
    for f, _ in items:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    ordered = sorted(items, key=lambda x: (sev_rank(x[0].severity), x[0].id))
    return {
        "event": "exposure.new", "version": 1, "sent_at": datetime.now(timezone.utc).isoformat(),
        "target": {"id": target.id, "domain": target.domain},
        "total": len(items), "counts": {k: v for k, v in counts.items() if v},
        "findings": [{"id": f.id, "severity": f.severity, "source": f.source, "kind": f.kind, "reason": r,
                      "title": f.title, "summary": f.summary, "url": f.url} for f, r in ordered[:MAX_PAYLOAD_FINDINGS]],
        "truncated": max(0, len(ordered) - MAX_PAYLOAD_FINDINGS),
    }


def render(fmt: str, target: Target, items, payload: Dict) -> Dict:
    if fmt == "slack":
        return {"text": _slack_safe(_text(target, items))}
    if fmt == "discord":
        return {"content": _text(target, items), "allowed_mentions": {"parse": []}}
    return payload


def notify_exposure(db: Session, target: Target, items: List[Tuple[ExposureFinding, str]], sleep=None) -> Dict:
    """items: (finding, reason) with reason new | escalated | reappeared. Never raises."""
    out = {"alerts": 0, "webhook": "none", "qualifying": 0}
    try:
        minimum = target.alert_min_severity or DEFAULT_MIN_SEVERITY
        qualifying = [(f, r) for f, r in items if meets_threshold(f.severity, minimum)]
        out["qualifying"] = len(qualifying)
        if not qualifying:
            return out
        qualifying.sort(key=lambda x: (sev_rank(x[0].severity), x[0].id))
        for f, reason in qualifying[:MAX_ALERTS_PER_RUN]:
            db.add(Alert(target_id=target.id, scan_id=None, alert_type=f"exposure_{f.kind}", severity=f.severity,
                         category="exposure", asset_subdomain=target.domain, summary=f.title,
                         detail={"finding_id": f.id, "source": f.source, "reason": reason, "url": f.url,
                                 "evidence": f.evidence}))
            out["alerts"] += 1
        left = len(qualifying) - out["alerts"]
        if left > 0:
            db.add(Alert(target_id=target.id, scan_id=None, alert_type="exposure_summary",
                         severity=qualifying[out["alerts"]][0].severity, category="exposure",
                         asset_subdomain=target.domain,
                         summary=f"{left} more exposure finding{'s' if left != 1 else ''} not listed individually. "
                                 "Open the Exposure page.", detail={"omitted": left}))
        db.commit()
        if target.webhook_url:
            payload = build_payload(target, qualifying)
            kwargs = {"sleep": sleep} if sleep else {}
            rec = deliver(db, target, render(target.webhook_format or "json", target, qualifying, payload),
                          scan_id=None, kind="exposure", event_count=len(qualifying), **kwargs)
            out["webhook"] = rec.status
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("[exposure] failed to create alerts or deliver webhook")
        out["webhook"] = "error"
    return out
