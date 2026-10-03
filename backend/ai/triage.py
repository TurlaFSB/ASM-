"""Run AI triage over one scan's confirmed change events and store the result on each event.

Bounded on purpose: a local model is slow and can be down, and a scan must never wait on it.
 - at most ASM_LLM_MAX_EVENTS events per scan, most severe first
 - at most ASM_LLM_BUDGET_SECONDS of model time per scan
 - stops after ASM_LLM_MAX_CONSECUTIVE_FAILURES failures in a row (provider down)
 - version-matched CVE events (those with a `group`) are left to the rules: they are rolled up
   per component and there can be dozens per service
Never raises. Idempotent: events that already have an ai_status are not re-sent.
"""
import logging
import os
import time
from typing import Dict, Optional

from backend.ai.classifier import classify_event
from backend.ai.providers import LLMProvider, provider_from_env
from backend.models.change_event import ChangeEvent
from backend.rollup import sev_rank

logger = logging.getLogger(__name__)


def _int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def event_dict(e: ChangeEvent) -> Dict:
    return {"id": e.id, "category": e.category, "change_type": e.change_type, "asset": e.asset,
            "subject": e.subject, "severity": e.severity, "confidence": e.confidence, "summary": e.summary,
            "fingerprint": e.fingerprint, "before": e.before, "after": e.after}


def triage_scan_events(db, scan, provider: Optional[LLMProvider] = None, clock=time.monotonic) -> Dict:
    out = {"status": "disabled", "classified": 0, "failed": 0, "skipped": 0}
    try:
        if provider is None:
            provider = provider_from_env()
        if provider is None:
            return out
        max_events = _int("ASM_LLM_MAX_EVENTS", 30)
        budget = _int("ASM_LLM_BUDGET_SECONDS", 180)
        max_fail = max(1, _int("ASM_LLM_MAX_CONSECUTIVE_FAILURES", 2))

        rows = (db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id, ChangeEvent.status == "confirmed",
                                             ChangeEvent.ai_status.is_(None)).all())
        todo = [r for r in rows if not r.group]
        todo.sort(key=lambda r: (sev_rank(r.severity), r.category, r.asset, r.subject))
        out["status"] = "ok"
        started, consecutive = clock(), 0
        for i, r in enumerate(todo):
            if i >= max_events or clock() - started > budget:
                out["skipped"] = len(todo) - i
                out["status"] = "partial"
                break
            res = classify_event(provider, event_dict(r))
            if res.get("ai_status") == "ok":
                consecutive = 0
                r.ai_status, r.ai_severity, r.final_severity = "ok", res["ai_severity"], res["final_severity"]
                r.ai_summary, r.ai_action, r.ai_model = res["ai_summary"], res["ai_action"], res["ai_model"]
                out["classified"] += 1
            else:
                consecutive += 1
                r.ai_status, r.ai_error = "failed", res.get("ai_error")
                out["failed"] += 1
            db.commit()
            if consecutive >= max_fail:
                out["skipped"] = len(todo) - i - 1
                out["status"] = "aborted"
                logger.warning(f"[ai] {consecutive} failures in a row, skipping triage for the rest of scan {scan.id}")
                break
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("[ai] triage crashed; rule-based severities stand")
        out["status"] = "error"
    return out
