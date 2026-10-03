import logging
from typing import Dict, Optional

from pydantic import ValidationError

from backend.ai import guardrails
from backend.ai.prompt import build_messages
from backend.ai.providers import LLMError, LLMProvider
from backend.ai.schema import Triage, json_schema

logger = logging.getLogger(__name__)


def classify_event(provider: Optional[LLMProvider], event: Dict, retries: int = 1) -> Dict:
    """Never raises. Returns {'ai_status': 'ok'|'rejected'|'failed'|'disabled', ...}; on anything but 'ok' the
    rule-based severity stands unchanged and no model text is kept."""
    if provider is None:
        return {"ai_status": "disabled"}
    messages = build_messages(event)
    last_err = ""
    for _ in range(1 + retries):
        try:
            raw = provider.complete(messages, json_schema())
            parsed = Triage.model_validate_json(raw)
        except LLMError as e:
            last_err = str(e)
            continue
        except ValidationError as e:
            last_err = f"invalid output: {e.errors()[0]['type']}"
            continue
        if not (guardrails.text_is_safe(parsed.summary) and guardrails.text_is_safe(parsed.recommended_action)):
            last_err = "output rejected by guardrails"
            continue
        out = guardrails.apply(event, parsed)
        if guardrails.conflicts_with_rules(event.get("severity", "info"), parsed.severity, out["final_severity"]):
            logger.warning(f"[ai] triage rejected for {event.get('fingerprint')}: model said {parsed.severity}, "
                           f"rules allow {out['final_severity']}")
            return {"ai_status": "rejected", "ai_severity": parsed.severity,
                    "ai_error": f"model said {parsed.severity}, rules said {event.get('severity', 'info')}"}
        out.update(ai_status="ok", ai_model=f"{provider.name}:{provider.model}")
        return out
    logger.warning(f"[ai] triage failed for {event.get('fingerprint')}: {last_err}")
    return {"ai_status": "failed", "ai_error": last_err[:200]}
