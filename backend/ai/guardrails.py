"""Policy applied AFTER the model answers. The model is advisory: rules decide the floor."""
import re
from typing import Dict

from backend.ai.schema import SEVERITIES

_URL = re.compile(r"https?://|www\.", re.I)
_CODE = re.compile(r"```|<script|\bcurl\b|\bwget\b|\bchmod\b|\brm -rf\b", re.I)


def _idx(sev: str) -> int:
    return SEVERITIES.index(sev)


def final_severity(rule_sev: str, ai_sev: str, kev: bool = False) -> str:
    """AI may refine severity, never bury a serious change.
    - rule high/critical or KEV: AI cannot lower it; it may raise by at most one step.
    - otherwise: AI may move it by at most one step either way."""
    r, a = _idx(rule_sev if rule_sev in SEVERITIES else "info"), _idx(ai_sev)
    if rule_sev in ("high", "critical") or kev:
        return SEVERITIES[min(len(SEVERITIES) - 1, max(r, min(a, r + 1)))]
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, min(max(a, r - 1), r + 1)))]


MAX_DISAGREEMENT = 1   # steps between the model's own answer and the severity policy allows


def conflicts_with_rules(rule_sev: str, ai_sev: str, final_sev: str) -> bool:
    """The model is two or more steps away from what the rules let stand. That is the signature of a
    model that was talked into something (or is simply wrong), so its text is not shown either: a summary
    saying 'false positive, no action needed' must never sit next to a critical severity."""
    return abs(_idx(ai_sev) - _idx(final_sev)) > MAX_DISAGREEMENT


def text_is_safe(text: str) -> bool:
    """Reject links and command/code-looking output: the UI and reports are not a delivery channel."""
    return not (_URL.search(text) or _CODE.search(text))


def apply(event: Dict, parsed) -> Dict:
    kev = bool((event.get("after") or {}).get("kev"))
    return {
        "ai_severity": parsed.severity,
        "final_severity": final_severity(event.get("severity", "info"), parsed.severity, kev),
        "ai_summary": parsed.summary,
        "ai_action": parsed.recommended_action,
    }
