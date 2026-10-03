"""Policy applied AFTER the model answers. The model is advisory: rules decide the floor."""
import os
import re
from typing import Dict, Optional

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


# Assertions about the target that a small model tends to invent. They are allowed only when the event data
# itself says the same thing, so "MySQL ... no auth observed" needs "no auth" in the event, not in the model's head.
_CLAIMS = [re.compile(p, re.I) for p in (
    r"no auth(entication)?\b", r"\bunauthenticated\b", r"without (any )?(auth(entication)?|password|login|credentials)",
    r"default (password|credential|login)s?", r"anonymous (access|login)",
    r"actively exploited|exploited in the wild|in the wild",
    r"(already|been) (compromised|breached)", r"\bbackdoor|\bmalware|\bransomware")]


# The model cannot know where a host sits on the network, so it may not say a service is on "the internet"
# unless the event says so. Checked on the summary only: advice like "not exposed to the public internet" is fine.
_SUMMARY_CLAIMS = [re.compile(r"\b(?:to|on|from) the (?:public )?internet\b", re.I)]


def unsupported_claim(text: str, event_text: str, kev: bool = False, summary: str = "") -> Optional[str]:
    """Return the first assertion in `text` (or `summary`, for summary-only rules) that the event data does not
    support, else None."""
    for rx in _SUMMARY_CLAIMS:
        m = rx.search(summary)
        if m and not rx.search(event_text):
            return m.group(0).lower()
    for rx in _CLAIMS:
        m = rx.search(text)
        if m and not rx.search(event_text) and not (kev and "exploited" in m.group(0).lower()):
            return m.group(0).lower()
    return None


def conflicts_with_rules(rule_sev: str, ai_sev: str, final_sev: str) -> bool:
    """The model is two or more steps away from what the rules let stand. That is the signature of a
    model that was talked into something (or is simply wrong), so its text is not shown either: a summary
    saying 'false positive, no action needed' must never sit next to a critical severity."""
    return abs(_idx(ai_sev) - _idx(final_sev)) > MAX_DISAGREEMENT


def text_is_safe(text: str) -> bool:
    """Reject links and command/code-looking output: the UI and reports are not a delivery channel."""
    return not (_URL.search(text) or _CODE.search(text))


def adjust_enabled() -> bool:
    """ASM_LLM_SEVERITY_MODE=advise (default): the model explains and recommends, the rules decide severity.
    =adjust: the model may refine severity within the policy above. Turn it on only for a model that passes the
    evaluation gates (python -m backend.scripts.ai_eval)."""
    return os.getenv("ASM_LLM_SEVERITY_MODE", "advise").strip().lower() == "adjust"


def apply(event: Dict, parsed, adjust: Optional[bool] = None) -> Dict:
    kev = bool((event.get("after") or {}).get("kev"))
    allowed = final_severity(event.get("severity", "info"), parsed.severity, kev)
    adjust = adjust_enabled() if adjust is None else adjust
    return {
        "ai_severity": parsed.severity,
        "policy_severity": allowed,                 # what adjust mode would use; always used for the conflict check
        "final_severity": allowed if adjust else (event.get("severity") if event.get("severity") in SEVERITIES else "info"),
        "ai_summary": parsed.summary,
        "ai_action": parsed.recommended_action,
    }
