"""Everything that reaches the prompt is attacker-influenced (page titles, paths, banners, finding text).
Reduce it to a small whitelist of short, printable fields; never forward raw page content."""
import re
import unicodedata
from typing import Dict

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_ANGLE = re.compile(r"[<>]")   # a hostile field must not be able to close the <event> envelope
_WS = re.compile(r"\s+")
FIELD_MAX = 160


def clean_text(v, limit: int = FIELD_MAX) -> str:
    s = str(v if v is not None else "")
    # drop control and invisible formatting characters (bidi overrides, zero-width joiners) but keep real letters
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf") or ch in "\t\n ")
    s = _ANGLE.sub(" ", _CTRL.sub("", s))
    s = _WS.sub(" ", s).strip()
    return s[:limit]


def event_view(e: Dict) -> Dict:
    """Whitelisted, truncated view of a change event for the prompt."""
    after = e.get("after") or {}
    before = e.get("before") or {}
    view = {
        "category": clean_text(e.get("category"), 20),
        "change": clean_text(e.get("change_type"), 20),
        "asset": clean_text(e.get("asset"), 80),
        "subject": clean_text(e.get("subject")),
        "rule_severity": clean_text(e.get("severity"), 10),
        "confidence": clean_text(e.get("confidence"), 10),
        "summary": clean_text(e.get("summary")),
    }
    for k in ("severity", "cve", "kev", "cvss", "status", "service", "product", "version"):
        v = after.get(k, before.get(k)) if isinstance(after, dict) else None
        if v not in (None, "", False):
            view[k] = clean_text(v, 40)
    return view
