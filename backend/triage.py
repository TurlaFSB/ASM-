"""Finding triage: a person's decision about a finding, kept across scans.

A finding is identified by what it is and where it is (template, CVE, host, port), not by the scan row that
reported it, so a decision made today still applies to next week's scan of the same thing.

Statuses
  in_progress     someone is working on it. Informational only; the finding stays in the active list.
  false_positive  not a real issue. Hidden from the active list and reports. Needs a reason.
  accepted_risk   known and accepted for now. Hidden until the review date (default 90 days), then it comes back.
                  Needs a reason.
  resolved        fixed, as judged by a person. Hidden until a LATER scan reports the finding again; then it
                  returns as open (it reappeared).
Setting a finding back to "open" removes the decision.
"""
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional

STATUSES = ("open", "in_progress", "false_positive", "accepted_risk", "resolved")
NEEDS_REASON = ("false_positive", "accepted_risk")
DEFAULT_ACCEPT_DAYS = 90
MAX_ACCEPT_DAYS = 365
NOTE_MAX = 1000


def extract_port(matched_at: Optional[str]) -> Optional[int]:
    if not matched_at:
        return None
    m = re.search(r"://[^/:]+:(\d+)", matched_at) or re.search(r":(\d+)(?:/|$)", matched_at)
    return int(m.group(1)) if m else None


def finding_key(template_id, cve_id, host, matched_at) -> str:
    """Stable identity of a finding on a target. Short, so it indexes well."""
    port = extract_port(matched_at)
    raw = "|".join([(template_id or "").lower(), (cve_id or "").upper(), (host or "").lower(), str(port or "")])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_suppressing(triage, vuln_created_at: Optional[datetime], now: Optional[datetime] = None) -> bool:
    """Does this decision hide this particular finding row right now?"""
    if triage is None:
        return False
    now = now or datetime.now(timezone.utc)
    if triage.status == "false_positive":
        return True
    if triage.status == "accepted_risk":
        exp = _aware(triage.expires_at)
        return exp is None or exp > now
    if triage.status == "resolved":
        made, seen = _aware(triage.updated_at), _aware(vuln_created_at)
        return made is None or seen is None or seen <= made
    return False


def triage_view(t, suppressed: bool) -> Optional[Dict]:
    if t is None:
        return None
    return {"status": t.status, "note": t.note, "by": t.updated_by, "at": t.updated_at, "expires_at": t.expires_at,
            "suppressed": suppressed}


def lookup(db, vulns: Iterable) -> Dict[int, Dict]:
    """{vuln.id: triage view} for the given Vulnerability rows (only those that have a decision)."""
    from backend.models.finding_triage import FindingTriage
    vulns = list(vulns)
    if not vulns:
        return {}
    targets = {v.target_id for v in vulns}
    keys = {v.finding_key for v in vulns if v.finding_key}
    rows = db.query(FindingTriage).filter(FindingTriage.target_id.in_(targets), FindingTriage.key.in_(keys)).all() if keys else []
    by = {(r.target_id, r.key): r for r in rows}
    now = datetime.now(timezone.utc)
    out: Dict[int, Dict] = {}
    for v in vulns:
        t = by.get((v.target_id, v.finding_key))
        if t is not None:
            out[v.id] = triage_view(t, is_suppressing(t, v.created_at, now))
    return out
