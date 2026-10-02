"""Roll-ups: many near-identical version-matched CVEs become one line per component and host.

A service banner like "Apache httpd 2.4.7" can match dozens of CVEs. Listing each one buries the
handful of findings that need a human, so views show ONE line per (component, host) -- worst
severity, KEV count, "N of M" when the per-service cap hid some -- and expand to the CVEs on demand.

Pure functions only (no database, no I/O) so every rule is unit-testable.
"""
import re
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
COMPONENT_RE = re.compile(r"^\[version match\]\s+(.*?):\s+CVE-\d{4}-\d{4,}")
_SENT_END_RE = re.compile(r"(?<=[.!?])\s")


def component_of(name: Optional[str]) -> Optional[str]:
    """'[version match] Apache httpd 2.4.7: CVE-2017-1234 ...' -> 'Apache httpd 2.4.7' (None if not a version match)."""
    m = COMPONENT_RE.match(name or "")
    return m.group(1).strip() if m else None


def short_summary(desc: Optional[str], limit: int = 170) -> str:
    """First sentence of an NVD description, without our own 'Matched by service version' tail."""
    desc = (desc or "").split(" Matched by service version")[0].strip()
    first = _SENT_END_RE.split(desc, maxsplit=1)[0]
    return first if len(first) <= limit else first[:limit].rstrip() + " …"


def sev_rank(sev: Optional[str]) -> int:
    s = (sev or "").lower()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _summarize_group(g: Dict, total: Optional[int]) -> Dict:
    g["cves"].sort(key=lambda c: (sev_rank(c["severity"]), not c["kev"], -(c["cvss"] or 0), c["cve_id"] or ""))
    g["shown"] = len(g["cves"])
    g["total"] = max(g["shown"], total or 0)
    g["capped"] = g["total"] > g["shown"]
    g["severity"] = g["cves"][0]["severity"]
    g["kev_count"] = sum(1 for c in g["cves"] if c["kev"])
    g["max_cvss"] = max((c["cvss"] or 0) for c in g["cves"])
    by_sev: Dict[str, int] = {}
    for c in g["cves"]:
        by_sev[c["severity"]] = by_sev.get(c["severity"], 0) + 1
    g["by_severity"] = {k: by_sev[k] for k in SEVERITY_ORDER if k in by_sev}
    return g


def _item_rank(item: Dict) -> Tuple:
    if item["kind"] == "component":
        return (sev_rank(item["severity"]), 0 if item["kev_count"] else 1, -item["max_cvss"], item["component"])
    kev = "kev" in (item.get("tags") or [])
    return (sev_rank(item.get("severity")), 0 if kev else 1, -(item.get("cvss_score") or 0), item.get("name") or "")


def rollup_findings(rows: Iterable[Dict], totals: Optional[Dict[Tuple, int]] = None) -> List[Dict]:
    """rows: serialized vulnerabilities (as the API returns them). totals: {(scan_id, host, component): matched}
    from the scan's cve_truncated record, so a capped service reads 'N of M'.

    Verified (scanner-confirmed) findings stay one line each; unverified version matches collapse into one
    'component' line per (scan, host, component)."""
    totals = totals or {}
    items: List[Dict] = []
    groups: Dict[Tuple, Dict] = {}
    for r in rows:
        comp = component_of(r.get("name")) if not r.get("verified", True) else None
        if comp is None:
            items.append({"kind": "finding", **r})
            continue
        key = (r.get("scan_id"), r.get("host"), comp)
        g = groups.setdefault(key, {"kind": "component", "component": comp, "host": r.get("host"),
                                    "scan_id": r.get("scan_id"), "target_id": r.get("target_id"), "cves": []})
        g["cves"].append({"id": r.get("id"), "cve_id": r.get("cve_id"), "cvss": r.get("cvss_score"),
                          "severity": (r.get("severity") or "info").lower(),
                          "kev": "kev" in (r.get("tags") or []), "summary": short_summary(r.get("description"))})
    for key, g in groups.items():
        items.append(_summarize_group(g, totals.get(key)))
    items.sort(key=_item_rank)
    return items


def rollup_events(events: Iterable[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Split change events (as the API returns them) into (events to list individually, CVE roll-ups).

    Version-match CVE events carry a `group` (the component); those collapse into one line per
    (asset, component, change_type). Everything else is returned unchanged and in order."""
    rest: List[Dict] = []
    groups: Dict[Tuple, Dict] = {}
    for e in events:
        if e.get("category") != "finding" or not e.get("group"):
            rest.append(e)
            continue
        rec = (e.get("after") if e.get("change_type") != "removed" else e.get("before")) or {}
        key = (e.get("asset"), e["group"], e.get("change_type"))
        g = groups.setdefault(key, {"kind": "cve_rollup", "asset": e.get("asset"), "component": e["group"],
                                    "change_type": e.get("change_type"), "confidence": e.get("confidence"),
                                    "scan_id": e.get("scan_id"), "cves": []})
        g["cves"].append({"event_id": e.get("id"), "cve_id": rec.get("cve"),
                          "cvss": rec.get("cvss"), "severity": (e.get("severity") or "info").lower(),
                          "kev": bool(rec.get("kev"))})
    out = [_summarize_group(g, None) for g in groups.values()]
    out.sort(key=lambda g: (sev_rank(g["severity"]), 0 if g["kev_count"] else 1, -g["max_cvss"], g["component"]))
    return rest, out
