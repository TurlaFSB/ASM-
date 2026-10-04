"""Machine-readable finding exports: plain JSON and SARIF 2.1.0 (for GitHub code scanning, DefectDojo, IDEs...).

Both include triaged findings with their decision, so a consumer can filter them; SARIF carries the decision as a
`suppressions` entry, which tools understand natively.
"""
from datetime import datetime
from typing import Dict, Iterable, List, Optional

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5"}
SUPPRESSION_STATUS = {"false_positive": "accepted", "accepted_risk": "accepted", "resolved": "accepted",
                      "in_progress": "underReview"}


def _iso(v) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else v


def _severity(v) -> str:
    s = (v.severity or "info").lower()
    return s if s in LEVEL else "info"


def finding_dict(v, decision: Optional[Dict]) -> Dict:
    return {
        "id": v.id, "severity": _severity(v), "name": v.name or "", "template_id": v.template_id or "",
        "host": v.host or "", "matched_at": v.matched_at or "", "cve_id": v.cve_id,
        "cvss_score": v.cvss_score, "tags": list(v.tags or []), "description": v.description or "",
        "triage": ({"status": decision["status"], "note": decision.get("note"), "by": decision.get("by"),
                    "at": _iso(decision.get("at")), "expires_at": _iso(decision.get("expires_at")),
                    "suppressed": decision.get("suppressed")} if decision else {"status": "open"}),
    }


def build_json(scan, target_domain: str, vulns: Iterable, decisions: Dict[int, Dict]) -> Dict:
    return {
        "scan_id": scan.id, "target": target_domain, "profile": scan.profile, "status": scan.status,
        "completed_at": _iso(scan.completed_at),
        "findings": [finding_dict(v, decisions.get(v.id)) for v in vulns],
    }


def build_sarif(scan, target_domain: str, vulns: Iterable, decisions: Dict[int, Dict]) -> Dict:
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    for v in vulns:
        sev = _severity(v)
        rule_id = v.cve_id or v.template_id or "finding"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": (v.name or rule_id)[:120],
            "shortDescription": {"text": v.name or rule_id},
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{v.cve_id}" if v.cve_id else None,
            "properties": {"security-severity": SECURITY_SEVERITY[sev], "tags": ["security"] + list(v.tags or [])},
        })
        result = {
            "ruleId": rule_id,
            "level": LEVEL[sev],
            "message": {"text": (v.name or rule_id) + (f": {v.description}" if v.description else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.matched_at or v.host or target_domain}}}],
            "partialFingerprints": {"asmFindingKey": v.finding_key} if v.finding_key else {},
            "properties": {"severity": sev, "host": v.host, "cve": v.cve_id, "cvss": v.cvss_score},
        }
        d = decisions.get(v.id)
        if d and d["status"] in SUPPRESSION_STATUS:
            result["suppressions"] = [{
                "kind": "external", "status": SUPPRESSION_STATUS[d["status"]],
                "justification": f"{d['status'].replace('_', ' ')}" + (f": {d['note']}" if d.get("note") else ""),
            }]
        results.append(result)
    for r in rules.values():
        if r["helpUri"] is None:
            del r["helpUri"]
    return {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ASM Platform", "informationUri": "https://github.com/TurlaFSB/ASM-",
                                "rules": list(rules.values())}},
            "invocations": [{"executionSuccessful": scan.status == "completed", "endTimeUtc": _iso(scan.completed_at)}],
            "properties": {"scanId": scan.id, "target": target_domain, "profile": scan.profile},
            "results": results,
        }],
    }
