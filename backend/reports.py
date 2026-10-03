"""PDF assessment report: data assembly (this module) + layout (templates/report.html).

Security notes
- Every value that originates from a scanned target (page titles, finding descriptions,
  banners) is attacker-influenced, so the template runs with autoescape ON and WeasyPrint
  is given a url_fetcher that refuses all resource loads (no file://, no internal HTTP).
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML
from sqlalchemy.orm import Session

from backend.models.target import Target
from backend.models.scan import Scan
from backend.models.asset import Asset
from backend.models.scan_asset import ScanAsset
from backend.models.vulnerability import Vulnerability
from backend.models.alert import Alert
from backend.models.discovered_path import DiscoveredPath
from backend.models.change_event import ChangeEvent
from backend.models.scan_snapshot import ScanSnapshot
from backend.scan_profiles import get_profile
from backend.tech_utils import clean_technologies
from backend.path_flags import is_sensitive_path

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
COUNTED = ["critical", "high", "medium", "low", "info"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_DESC = 700

SEVERITY_RECOMMENDATIONS = {
    "critical": "Remediate within 24-48 hours. Patch or mitigate before any other work.",
    "high": "Remediate within 7 days, after critical items.",
    "medium": "Schedule remediation within 30 days.",
    "low": "Address during regular maintenance cycles.",
    "info": "No action required; review for exposure of unnecessary information.",
}

SLA = {"critical": "24-48 hours", "high": "7 days", "medium": "30 days", "low": "Next cycle", "info": "—"}

# Tag-driven advice for findings that have no CVE (misconfigurations, exposures, weak settings)
TAG_ADVICE = [
    ({"default-login", "default-logins"}, "Change default credentials immediately and restrict the interface to trusted networks."),
    ({"takeover"}, "Remove the dangling DNS record or reclaim the resource it points to."),
    ({"panel", "exposure", "exposed-panel"}, "Restrict access to this interface (VPN, IP allow-list or authentication) or remove it from the public network."),
    ({"files", "config", "backup"}, "Remove the exposed file or directory listing and review what else the web root serves."),
    ({"misconfig"}, "Correct the configuration in line with vendor hardening guidance."),
    ({"ssh"}, "Harden the SSH configuration: current ciphers/MACs/key exchange only, key-based authentication, restrict by source address."),
    ({"ssl", "tls"}, "Disable legacy protocols and weak ciphers; renew or replace weak or expired certificates."),
    ({"ftp", "telnet", "smb", "samba", "mysql", "rdp", "vnc", "redis", "mongodb", "memcached"},
     "Do not expose this service to untrusted networks; restrict it with a firewall or VPN and require authentication."),
]
VERSION_MATCH_NOTE = "First confirm the installed version and patch level (fixes are often backported), then patch or mitigate."

MODULE_LABELS = [
    ("subfinder", "Subdomain discovery (subfinder)"), ("amass", "Subdomain discovery (amass)"),
    ("dns", "DNS resolution"), ("whois_asn", "WHOIS / ASN"), ("portscan", "Port & service scan (nmap)"),
    ("httpprobe", "HTTP probing (httpx)"), ("whatweb", "Technology fingerprinting (whatweb)"),
    ("dirbuster", "Directory discovery (feroxbuster)"), ("vuln", "Web vulnerability scan (nuclei)"),
    ("nuclei_network", "Network service checks (nuclei)"), ("cve_match", "Version-to-CVE correlation (NVD)"),
    ("sslyze", "TLS configuration (sslyze)"), ("screenshot", "Screenshots (EyeWitness)"),
]


def _module_state(status: str) -> str:
    v = (status or "").lower()
    if v.startswith(("ok", "completed", "resolved")):
        return "ok"
    if v.startswith("skipped") or v.startswith("no ") or v == "empty":
        return "skip"
    if v.startswith(("partial", "timeout")):
        return "warn"
    return "fail"


def _limitation(label: str, status: str, state: str) -> Optional[str]:
    if state == "warn":
        return f"{label}: {status}. Results for this stage may be incomplete."
    if state == "fail":
        return f"{label}: {status}. This stage did not complete, so its findings are missing."
    return None


def calculate_risk_rating(vulns) -> str:
    severities = {(v.severity or "info").lower() for v in vulns}
    for level in ("critical", "high", "medium", "low"):
        if level in severities:
            return level.capitalize()
    return "Informational"


def _tags(v) -> List[str]:
    t = v.tags
    if isinstance(t, str):
        t = [x.strip() for x in t.split(",")]
    return [str(x).lower() for x in (t or [])]


def _guidance(sev: str, tags: List[str], cve: Optional[str]) -> str:
    tagset = set(tags)
    for keys, text in TAG_ADVICE:
        if tagset & keys and not cve:
            return text
    if "version-match" in tagset:
        return f"{SEVERITY_RECOMMENDATIONS.get(sev, '')} {VERSION_MATCH_NOTE}".strip()
    return SEVERITY_RECOMMENDATIONS.get(sev, "Review and remediate per vendor guidance.")


def _vuln_view(v: Vulnerability) -> Dict:
    sev = (v.severity or "info").lower()
    tags = _tags(v)
    desc = (v.description or "").strip()
    if len(desc) > MAX_DESC:
        desc = desc[:MAX_DESC].rstrip() + " …"
    return {
        "name": v.name, "severity": sev, "host": v.host, "matched_at": v.matched_at,
        "template_id": v.template_id, "cve_id": v.cve_id if v.cve_id and CVE_RE.match(v.cve_id) else None,
        "cvss": v.cvss_score, "description": desc, "tags": tags,
        "unverified": "version-match" in tags or "unverified" in tags,
        "kev": "kev" in tags, "exploitable": bool(v.is_exploitable_confirmed),
        "guidance": _guidance(sev, tags, v.cve_id),
    }


def _sort_key(v: Dict):
    sev = SEVERITY_ORDER.index(v["severity"]) if v["severity"] in SEVERITY_ORDER else 99
    return (sev, not v["kev"], not v["exploitable"], v["unverified"], -(v["cvss"] or 0), v["host"] or "")


from backend.rollup import COMPONENT_RE, short_summary as _short_summary  # noqa: E402


def _component(v: Dict) -> str:
    m = COMPONENT_RE.match(v.get("name") or "")
    return m.group(1).strip() if m else (v.get("name") or "Unknown component")


def group_inferred(vulns: List[Dict]) -> List[Dict]:
    """Version-matched (unverified) CVEs collapse into one block per component and host, so a
    service with 20 CVEs is one table and one remediation action, not 20 near-identical cards."""
    groups: Dict[tuple, Dict] = {}
    for v in vulns:
        comp = _component(v)
        g = groups.setdefault((comp, v["host"]), {"component": comp, "host": v["host"], "rows": []})
        g["rows"].append({"cve_id": v["cve_id"], "cvss": v["cvss"], "severity": v["severity"],
                          "kev": v["kev"], "summary": _short_summary(v["description"])})
    out = []
    for g in groups.values():
        g["rows"].sort(key=lambda r: (SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 99,
                                      not r["kev"], -(r["cvss"] or 0)))
        g["severity"] = g["rows"][0]["severity"]
        g["count"] = len(g["rows"])
        g["kev_count"] = sum(1 for r in g["rows"] if r["kev"])
        g["max_cvss"] = max((r["cvss"] or 0) for r in g["rows"])
        by_sev = {}
        for r in g["rows"]:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        g["by_sev"] = [(k, by_sev[k]) for k in SEVERITY_ORDER if k in by_sev]
        g["guidance"] = (f"Confirm the installed version and distribution patch level for {g['component']} "
                         "(vendors often backport fixes without changing the version string), then apply vendor "
                         "updates." + (f" Start with the {g['kev_count']} CVE(s) marked KEV." if g["kev_count"] else ""))
        g["verify_sla"] = "48 hours" if g["kev_count"] else ("7 days" if g["severity"] in ("critical", "high") else "30 days")
        out.append(g)
    out.sort(key=lambda g: (SEVERITY_ORDER.index(g["severity"]) if g["severity"] in SEVERITY_ORDER else 99,
                            -g["kev_count"], -g["max_cvss"], g["component"]))
    return out


def describe_change(detail) -> List[str]:
    """Turn an alert's detail dict into readable bullet lines (never a raw dict repr)."""
    if not isinstance(detail, dict):
        return [str(detail)] if detail else []
    out = []
    op, np_ = set(detail.get("old_ports") or []), set(detail.get("new_ports") or [])
    if np_ - op:
        out.append("Ports opened: " + ", ".join(str(p) for p in sorted(np_ - op)))
    if op - np_:
        out.append("Ports closed: " + ", ".join(str(p) for p in sorted(op - np_)))
    ot = set(clean_technologies(detail.get("old_technologies")))
    nt = set(clean_technologies(detail.get("new_technologies")))
    if nt - ot:
        out.append("Technologies added: " + ", ".join(sorted(nt - ot)))
    if ot - nt:
        out.append("Technologies removed: " + ", ".join(sorted(ot - nt)))
    if detail.get("old_http_status") != detail.get("new_http_status") and "new_http_status" in detail:
        out.append(f"HTTP status {detail.get('old_http_status') or '—'} → {detail.get('new_http_status') or '—'}")
    if detail.get("reason"):
        out.append(str(detail["reason"]))
    return out or ["Content fingerprint changed."]


def _paths_view(db: Session, scan_id: int, assets: Dict[int, Asset]) -> List[Dict]:
    rows = db.query(DiscoveredPath).filter(DiscoveredPath.scan_id == scan_id).all()
    out = []
    for p in rows:
        a = assets.get(p.asset_id) or db.get(Asset, p.asset_id)
        out.append({"host": a.subdomain if a else "—", "port": p.port, "path": p.path, "status": p.status_code,
                    "length": p.content_length, "redirect": p.redirect_location})
    out.sort(key=lambda r: (r["host"], r["port"] or 0, r["path"]))
    return out


def _sev(r) -> str:
    return r.final_severity or r.severity


def _changes_view(db: Session, scan: Scan, mr: Dict) -> Optional[Dict]:
    """Structured changes for this scan from the diff engine; None for scans recorded before it existed
    (the template then falls back to the legacy per-asset alerts)."""
    if not db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == scan.id).first():
        return None
    detail = mr.get("diff_detail") or {}
    rows = (db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id, ChangeEvent.status == "confirmed").all())
    rows.sort(key=lambda r: (SEVERITY_ORDER.index(_sev(r)) if _sev(r) in SEVERITY_ORDER else 9,
                             r.category, r.asset, r.subject))
    direct, grouped = [], {}
    for r in rows:
        if r.group and r.confidence == "inferred":
            g = grouped.setdefault((r.group, r.asset, r.change_type), {"group": r.group, "asset": r.asset,
                                                                       "change_type": r.change_type, "n": 0,
                                                                       "severity": _sev(r)})
            g["n"] += 1
        else:
            direct.append({"severity": _sev(r), "category": r.category, "change_type": r.change_type,
                           "asset": r.asset, "summary": r.summary, "confidence": r.confidence})
    counts = {k: 0 for k in COUNTED}
    for r in rows:
        counts[_sev(r)] = counts.get(_sev(r), 0) + 1
    baseline_id = detail.get("baseline_scan_id")
    pending = db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id, ChangeEvent.status == "pending").count()
    return {"is_baseline": baseline_id is None, "baseline_scan_id": baseline_id, "total": len(rows),
            "counts": counts, "events": direct, "inferred_groups": sorted(grouped.values(), key=lambda g: -g["n"]),
            "pending": pending, "not_compared": detail.get("skipped", [])}


def build_report_context(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError("Scan not found")

    target = db.query(Target).filter(Target.id == scan.target_id).first()

    # Point-in-time inventory for THIS scan; older scans without scan_assets rows fall back
    # to the target's currently known assets.
    assets = (db.query(Asset).join(ScanAsset, ScanAsset.asset_id == Asset.id)
              .filter(ScanAsset.scan_id == scan_id).all())
    if not assets:
        assets = [a for a in db.query(Asset).filter(Asset.target_id == scan.target_id).all()
                  if a.status != "disappeared"]
    assets.sort(key=lambda a: -(a.risk_score or 0))

    raw_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()
    vulns = sorted((_vuln_view(v) for v in raw_vulns), key=_sort_key)

    severity_counts = {k: 0 for k in COUNTED}
    unverified_counts = {k: 0 for k in COUNTED}
    for v in vulns:
        if v["severity"] in severity_counts:
            severity_counts[v["severity"]] += 1
            if v["unverified"]:
                unverified_counts[v["severity"]] += 1
    confirmed_counts = {k: severity_counts[k] - unverified_counts[k] for k in COUNTED}

    duration = None
    if scan.started_at and scan.completed_at:
        total_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = (f"{hours}h " if hours else "") + f"{minutes}m {seconds}s"

    def _alerts(kind):
        rows = [a for a in alerts if a.alert_type == kind]
        return [{"subdomain": a.asset_subdomain, "ip": a.asset_ip, "at": a.created_at,
                 "lines": describe_change(a.detail)} for a in rows]

    new_assets, changed_assets = _alerts("new_asset"), _alerts("changed_asset")
    disappeared_assets, reappeared_assets = _alerts("disappeared_asset"), _alerts("reappeared_asset")

    # Scan coverage: what ran, what was skipped, what is incomplete
    mr = scan.module_results or {}
    coverage, limitations = [], []
    for key, label in MODULE_LABELS:
        if key in mr:
            status = str(mr[key])
            state = _module_state(status)
            coverage.append({"label": label, "status": status, "state": state})
            lim = _limitation(label, status, state)
            if lim:
                limitations.append(lim)
    profile = get_profile(scan.profile or mr.get("profile"))

    confirmed_vulns = [v for v in vulns if not v["unverified"]]
    inferred_groups = group_inferred([v for v in vulns if v["unverified"] and v["severity"] != "info"])
    # per-service cap: how many CVEs matched in total vs how many were kept (label == group component)
    cve_totals = {f"{t.get('host')}|{t['label']}": t["total"] for t in (mr.get("cve_truncated") or []) if t.get("label")}

    # Remediation priorities: one row per distinct confirmed finding (hosts aggregated) plus one
    # row per inferred component, so the list stays actionable instead of repeating itself.
    grouped: Dict[tuple, Dict] = {}
    for v in confirmed_vulns:
        if v["severity"] == "info":
            continue
        key = (v["name"], v["cve_id"])
        g = grouped.setdefault(key, {**v, "hosts": []})
        if v["host"] and v["host"] not in g["hosts"]:
            g["hosts"].append(v["host"])
    priorities = sorted(grouped.values(), key=_sort_key)

    paths = _paths_view(db, scan_id, {a.id: a for a in assets})
    sensitive = [p for p in paths if is_sensitive_path(p["path"], p["status"])]

    key_findings = []
    c = severity_counts
    if c["critical"]:
        key_findings.append(f"{c['critical']} critical finding(s) require immediate attention"
                            + (f" ({unverified_counts['critical']} inferred from software versions and not yet verified)."
                               if unverified_counts["critical"] else "."))
    if c["high"]:
        key_findings.append(f"{c['high']} high severity finding(s) detected"
                            + (f" ({unverified_counts['high']} unverified)." if unverified_counts["high"] else "."))
    kev = sum(1 for v in vulns if v["kev"])
    if kev:
        key_findings.append(f"{kev} finding(s) match CISA's Known Exploited Vulnerabilities catalogue: attackers are actively exploiting these in the wild.")
    if sensitive:
        key_findings.append(f"{len(sensitive)} potentially sensitive path(s) are reachable (admin, backup or configuration content).")
    if new_assets:
        key_findings.append(f"{len(new_assets)} new asset(s) appeared since the previous scan.")
    if disappeared_assets:
        key_findings.append(f"{len(disappeared_assets)} previously known asset(s) are no longer reachable.")
    if limitations:
        key_findings.append(f"Coverage is incomplete for {len(limitations)} stage(s); see Scope & Coverage.")
    if not (c["critical"] or c["high"]):
        key_findings.append("No critical or high severity findings were identified in this scan.")

    rating = calculate_risk_rating(raw_vulns)
    rating_basis = None
    top = rating.lower()
    if top in severity_counts and severity_counts[top] and confirmed_counts[top] == 0:
        rating_basis = "Based solely on findings inferred from software versions; verification may lower this rating."

    # Top actions for the executive summary: inferred components need verification first, confirmed
    # findings need fixing; rank both by severity then KEV.
    actions = [{"text": p["name"], "severity": p["severity"], "kev": p["kev"], "sla": SLA[p["severity"]],
                "kind": "Fix"} for p in priorities if p["severity"] != "info"]
    actions += [{"text": f"Verify and patch {g['component']} ({g['count']} inferred CVEs)", "severity": g["severity"],
                 "kev": g["kev_count"] > 0, "sla": g["verify_sla"], "kind": "Verify"} for g in inferred_groups]
    actions.sort(key=lambda a: (SEVERITY_ORDER.index(a["severity"]), not a["kev"]))
    top_actions = actions[:5]

    changes = _changes_view(db, scan, mr)

    technologies = sorted({t for a in assets for t in clean_technologies(a.technologies)})

    return {
        "report_id": f"ASM-{scan.id:05d}",
        "target": target, "scan": scan, "profile": profile, "duration": duration,
        "assets": assets, "vulnerabilities": vulns,
        "changes": changes, "top_actions": top_actions, "confirmed_vulns": confirmed_vulns, "inferred_groups": inferred_groups, "cve_totals": cve_totals,
        "severity_counts": severity_counts, "confirmed_counts": confirmed_counts,
        "unverified_counts": unverified_counts,
        "risk_rating": rating, "rating_basis": rating_basis, "key_findings": key_findings,
        "new_assets": new_assets, "changed_assets": changed_assets,
        "disappeared_assets": disappeared_assets, "reappeared_assets": reappeared_assets,
        "priorities": priorities, "sla": SLA, "coverage": coverage, "limitations": limitations,
        "stages": profile.stage_names(), "paths": paths, "sensitive_paths": sensitive,
        "generated_at": datetime.now(timezone.utc),
        "whois_data": target.whois_data if target else None,
        "technologies": technologies,
        "tls_findings": [v for v in vulns if "sslyze" in v["tags"]],
        "internal_target": bool(target and not (target.whois_data or {}).get("domain_whois")),
    }


def _deny_fetch(url, *args, **kwargs):
    """Reports are fully self-contained: refuse every resource load so scanned content can
    never make the report generator read local files or call internal services."""
    raise ValueError(f"resource loading disabled in reports: {url[:80]}")


def generate_pdf_report(db: Session, scan_id: int) -> bytes:
    context = build_report_context(db, scan_id)
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)),
                      autoescape=select_autoescape(["html", "xml"], default=True))
    env.filters["clean_tech"] = clean_technologies
    html_content = env.get_template("report.html").render(**context)
    return HTML(string=html_content, url_fetcher=_deny_fetch).write_pdf()
