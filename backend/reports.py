from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from sqlalchemy.orm import Session

from backend.models.target import Target
from backend.models.scan import Scan
from backend.models.asset import Asset
from backend.models.vulnerability import Vulnerability
from backend.models.alert import Alert

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

SEVERITY_RECOMMENDATIONS = {
    "critical": "Critical findings require immediate remediation within 24-48 hours. Patch or mitigate before any other work.",
    "high": "High severity findings should be remediated within 7 days. Prioritize after critical items.",
    "medium": "Medium severity findings should be scheduled for remediation within 30 days.",
    "low": "Low severity findings can be addressed during regular maintenance cycles.",
}

def calculate_risk_rating(vulns):
    severities = {(v.severity or "informational").lower() for v in vulns}
    for level in SEVERITY_ORDER:
        if level in severities:
            return level.capitalize()
    return "Informational"

def build_report_context(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError("Scan not found")

    target = db.query(Target).filter(Target.id == scan.target_id).first()
    assets = db.query(Asset).filter(Asset.target_id == scan.target_id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = (v.severity or "informational").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    duration = None
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        total_seconds = int(delta.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration = (f"{hours}h " if hours else "") + f"{minutes}m {seconds}s"

    new_assets = [a for a in alerts if a.alert_type == "new_asset"]
    changed_assets = [a for a in alerts if a.alert_type == "changed_asset"]
    disappeared_assets = [a for a in alerts if a.alert_type == "disappeared_asset"]

    seen_cves = set()
    recommendations = []
    for v in sorted(vulns, key=lambda x: SEVERITY_ORDER.index(x.severity.lower()) if x.severity.lower() in SEVERITY_ORDER else 99):
        if v.cve_id and v.cve_id not in seen_cves:
            seen_cves.add(v.cve_id)
            recommendations.append({
                "cve_id": v.cve_id,
                "name": v.name,
                "severity": v.severity,
                "guidance": SEVERITY_RECOMMENDATIONS.get(v.severity.lower(), "Review and remediate per vendor guidance."),
            })

    key_findings = []
    if severity_counts["critical"] > 0:
        key_findings.append(f"{severity_counts['critical']} critical vulnerability(ies) identified requiring immediate attention.")
    if severity_counts["high"] > 0:
        key_findings.append(f"{severity_counts['high']} high severity finding(s) detected across the attack surface.")
    if new_assets:
        key_findings.append(f"{len(new_assets)} new asset(s) discovered since the previous scan, expanding the attack surface.")
    if disappeared_assets:
        key_findings.append(f"{len(disappeared_assets)} previously known asset(s) are no longer reachable.")
    if not key_findings:
        key_findings.append("No critical or high severity findings identified in this scan cycle.")

    tls_findings = [v for v in vulns if v.vuln_type == "tls-misconfiguration"]
    technologies = sorted({tech for a in assets if a.status != "disappeared" for tech in (a.technologies or [])})

    return {
        "target": target,
        "scan": scan,
        "duration": duration,
        "assets": assets,
        "vulnerabilities": vulns,
        "severity_counts": severity_counts,
        "risk_rating": calculate_risk_rating(vulns),
        "key_findings": key_findings,
        "new_assets": new_assets,
        "changed_assets": changed_assets,
        "disappeared_assets": disappeared_assets,
        "recommendations": recommendations,
        "generated_at": datetime.now(timezone.utc),
        "whois_data": target.whois_data if target else None,
        "technologies": technologies,
        "tls_findings": tls_findings,
    }

def generate_pdf_report(db: Session, scan_id: int) -> bytes:
    context = build_report_context(db, scan_id)
    env = Environment(loader=FileSystemLoader("backend/templates"))
    template = env.get_template("report.html")
    html_content = template.render(**context)
    pdf_bytes = HTML(string=html_content).write_pdf()
    return pdf_bytes
