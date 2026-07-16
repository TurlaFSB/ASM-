"""
Risk scoring engine for ASM Platform.

Methodology (aligned to CVSS v3.1 severity bands, not arbitrary weights):
- Each vulnerability's contribution is its CVSS score if present (0-10 scale),
  else falls back to the CVSS v3.1 severity band midpoint:
    Critical -> 9.0, High -> 7.5, Medium -> 5.0, Low -> 2.5, Info -> 0.5
- Asset base score = MAX(cvss-derived score across all vulns on that asset) * 10
  (max, not sum -- one critical RCE outweighs five informational findings;
  this mirrors how Cortex Xpanse / Censys ASM score assets)
- Modifiers (additive, capped):
    +5 per additional finding at or above High severity beyond the first (max +15)
    +10 if a high-risk exposed port is open (DB/remote-admin ports)
    +5 if HTTP title/status suggests an exposed admin/login surface
- Final score clamped to [0, 100], bucketed into:
    Critical (80-100), High (60-79), Medium (35-59), Low (10-34), Informational (<10)
"""

SEVERITY_CVSS_MIDPOINT = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "informational": 0.5,
}

from backend.kev import is_known_exploited
from urllib.parse import urlparse

HIGH_RISK_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
    1433: "MSSQL", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (SSL)",
    23: "Telnet", 21: "FTP", 2049: "NFS", 1099: "Java RMI",
}

ADMIN_KEYWORDS = ("login", "admin", "panel", "dashboard", "signin", "wp-admin", "manager")


def cvss_for_vuln(vuln) -> float:
    """Return the best available CVSS-equivalent score for a vulnerability record."""
    if getattr(vuln, "cvss_score", None):
        try:
            return float(vuln.cvss_score)
        except (TypeError, ValueError):
            pass
    sev = (vuln.severity or "info").lower()
    return SEVERITY_CVSS_MIDPOINT.get(sev, 0.5)


def score_asset(asset, vulns_for_asset: list) -> dict:
    """
    Compute risk score + level for a single asset given its associated vulnerabilities.
    vulns_for_asset: list of Vulnerability ORM objects matched to this asset's host.
    """
    kev_hit = any(is_known_exploited(v.cve_id) for v in vulns_for_asset if v.cve_id)

    if vulns_for_asset:
        cvss_scores = [cvss_for_vuln(v) for v in vulns_for_asset]
        base_score = max(cvss_scores) * 10  # scale 0-10 CVSS to 0-100
    else:
        base_score = 0.0
        cvss_scores = []

    if kev_hit:
        # Active exploitation confirmed by CISA -- force into Critical band
        # regardless of CVSS, since real-world attacker interest outweighs
        # theoretical severity.
        base_score = max(base_score, 90.0)

    # Modifier: multiple high-severity findings compound risk
    high_or_above = sum(1 for v in vulns_for_asset if (v.severity or "").lower() in ("critical", "high"))
    multi_finding_bonus = min((high_or_above - 1) * 5, 15) if high_or_above > 1 else 0

    # Modifier: high-risk exposed ports
    port_bonus = 0
    open_ports = asset.open_ports or []
    for p in open_ports:
        port_num = p.get("port") if isinstance(p, dict) else p
        if port_num in HIGH_RISK_PORTS:
            port_bonus = 10
            break

    # Modifier: exposed admin/login surface
    admin_bonus = 0
    title = (asset.http_title or "").lower()
    if any(k in title for k in ADMIN_KEYWORDS):
        admin_bonus = 5

    total = base_score + multi_finding_bonus + port_bonus + admin_bonus
    total = max(0.0, min(100.0, total))

    if total >= 80:
        level = "Critical"
    elif total >= 60:
        level = "High"
    elif total >= 35:
        level = "Medium"
    elif total >= 10:
        level = "Low"
    else:
        level = "Informational"

    return {
        "risk_score": round(total, 1),
        "risk_level": level,
        "max_cvss": max(cvss_scores) if cvss_scores else 0.0,
        "finding_count": len(vulns_for_asset),
        "known_exploited": kev_hit,
    }


def _extract_host(url_or_host: str) -> str:
    """Get bare hostname from a URL or already-bare host string."""
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or ""
    return url_or_host.split("/")[0].split(":")[0]


def score_all_assets(db, target_id: int, scan_id: int):
    """
    Score every asset belonging to target_id using vulnerabilities from scan_id.
    Persists risk_score/risk_level to each Asset row. Call after vuln findings
    are saved to DB for the scan.
    """
    from backend.models.asset import Asset
    from backend.models.vulnerability import Vulnerability

    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    vulns_by_host = {}
    for v in vulns:
        host = _extract_host(v.host or "")
        if host:
            vulns_by_host.setdefault(host.lower(), []).append(v)

    for asset in assets:
        matched = vulns_by_host.get((asset.subdomain or "").lower(), [])
        result = score_asset(asset, matched)
        asset.risk_score = result["risk_score"]
        asset.risk_level = result["risk_level"]

    db.commit()
