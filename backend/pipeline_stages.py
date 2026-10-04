"""Building blocks of the scan pipeline, kept free of Celery so each one can be unit-tested on its own.

`tasks.run_scan` strings these together: it owns the lock, the guard thread and the try/except/finally
bookkeeping, while everything that decides or transforms data lives here.
"""
import ipaddress
import logging
import socket
from typing import Dict, List, Optional, Tuple

from backend.validators import INTERNAL_SUFFIXES, classify_target

logger = logging.getLogger(__name__)


def is_internal_target(domain: str) -> bool:
    """A raw IP or an internal/lab host name: public subdomain discovery cannot find anything for these."""
    return classify_target(domain) == "ip" or domain.lower().endswith(INTERNAL_SUFFIXES)


def enter_stage(task, db, scan, stage: str) -> None:
    """Publish the current stage to Celery and to the scan row (what the UI shows)."""
    task.update_state(state="PROGRESS", meta={"stage": stage})
    if scan:
        scan.current_stage = stage
        db.commit()


def internal_live_hosts(domain: str) -> Tuple[List[Dict], str]:
    """The single 'live host' of an IP/internal target and the DNS status text to record."""
    try:
        ipaddress.ip_address(domain)
        resolved = domain
    except ValueError:
        try:
            resolved = socket.gethostbyname(domain)
        except socket.gaierror as e:
            logger.warning(f"[pipeline] Could not resolve internal hostname {domain}: {e}")
            resolved = None
    if resolved:
        return [{"subdomain": domain, "ip": resolved}], "resolved directly (internal target)"
    return [], "resolution failed"


def extract_cve_id(finding: Dict) -> Optional[str]:
    """Prefer the CVE from nuclei's classification block; fall back to tags, then the template id."""
    cve_id = finding.get("cve_id")
    if cve_id:
        return cve_id
    tags = finding.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if str(tag).upper().startswith("CVE-"):
                return str(tag).upper()
    template_id = finding.get("template_id", "") or ""
    if template_id.upper().startswith("CVE-"):
        return template_id.upper()
    return None


def build_vulnerabilities(findings: List[Dict], target_id: int, scan_id: Optional[int], *,
                          type_key: str = "type", derive_cve: bool = True):
    """Turn scanner findings into unsaved Vulnerability rows (nuclei: type_key='type'; sslyze: 'vuln_type')."""
    from backend.models.vulnerability import Vulnerability
    rows = []
    for f in findings:
        rows.append(Vulnerability(
            target_id=target_id,
            scan_id=scan_id,
            template_id=f.get("template_id", ""),
            name=f.get("name", ""),
            severity=f.get("severity", "info"),
            description=f.get("description", ""),
            matched_at=f.get("matched_at", ""),
            vuln_type=f.get(type_key, ""),
            tags=f.get("tags", []),
            host=f.get("host", ""),
            cve_id=extract_cve_id(f) if derive_cve else f.get("cve_id"),
            cvss_score=f.get("cvss_score"),
        ))
    return rows


def collect_web_results(stage_results: Dict, prof, enable_dirbuster: bool, http_data: Dict,
                        module_results: Dict) -> Dict:
    """Fold the parallel web-analysis outputs into module_results and return the datasets later stages need.

    Mutates `module_results` and merges whatweb technologies into `http_data['hosts']` entries.
    """
    skipped = f"skipped (profile: {prof.name})"
    module_results["profile"] = prof.name

    whatweb_data = stage_results.get("whatweb") or {"hosts": {}, "module_status": skipped}
    module_results["whatweb"] = whatweb_data["module_status"]
    for entry in http_data["hosts"]:
        ww = whatweb_data["hosts"].get(entry.get("url", ""))
        if ww:
            entry["technologies"] = sorted(set(entry.get("technologies", [])) | set(ww.get("technologies", [])))

    if enable_dirbuster:
        dirbuster_data = stage_results["dirbuster"]
        module_results["dirbuster"] = dirbuster_data["module_status"]
    else:
        dirbuster_data = {"hosts": {}, "module_status": "skipped"}
        module_results["dirbuster"] = skipped if not prof.run_dirbuster else "skipped"

    vuln_data = stage_results.get("nuclei") or {"findings": [], "module_status": skipped}
    module_results["vuln"] = vuln_data["module_status"]

    net_data = stage_results.get("nuclei_network")
    if net_data is not None:
        module_results["nuclei_network"] = net_data["module_status"]
        if net_data.get("degraded"):
            module_results["nuclei_network_degraded"] = net_data["degraded"]   # host:ports not fully tested
        vuln_data["findings"] = list(vuln_data.get("findings", [])) + net_data.get("findings", [])
    else:
        module_results["nuclei_network"] = (
            skipped if not prof.run_nuclei_network else "skipped (no recognised network services)")

    cve_data = stage_results.get("cve_match") or {"findings": [], "module_status": skipped}
    module_results["cve_match"] = cve_data["module_status"]
    if cve_data.get("truncated"):
        module_results["cve_truncated"] = cve_data["truncated"]      # report says "N of M shown"
    # version-matched CVEs flow through the same save/score/KEV path as nuclei findings
    vuln_data["findings"] = list(vuln_data.get("findings", [])) + cve_data.get("findings", [])
    module_results["nuclei_templates"] = vuln_data.get("template_count")

    sslyze_data = stage_results.get("sslyze") or {"findings": [], "module_status": skipped}
    module_results["sslyze"] = sslyze_data["module_status"]
    screenshot_data = stage_results.get("screenshot") or {"screenshots": [], "module_status": skipped}
    module_results["screenshot"] = screenshot_data["module_status"]

    return {"dirbuster": dirbuster_data, "vuln": vuln_data, "sslyze": sslyze_data, "screenshot": screenshot_data}


def record_changes_and_alerts(db, scan, module_results: Dict) -> None:
    """Snapshot + diff, advisory AI triage, alerts and webhook digest. Never turns a finished scan into a failed one."""
    try:
        from backend.diffing.service import record_scan_changes
        diff_summary = record_scan_changes(db, scan, module_results)
        module_results["diff"] = ("baseline recorded" if diff_summary.get("baseline")
                                  else f"ok ({diff_summary['events']} changes, {diff_summary['pending']} pending)")
        module_results["diff_detail"] = diff_summary
        logger.info(f"[diff] {module_results['diff']}")
        from backend.ai.triage import triage_scan_events
        ai = triage_scan_events(db, scan)
        module_results["ai_triage"] = ai
        if ai["status"] != "disabled":
            logger.info(f"[ai] {ai}")
        from backend.notifications import notify_scan_changes
        note = notify_scan_changes(db, scan)
        module_results["notify"] = (f"ok ({note['alerts']} alerts, webhook {note['webhook']})"
                                    if note["qualifying"] else "nothing to announce")
        logger.info(f"[notify] {module_results['notify']}")
    except Exception as e:  # noqa: BLE001
        db.rollback()
        logger.exception("[diff] failed to record changes")
        module_results["diff"] = f"failed: {e}"


def seal_record(db, scan, module_results: Dict) -> None:
    """Seal the finished record (signed hash chained to the target's previous seal). Never fatal."""
    try:
        from backend.integrity import seal_scan
        seal = seal_scan(db, scan)
        module_results["integrity"] = f"sealed #{seal.seq}" if seal else "not sealed (no snapshot)"
    except Exception as e:  # noqa: BLE001
        db.rollback()
        logger.exception("[integrity] sealing failed")
        module_results["integrity"] = f"failed: {e}"


def lock_is_stale(redis_client, db, target_id: int, scan_id: Optional[int], cx) -> Tuple[bool, Optional[int]]:
    """A target lock whose owner scan is no longer active (worker killed, restarted, OOM) can be cleared.

    Returns (stale, owner_scan_id).
    """
    from backend.models.scan import Scan
    try:
        raw = redis_client.get(cx.owner_key(target_id))
        owner_id = int(raw) if raw else None
    except Exception:  # noqa: BLE001
        owner_id = None
    if owner_id:
        owner = db.query(Scan).filter(Scan.id == owner_id).first()
        return (owner is None or owner.status not in ("pending", "running")), owner_id
    # Lock taken by code that predates the owner marker (or the marker expired): stale unless some OTHER
    # scan of this target is actually running right now.
    other = db.query(Scan).filter(Scan.target_id == target_id, Scan.status == "running",
                                  Scan.id != scan_id).first()
    return other is None, owner_id
