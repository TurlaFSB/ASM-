"""
sslyze integration -- TLS/SSL configuration analysis.
Runs sslyze's Python API against each live HTTPS host, translates findings into
the same Vulnerability shape Nuclei findings use, so both sources sort/group
together in the UI. Not a Nuclei wrapper -- sslyze inspects protocol/cipher/cert
config directly, catching classes of issues Nuclei's template-based scanning doesn't.
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict

from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ServerScanStatusEnum
from sslyze.errors import ServerHostnameCouldNotBeResolved

logger = logging.getLogger(__name__)

_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")

# (attribute_name_on_scan_result, protocol_label, severity)
_LEGACY_PROTOCOLS = [
    ("ssl_2_0_cipher_suites", "SSLv2", "critical"),
    ("ssl_3_0_cipher_suites", "SSLv3", "high"),
    ("tls_1_0_cipher_suites", "TLSv1.0", "medium"),
    ("tls_1_1_cipher_suites", "TLSv1.1", "medium"),
]


def _build_finding(template_id, name, severity, description, host, matched_at, cve_id=None):
    return {
        "template_id": template_id,
        "name": name,
        "severity": severity,
        "description": description,
        "matched_at": matched_at,
        "vuln_type": "tls-misconfiguration",
        "tags": ["ssl", "tls", "sslyze"],
        "host": host,
        "cve_id": cve_id,
        "cvss_score": None,
    }


def _extract_findings(host: str, cmds) -> List[Dict]:
    findings = []
    matched_at = f"{host}:443"

    # --- Legacy protocol support ---
    for attr, label, severity in _LEGACY_PROTOCOLS:
        attempt = getattr(cmds, attr, None)
        if attempt is None or attempt.result is None:
            continue
        if attempt.result.accepted_cipher_suites:
            findings.append(_build_finding(
                template_id=f"sslyze-protocol-{label.lower().replace('.', '')}",
                name=f"Deprecated {label} protocol supported",
                severity=severity,
                description=f"Server accepts connections using {label}, a deprecated and insecure protocol version.",
                host=host,
                matched_at=matched_at,
            ))

    # --- Weak ciphers (checked across TLS 1.0-1.2; TLS 1.3 has no weak-cipher legacy suites) ---
    weak_ciphers_found = set()
    for attr in ("tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites"):
        attempt = getattr(cmds, attr, None)
        if attempt is None or attempt.result is None:
            continue
        for accepted in attempt.result.accepted_cipher_suites:
            cipher_name = accepted.cipher_suite.name
            if any(marker in cipher_name for marker in _WEAK_CIPHER_MARKERS):
                weak_ciphers_found.add(cipher_name)
    if weak_ciphers_found:
        findings.append(_build_finding(
            template_id="sslyze-weak-cipher",
            name="Weak cipher suite(s) supported",
            severity="medium",
            description=f"Server accepts weak cipher suite(s): {', '.join(sorted(weak_ciphers_found))}",
            host=host,
            matched_at=matched_at,
        ))

    # --- Certificate issues ---
    ci_attempt = cmds.certificate_info
    if ci_attempt.result and ci_attempt.result.certificate_deployments:
        deployment = ci_attempt.result.certificate_deployments[0]
        chain = deployment.received_certificate_chain
        if chain:
            leaf = chain[0]
            now = datetime.now(timezone.utc)
            if leaf.not_valid_after_utc < now:
                days_expired = (now - leaf.not_valid_after_utc).days
                findings.append(_build_finding(
                    template_id="sslyze-expired-cert",
                    name="Expired SSL/TLS certificate",
                    severity="critical",
                    description=f"Certificate expired {days_expired} day(s) ago (not valid after {leaf.not_valid_after_utc.isoformat()}).",
                    host=host,
                    matched_at=matched_at,
                ))
        if deployment.verified_chain_has_sha1_signature:
            findings.append(_build_finding(
                template_id="sslyze-sha1-signature",
                name="Certificate chain uses SHA-1 signature",
                severity="medium",
                description="Certificate chain contains a SHA-1 signature, considered cryptographically weak and deprecated.",
                host=host,
                matched_at=matched_at,
            ))

    # --- Heartbleed ---
    hb_attempt = cmds.heartbleed
    if hb_attempt.result and hb_attempt.result.is_vulnerable_to_heartbleed:
        findings.append(_build_finding(
            template_id="sslyze-heartbleed",
            name="Vulnerable to Heartbleed",
            severity="critical",
            description="Server is vulnerable to Heartbleed (CVE-2014-0160), allowing an attacker to read server memory including private keys and session data.",
            host=host,
            matched_at=matched_at,
            cve_id="CVE-2014-0160",
        ))

    return findings


def run_sslyze(hosts: List[str], timeout: int = 30) -> Dict:
    """
    hosts: list of bare hostnames (NOT urls -- sslyze connects directly on port 443,
    it doesn't parse http:// or https:// prefixes).
    """
    result = {"findings": [], "module_status": "ok"}
    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    scanner = Scanner()
    valid_requests = []
    for host in hosts:
        try:
            location = ServerNetworkLocation(hostname=host, port=443)
            valid_requests.append(ServerScanRequest(server_location=location))
        except ServerHostnameCouldNotBeResolved:
            logger.warning(f"[sslyze] could not resolve {host}, skipping")
        except Exception as e:
            logger.warning(f"[sslyze] error queuing {host}: {e}")

    if not valid_requests:
        result["module_status"] = "no resolvable hosts"
        return result

    scanner.queue_scans(valid_requests)

    scanned = 0
    for scan_result in scanner.get_results():
        host = scan_result.server_location.hostname
        if scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            logger.warning(f"[sslyze] scan not completed for {host}: {scan_result.scan_status}")
            continue
        try:
            findings = _extract_findings(host, scan_result.scan_result)
            result["findings"].extend(findings)
            scanned += 1
        except Exception as e:
            logger.warning(f"[sslyze] error extracting findings for {host}: {e}")

    if scanned == 0:
        result["module_status"] = "empty"

    logger.info(f"[sslyze] scanned={scanned}/{len(hosts)} findings={len(result['findings'])}")
    return result
