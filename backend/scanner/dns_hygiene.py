"""DNS hygiene of a domain's own zone: dangling name servers, certificate-authority policy (CAA) and DNSSEC.

Public DNS lookups only; nothing is sent to the target's servers other than ordinary resolver traffic.

* Dangling name server: an NS record that names a host which does not exist. Whoever registers that name can answer
  for the whole zone, so this is reported as high severity.
* CAA: without a CAA record any certificate authority may issue for the domain. Informational.
* DNSSEC: no DS record at the parent means answers are not signed. Informational.

NS and DNSSEC apply only to a zone apex (a name that has its own SOA); a plain host name inside a zone is skipped
instead of being reported as lacking them.
"""
import logging
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

_ABSENT = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


def _resolver(resolver=None):
    res = resolver or dns.resolver.Resolver()
    res.lifetime = 5
    return res


def _lookup(name: str, rtype: str, resolver) -> Optional[list]:
    """Records, [] when the name or type is authoritatively absent, None when the lookup itself failed."""
    try:
        return list(resolver.resolve(name, rtype))
    except _ABSENT:
        return []
    except (dns.exception.DNSException, OSError):
        return None


def _finding(slug: str, name: str, severity: str, description: str, domain: str, matched_at: str) -> Dict:
    return {"template_id": slug, "name": name, "severity": severity, "description": description,
            "matched_at": matched_at, "vuln_type": "dns-hygiene",
            "tags": ["dns-hygiene", "posture", "dns"], "host": domain, "cve_id": None, "cvss_score": None}


def check_dangling_ns(domain: str, resolver) -> List[Dict]:
    out: List[Dict] = []
    for rr in _lookup(domain, "NS", resolver) or []:
        ns = str(rr.target).rstrip(".").lower()
        try:
            resolver.resolve(ns, "A")
            continue
        except dns.resolver.NoAnswer:
            try:
                resolver.resolve(ns, "AAAA")
                continue
            except dns.resolver.NoAnswer:
                continue                      # the name exists but has neither record we asked for: not dangling
            except (dns.exception.DNSException, OSError):
                continue
        except dns.resolver.NXDOMAIN:
            out.append(_finding(
                "dns-ns-dangling", "Name server does not exist", "high",
                f"The zone delegates to {ns}, but that name does not exist. Anyone who registers it can answer "
                "DNS queries for the domain and redirect its web and mail traffic. Remove the NS record or "
                "point it at a name server you control.", domain, f"{domain} NS {ns}"))
        except (dns.exception.DNSException, OSError):
            continue                          # could not tell: never guess a high-severity finding
    return out


def check_caa(domain: str, resolver) -> List[Dict]:
    """CAA is looked up the way a CA does: at the name, then each parent, stopping before the bare TLD."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        recs = _lookup(".".join(labels[i:]), "CAA", resolver)
        if recs is None:
            return []                         # lookup error: say nothing rather than guess
        if recs:
            return []
    return [_finding("dns-caa-missing", "No CAA record", "info",
                     "A CAA record limits which certificate authorities may issue certificates for the domain, "
                     "which narrows the damage of a mis-issued certificate. None is published.",
                     domain, f"{domain} CAA")]


def check_dnssec(domain: str, resolver) -> List[Dict]:
    ds = _lookup(domain, "DS", resolver)
    if ds is None or ds:
        return []
    return [_finding("dns-dnssec-missing", "DNSSEC is not enabled", "info",
                     "The parent zone has no DS record for this domain, so its DNS answers are not signed and "
                     "cannot be validated. DNSSEC is optional; it protects against forged DNS responses.",
                     domain, f"{domain} DS")]


def run_dns_hygiene(domain: str, resolver=None) -> Dict:
    domain = (domain or "").strip().rstrip(".").lower()
    result: Dict = {"findings": [], "module_status": "ok"}
    if not domain:
        result["module_status"] = "no domain provided"
        return result
    res = _resolver(resolver)
    soa = _lookup(domain, "SOA", res)
    if soa is None:
        result["module_status"] = "failed: DNS lookup error"
        return result
    findings: List[Dict] = []
    if soa:                                    # a zone apex: delegation and DNSSEC are meaningful here
        findings += check_dangling_ns(domain, res)
        findings += check_dnssec(domain, res)
    findings += check_caa(domain, res)
    result["findings"] = findings
    return result
