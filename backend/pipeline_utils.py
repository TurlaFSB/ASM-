"""Pure helpers that carry data between scan stages (unit-testable, no I/O)."""
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

COMMON_WEB_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8180, 8443, 8888, 9090}
TLS_SERVICE_HINTS = ("ssl", "https", "tls")


def is_web_port(p: Dict) -> bool:
    svc = (p.get("service") or "").lower()
    return "http" in svc or p.get("port") in COMMON_WEB_PORTS


def build_web_targets(port_hosts: List[Dict], fallback_hosts: List[str]) -> List[str]:
    """host:port probe targets from nmap results. Falls back to bare hosts only
    when the port scan produced nothing at all (so a failed nmap still probes 80/443)."""
    targets: List[str] = []
    for h in port_hosts:
        for p in h.get("ports", []):
            if (p.get("protocol") or "tcp") == "tcp" and is_web_port(p):
                targets.append(f"{h['subdomain']}:{p['port']}")
    if not targets:
        return list(dict.fromkeys(fallback_hosts))
    return list(dict.fromkeys(targets))


def tls_targets_from_urls(urls: List[str]) -> List[Tuple[str, int]]:
    """(host, port) for every confirmed https URL httpx found."""
    out: List[Tuple[str, int]] = []
    for u in urls:
        pu = urlparse(u)
        if pu.scheme == "https" and pu.hostname:
            out.append((pu.hostname, pu.port or 443))
    return list(dict.fromkeys(out))


def merge_http_info(http_hosts: List[Dict]) -> Dict[str, Dict]:
    """Aggregate every URL httpx found per host (IP or name) into one record:
    union of technologies; status/title taken from the preferred URL (80/443 first)."""
    by_host: Dict[str, List[Dict]] = {}
    for h in http_hosts:
        key = h.get("host") or ""
        by_host.setdefault(key, []).append(h)
        inp = (h.get("input") or "").split(":")[0]
        if inp and inp != key:
            by_host.setdefault(inp, []).append(h)

    def rank(h):
        port = urlparse(h.get("url", "")).port
        return (0 if port in (None, 80, 443) else 1, h.get("url", ""))

    merged: Dict[str, Dict] = {}
    for key, entries in by_host.items():
        entries = sorted({id(e): e for e in entries}.values(), key=rank)
        techs = sorted({t for e in entries for t in (e.get("technologies") or [])})
        primary = entries[0]
        merged[key] = {
            "technologies": techs,
            "status_code": primary.get("status_code"),
            "title": primary.get("title", ""),
            "urls": [e.get("url") for e in entries if e.get("url")],
        }
    return merged


def pipeline_trusted_for_removals(module_results: Dict, internal_target: bool) -> bool:
    """Only mark assets 'disappeared' when discovery actually worked; a DNS/subdomain
    failure must never look like 'everything vanished'."""
    dns = str(module_results.get("dns", ""))
    if internal_target:
        return dns.startswith("resolved")
    return dns == "ok" and str(module_results.get("subfinder", "")) == "ok"
