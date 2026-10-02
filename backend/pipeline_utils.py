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


def run_stages_parallel(jobs: Dict[str, Optional[callable]], defaults: Dict[str, Dict],
                        max_workers: int = 6, parallel: bool = True):
    """Run independent scanner stages concurrently (they only read the confirmed web
    targets and never touch the DB). A crashing stage degrades to its default result with
    a failed status instead of killing the scan. Returns (results, timings)."""
    import time
    from concurrent.futures import ThreadPoolExecutor

    results: Dict[str, Dict] = {}
    timings: Dict[str, float] = {}

    def _run(name, fn):
        t0 = time.time()
        try:
            res = fn()
        except Exception as e:  # noqa: BLE001
            res = {**defaults.get(name, {}), "module_status": f"failed: {e}"}
        return name, res, round(time.time() - t0, 2)

    active = {k: v for k, v in jobs.items() if v is not None}
    if parallel and len(active) > 1:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(active))) as ex:
            for name, res, dt in ex.map(lambda kv: _run(*kv), active.items()):
                results[name], timings[name] = res, dt
    else:
        for kv in active.items():
            name, res, dt = _run(*kv)
            results[name], timings[name] = res, dt
    return results, timings


def effective_rate(rate_limit: int, multiplier_env: Optional[str] = None, cap: int = 1000) -> int:
    """Target.rate_limit is a polite default (10 req/s). For lab/internal scans the operator
    can raise throughput for the heavy tools with ASM_RATE_MULTIPLIER (default 1 = unchanged)."""
    import os
    raw = multiplier_env if multiplier_env is not None else os.getenv("ASM_RATE_MULTIPLIER", "1")
    try:
        mult = max(1.0, float(raw))
    except ValueError:
        mult = 1.0
    return max(1, min(int(rate_limit * mult), cap))


def merge_known_ports(previous, current):
    """A narrower scan (e.g. top-100 ports) must not 'close' ports a wider scan found earlier.
    Union by port number; the fresh observation wins for ports seen in both."""
    merged = {p["port"]: p for p in (previous or []) if isinstance(p, dict) and "port" in p}
    for p in current or []:
        merged[p["port"]] = p
    return [merged[k] for k in sorted(merged)]


def merge_known_technologies(previous, current):
    """Same idea for technologies when a profile skips the tech-fingerprinting stage."""
    return sorted(set(previous or []) | set(current or []))
