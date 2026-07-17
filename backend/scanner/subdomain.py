import subprocess
import os
import signal
import json
import logging
import time
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


def _run_with_process_group_cleanup(cmd: List[str], timeout: int, input_text: str = None) -> subprocess.CompletedProcess:
    """
    Run a subprocess in its own process group so that on timeout we can kill
    the entire tree (parent + any child engine processes it spawns), not just
    the direct child. Some tools (e.g. Amass) launch a long-lived "engine"
    process that survives a plain subprocess.run(timeout=...) kill, since
    Python only terminates the immediate child PID.

    On timeout: SIGTERM the whole group, wait briefly, SIGKILL if still alive.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,  # new process group -- required for group-wide signaling
    )
    try:
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        pgid = os.getpgid(proc.pid)
        logger.warning(f"Timeout on {cmd[0]} (pgid={pgid}) -- sending SIGTERM to process group")
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning(f"{cmd[0]} still alive after SIGTERM -- sending SIGKILL to process group")
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
        raise


def run_subfinder(domain: str, rate_limit: int = 10) -> List[str]:
    """Run subfinder against domain. Returns list of subdomains."""
    start = time.time()
    try:
        result = _run_with_process_group_cleanup(
            ["subfinder", "-d", domain, "-silent", "-rate-limit", str(rate_limit), "-json"],
            timeout=120,
        )

        subdomains = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", ""))
                except json.JSONDecodeError:
                    subdomains.append(line.strip())

        duration = time.time() - start
        clean = [normalize_hostname(s, domain) for s in subdomains]
        clean = [s for s in clean if s]
        logger.info(f"[subfinder] domain={domain} status=ok results={len(clean)} duration={duration:.2f}s")
        return list(set(clean))

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        logger.error(f"[subfinder] domain={domain} status=timeout duration={duration:.2f}s")
        return []
    except FileNotFoundError:
        logger.error("[subfinder] tool_not_found")
        return []
    except Exception as e:
        logger.error(f"[subfinder] domain={domain} status=failed error={e}")
        return []


def run_amass(domain: str) -> List[str]:
    """Run amass passive enumeration. Returns list of subdomains."""
    start = time.time()
    try:
        result = _run_with_process_group_cleanup(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
            timeout=150,
        )

        subdomains = []
        for line in result.stdout.strip().split("\n"):
            host = normalize_hostname(line, domain)
            if host:
                subdomains.append(host)

        duration = time.time() - start
        logger.info(f"[amass] domain={domain} status=ok results={len(subdomains)} duration={duration:.2f}s")
        return list(set(subdomains))

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        logger.error(f"[amass] domain={domain} status=timeout duration={duration:.2f}s")
        return []
    except FileNotFoundError:
        logger.error("[amass] tool_not_found")
        return []
    except Exception as e:
        logger.error(f"[amass] domain={domain} status=failed error={e}")
        return []


def normalize_hostname(raw: str, domain: str) -> str:
    """
    Normalize and validate a discovered hostname against the target domain
    using proper suffix-boundary matching, not substring matching.
    'vulnweb.com.attacker.example' contains 'vulnweb.com' as a substring but
    is not a subdomain of it -- only exact match or a '.' + domain suffix counts.
    """
    if not raw:
        return ""
    host = raw.strip().lower().rstrip(".")
    if not host:
        return ""
    domain_l = domain.strip().lower().rstrip(".")
    if host == domain_l or host.endswith("." + domain_l):
        return host
    return ""


def enumerate_subdomains(domain: str, rate_limit: int = 10) -> Dict:
    """
    Run all subdomain enumeration tools and merge results.
    Returns dict with subdomains list and per-tool status.
    """
    results = {
        "domain": domain,
        "subdomains": [],
        "module_status": {
            "subfinder": "ok",
            "amass": "ok"
        }
    }

    logger.info(f"[SCAN] START subdomain_enumeration domain={domain}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        sf_future = executor.submit(run_subfinder, domain, rate_limit)
        am_future = executor.submit(run_amass, domain)

        subfinder_results = sf_future.result()
        amass_results = am_future.result()

    if not subfinder_results:
        results["module_status"]["subfinder"] = "empty"

    if not amass_results:
        results["module_status"]["amass"] = "empty"

    # Always include the apex domain itself as a scan candidate, regardless
    # of what subfinder/amass find -- otherwise private/local-only domains
    # (or public domains with zero discoverable subdomains) never get scanned
    # at all, since these tools only report *discovered* subdomains.
    all_subdomains = list(set(subfinder_results + amass_results + [domain.strip().lower()]))
    results["subdomains"] = sorted(all_subdomains)

    logger.info(f"[SCAN] END subdomain_enumeration domain={domain} results={len(all_subdomains)}")
    return results
