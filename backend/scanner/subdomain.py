import re
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


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


def _subfinder(domain: str, rate_limit: int = 10):
    """Returns (subdomains, status): ok | empty | timeout | not installed | failed: ..."""
    start = time.time()
    try:
        result = _run_with_process_group_cleanup(
            ["subfinder", "-d", domain, "-silent", "-rate-limit", str(rate_limit), "-json"],
            timeout=_env_int("ASM_SUBFINDER_TIMEOUT", 120, 10, 900),
        )
        subdomains = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", ""))
                except json.JSONDecodeError:
                    subdomains.append(line.strip())
        clean = [normalize_hostname(s, domain) for s in subdomains]
        clean = sorted({s for s in clean if s})
        logger.info(f"[subfinder] domain={domain} status=ok results={len(clean)} duration={time.time() - start:.2f}s")
        return clean, ("ok" if clean else "empty")
    except subprocess.TimeoutExpired:
        logger.error(f"[subfinder] domain={domain} status=timeout duration={time.time() - start:.2f}s")
        return [], "timeout"
    except FileNotFoundError:
        logger.error("[subfinder] tool_not_found")
        return [], "not installed"
    except Exception as e:  # noqa: BLE001
        logger.error(f"[subfinder] domain={domain} status=failed error={e}")
        return [], f"failed: {type(e).__name__}"


def _amass(domain: str):
    """Passive amass enumeration, a secondary source. Bounded by ASM_AMASS_TIMEOUT (seconds, default 90) so a
    hung engine cannot hold up every scan. Returns (subdomains, status)."""
    if os.getenv("ASM_AMASS_ENABLED", "true").strip().lower() in ("0", "false", "no", "off"):
        return [], "skipped (disabled by ASM_AMASS_ENABLED)"
    start = time.time()
    try:
        result = _run_with_process_group_cleanup(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
            timeout=_env_int("ASM_AMASS_TIMEOUT", 90, 20, 900),
        )
        subdomains = []
        for line in result.stdout.strip().split("\n"):
            host = normalize_hostname(line, domain)
            if host:
                subdomains.append(host)
        found = sorted(set(subdomains))
        logger.info(f"[amass] domain={domain} status=ok results={len(found)} duration={time.time() - start:.2f}s")
        return found, ("ok" if found else "empty")
    except subprocess.TimeoutExpired:
        logger.error(f"[amass] domain={domain} status=timeout duration={time.time() - start:.2f}s")
        return [], "timeout"
    except FileNotFoundError:
        logger.error("[amass] tool_not_found")
        return [], "not installed"
    except Exception as e:  # noqa: BLE001
        logger.error(f"[amass] domain={domain} status=failed error={e}")
        return [], f"failed: {type(e).__name__}"


def run_subfinder(domain: str, rate_limit: int = 10) -> List[str]:
    """Run subfinder against domain. Returns list of subdomains."""
    return _subfinder(domain, rate_limit)[0]


def run_amass(domain: str) -> List[str]:
    """Run amass passive enumeration. Returns list of subdomains."""
    return _amass(domain)[0]


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
    # Tool output is attacker-influenced (wildcard zones, hostile sub-zones): only plain hostname
    # characters, and never a leading "-" that a downstream CLI could read as an option.
    if not host or host.startswith("-") or not re.fullmatch(r"[a-z0-9._-]+", host):
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
        sf_future = executor.submit(_subfinder, domain, rate_limit)
        am_future = executor.submit(_amass, domain)
        subfinder_results, results["module_status"]["subfinder"] = sf_future.result()
        amass_results, results["module_status"]["amass"] = am_future.result()

    # Always include the apex domain itself as a scan candidate, regardless
    # of what subfinder/amass find -- otherwise private/local-only domains
    # (or public domains with zero discoverable subdomains) never get scanned
    # at all, since these tools only report *discovered* subdomains.
    all_subdomains = list(set(subfinder_results + amass_results + [domain.strip().lower()]))
    results["subdomains"] = sorted(all_subdomains)

    logger.info(f"[SCAN] END subdomain_enumeration domain={domain} results={len(all_subdomains)}")
    return results
