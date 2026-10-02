import subprocess
import json
import logging
import tempfile
import os
import time
from typing import List, Dict
from backend.scanner.subdomain import _run_with_process_group_cleanup


logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Nuclei scan profiles
#
# ASM:
#   Fast continuous attack surface monitoring.
#
# VAPT:
#   Deeper manual assessment.
#
# INTERNAL:
#   Internal enterprise infrastructure.
# ------------------------------------------------------------------

ASM_TAGS = [
    "exposure",
    "misconfig",
    "panel",
    "takeover",
    "default-login",
    "config",
    "files",
    "cve",
]

VAPT_TAGS = ASM_TAGS + [
    "sqli",
    "xss",
    "rce",
    "lfi",
    "ssrf",
    "xxe",
    "ssti",
    "cmdi",
    "idor",
    "auth-bypass",
    "jwt",
]

INTERNAL_TAGS = ASM_TAGS + [
    "network",
    "smb",
    "ldap",
    "rdp",
    "ftp",
    "ssh",
    "redis",
    "mongodb",
    "elasticsearch",
    "docker",
    "kubernetes",
    "jenkins",
]


DEFAULT_SCAN_PROFILE = ASM_TAGS



NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "1800"))
NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "info,low,medium,high,critical")
# Automatic scan: nuclei fingerprints each target (Wappalyzer) and runs only the templates
# relevant to the detected technologies. Set NUCLEI_AUTOSCAN=false to use the fixed tag profile.
NUCLEI_AUTOSCAN = os.getenv("NUCLEI_AUTOSCAN", "true").lower() != "false"
# Default is 30: a small/slow host that drops 30 requests is abandoned and its remaining
# templates silently never run. Raise it, and report when it still happens.
NUCLEI_MAX_HOST_ERROR = os.getenv("NUCLEI_MAX_HOST_ERROR", "100")
NUCLEI_CONCURRENCY = os.getenv("NUCLEI_CONCURRENCY", "15")

# info-severity results are kept only when they are attack-surface exposures; pure
# technology/WAF/version detections are already captured by httpx/whatweb/nmap.
INFO_KEEP_TAGS = {"panel", "exposure", "misconfig", "takeover", "default-login", "config", "files"}


# nmap service name -> nuclei tags. Lets nuclei run service-specific checks (e.g. the
# UnrealIRCd backdoor, ProFTPD mod_copy, Samba, MySQL) that web-only scanning never reaches.
SERVICE_TAGS = {
    "ftp": ["ftp"], "ssh": ["ssh"], "mysql": ["mysql"], "irc": ["irc", "unrealircd"],
    "netbios-ssn": ["smb", "samba"], "microsoft-ds": ["smb", "samba"], "smb": ["smb", "samba"],
    "rpcbind": ["rpc"], "ipp": ["cups"], "postgresql": ["postgres"], "redis": ["redis"],
    "mongodb": ["mongodb"], "vnc": ["vnc"], "telnet": ["telnet"], "smtp": ["smtp"],
    "snmp": ["snmp"], "ldap": ["ldap"], "ms-wbt-server": ["rdp"], "memcached": ["memcached"],
    "nfs": ["nfs"], "domain": ["dns"],
}


def network_tags_from_services(port_hosts: List[Dict]) -> List[str]:
    tags = set()
    for h in port_hosts:
        for p in h.get("ports", []):
            svc = (p.get("service") or "").lower()
            if svc in SERVICE_TAGS:
                tags.update(SERVICE_TAGS[svc])
    return sorted(tags)


def keep_finding(f: Dict) -> bool:
    if (f.get("severity") or "").lower() != "info":
        return True
    tags = f.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return bool({str(t).lower() for t in tags} & INFO_KEEP_TAGS)


def build_nuclei_cmd(targets_path: str, out_path: str, rate_limit: int, tags=None):
    cmd = [
        "nuclei", "-nc",              # NOT -silent: warnings (e.g. host skipped) must reach stderr
        "-l", targets_path,
        "-rate-limit", str(rate_limit),
        "-c", NUCLEI_CONCURRENCY,
        "-mhe", NUCLEI_MAX_HOST_ERROR,
        "-retries", "1",
        "-ni",                        # no interactsh/OAST
        "-duc",                       # no update check at scan time
        "-timeout", "10",
        "-severity", NUCLEI_SEVERITY,
    ]
    if tags:                      # explicit service tags (network-service pass)
        cmd += ["-tags", ",".join(tags)]
    else:
        cmd += ["-as"] if NUCLEI_AUTOSCAN else ["-tags", ",".join(DEFAULT_SCAN_PROFILE)]
    cmd += ["-jsonl-export", out_path]
    return cmd




def _read_findings(path: str) -> List[Dict]:
    """Parse nuclei's JSONL export. Used for both normal completion and for salvaging
    findings written before a timeout."""
    findings: List[Dict] = []
    if not path or not os.path.exists(path):
        return findings
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("[nuclei] Skipping malformed JSON line.")
                continue
            if not isinstance(data, dict):
                continue
            info = data.get("info", {})
            classification = info.get("classification", {}) or {}
            cve_ids = classification.get("cve-id") or []
            findings.append({
                "host": data.get("host", ""),
                "template_id": data.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", ""),
                "description": info.get("description", ""),
                "matched_at": data.get("matched-at", ""),
                "type": data.get("type", ""),
                "tags": info.get("tags", []),
                "cvss_score": classification.get("cvss-score"),
                "cvss_metrics": classification.get("cvss-metrics"),
                "cve_id": cve_ids[0] if cve_ids else None,
            })
    return findings


def _summarize(result: Dict) -> None:
    result["total"] = len(result["findings"])
    counts: Dict[str, int] = {}
    for f in result["findings"]:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    result["severity_counts"] = counts


TEMPLATE_DIRS = ("~/nuclei-templates", "~/.local/nuclei-templates")


def template_count() -> int:
    """Number of nuclei template files installed (0 means nuclei would silently run nothing)."""
    for d in TEMPLATE_DIRS:
        root = os.path.expanduser(d)
        if os.path.isdir(root):
            n = 0
            for _, _, files in os.walk(root):
                n += sum(1 for f in files if f.endswith((".yaml", ".yml")))
            if n:
                return n
    return 0


def check_template_freshness(max_age_days: int = 7) -> str:
    """
    Check whether local Nuclei templates are reasonably fresh.
    Templates should be updated outside the scan pipeline.
    """
    template_dir = next((os.path.expanduser(d) for d in TEMPLATE_DIRS
                         if os.path.isdir(os.path.expanduser(d))), os.path.expanduser(TEMPLATE_DIRS[0]))

    if not os.path.isdir(template_dir):
        return "templates_not_found"

    mtime = os.path.getmtime(template_dir)
    age_days = (time.time() - mtime) / 86400

    if age_days > max_age_days:
        logger.warning(
            f"Nuclei templates are {age_days:.1f} days old "
            f"(threshold: {max_age_days}d). "
            f"Run: nuclei -update-templates"
        )
        return f"stale ({age_days:.0f}d old)"

    return "fresh"


def run_nuclei(hosts: List[str], rate_limit: int = 50, tags=None) -> Dict:
    """
    Run Nuclei against a list of confirmed HTTP endpoints.
    Returns structured vulnerability data.
    """

    result = {
        "findings": [],
        "module_status": "ok",
        "total": 0,
        "template_freshness": check_template_freshness(),
    }

    # Remove duplicate targets
    hosts = sorted(
        {
            h.strip()
            for h in hosts
            if h and h.strip()
        }
    )

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    n_templates = template_count()
    result["template_count"] = n_templates
    if n_templates == 0:
        logger.error("[nuclei] NO TEMPLATES INSTALLED -- refusing to report an empty scan as success. "
                     "Rebuild the image or run: nuclei -update-templates")
        result["module_status"] = "failed: no nuclei templates installed"
        return result
    logger.info(f"[nuclei] templates installed: {n_templates}")

    tmp_path = None
    targets_path = None
    start = time.time()

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
        ) as tmp:
            targets_path = tmp.name
            tmp.write("\n".join(hosts))
            tmp.flush()
            os.fsync(tmp.fileno())

        import shutil
        _mem_snapshot = shutil.os.popen("free -h").read().strip()
        logger.info(f"[nuclei] pre-run memory:\n{_mem_snapshot}")
        logger.info(
            f"[nuclei] scanning {len(hosts)} hosts using {targets_path}"
        )

        nuclei_result = _run_with_process_group_cleanup(
            build_nuclei_cmd(targets_path, tmp_path, rate_limit, tags),
            timeout=NUCLEI_TIMEOUT,
        )

        if nuclei_result.returncode != 0:
            duration = time.time() - start

            logger.error(
                f"[nuclei] "
                f"returncode={nuclei_result.returncode} "
                f"duration={duration:.2f}s"
            )

            if nuclei_result.stderr:
                logger.error(nuclei_result.stderr.strip())

            result["module_status"] = "failed"
            return result

        result["findings"] = [f for f in _read_findings(tmp_path) if keep_finding(f)]
        _summarize(result)
        stderr_txt = nuclei_result.stderr or ""
        skipped_hosts = "unresponsive" in stderr_txt
        if skipped_hosts:
            logger.warning("[nuclei] host(s) skipped as unresponsive -- results are INCOMPLETE")
            result["module_status"] = "partial (host skipped as unresponsive; lower the scan rate)"

        if result["total"] == 0 and not skipped_hosts:
            result["module_status"] = "empty"
            tail = (nuclei_result.stderr or "").strip()[-600:]
            logger.warning(f"[nuclei] 0 findings with {n_templates} templates; stderr tail: {tail!r}")

        duration = time.time() - start

        logger.info(
            f"[nuclei] "
            f"hosts_in={len(hosts)} "
            f"status={result['module_status']} "
            f"findings={result['total']} "
            f"duration={duration:.2f}s"
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        result["findings"] = [f for f in _read_findings(tmp_path) if keep_finding(f)]  # keep what was found before the cap
        _summarize(result)
        logger.error(
            f"[nuclei] hosts_in={len(hosts)} status=timeout after {NUCLEI_TIMEOUT}s "
            f"(salvaged {result['total']} findings) duration={duration:.2f}s"
        )
        result["module_status"] = (
            f"partial (timeout, {result['total']} findings kept)" if result["total"] else "timeout"
        )

    except FileNotFoundError:
        logger.error("[nuclei] tool_not_found")
        result["module_status"] = "tool_not_found"

    except Exception as e:
        duration = time.time() - start

        logger.error(
            f"[nuclei] "
            f"hosts_in={len(hosts)} "
            f"status=failed "
            f"error={e} "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = f"failed: {e}"

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

        if targets_path and os.path.exists(targets_path):
            os.unlink(targets_path)

    return result