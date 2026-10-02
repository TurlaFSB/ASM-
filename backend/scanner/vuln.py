import subprocess
import json
import logging
import tempfile
import os
import re
import time
from typing import List, Dict


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
# Service-tag (network) pass: many parallel handshakes against one daemon (e.g. old OpenSSH with
# MaxStartups) can get dropped, which makes whole template families flap between scans.
NUCLEI_NETWORK_CONCURRENCY = os.getenv("NUCLEI_NETWORK_CONCURRENCY", "4")
# Second-chance pass for templates that hit transient errors (timeouts/resets) during the network pass
NUCLEI_RETRY_PAUSE = float(os.getenv("NUCLEI_RETRY_PAUSE", "5"))
NUCLEI_RETRY_TIMEOUT = int(os.getenv("NUCLEI_RETRY_TIMEOUT", "150"))
NUCLEI_RETRY_RATE = os.getenv("NUCLEI_RETRY_RATE", "1")
NUCLEI_RETRY_MAX_TARGETS = 5
DEGRADED_MIN_TEMPLATES = 2      # transient errors in at least this many templates => host:port is degraded

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


_EXECUTING_RE = re.compile(r"Executing (\d+) templates? on ")


def templates_executed(stderr: str) -> int:
    """Total template runs nuclei reports ('Executing 148 templates on http://...'). Zero means
    nothing was actually tested, which is what 'empty' is meant to flag."""
    return sum(int(n) for n in _EXECUTING_RE.findall(stderr or ""))


def keep_finding(f: Dict) -> bool:
    if (f.get("severity") or "").lower() != "info":
        return True
    tags = f.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return bool({str(t).lower() for t in tags} & INFO_KEEP_TAGS)


def build_nuclei_cmd(targets_path: str, rate_limit: int, tags=None, severity: str = None):
    cmd = [
        "nuclei", "-nc",              # NOT -silent: warnings (e.g. host skipped) must reach stderr
        "-l", targets_path,
        "-rate-limit", str(rate_limit),
        "-c", NUCLEI_NETWORK_CONCURRENCY if tags else NUCLEI_CONCURRENCY,
        "-mhe", NUCLEI_MAX_HOST_ERROR,
        "-retries", "2" if tags else "1",
        "-ni",                        # no interactsh/OAST
        "-duc",                       # no update check at scan time
        "-timeout", "10",
        "-severity", severity or NUCLEI_SEVERITY,
    ]
    if tags:                      # explicit service tags (network-service pass)
        # -v: per-template "Could not execute request" warnings are what tell us a service was not
        # really tested (see collect_transient_errors); they are not guaranteed without it.
        cmd += ["-tags", ",".join(tags), "-v"]
    else:
        cmd += ["-as"] if NUCLEI_AUTOSCAN else ["-tags", ",".join(DEFAULT_SCAN_PROFILE)]
    # Stream one JSON result per line to STDOUT (the caller redirects it to a file). The old
    # -jsonl-export wrote its file only when nuclei exited cleanly, so a timeout lost every
    # finding found so far; streamed lines survive a kill.
    cmd += ["-jsonl"]
    return cmd




def _run_streaming(cmd: List[str], out_path: str, err_path: str, timeout: int):
    """Run cmd in its own process group with stdout/stderr going straight to files.
    Returns (returncode, timed_out). On timeout the whole group is terminated (SIGTERM, then
    SIGKILL) but everything already written stays on disk for salvage."""
    import signal
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, preexec_fn=os.setsid)
        try:
            return proc.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            pgid = os.getpgid(proc.pid)
            logger.warning(f"[nuclei] time budget of {timeout}s reached -- terminating process group {pgid}")
            for sig, grace in ((signal.SIGTERM, 8), (signal.SIGKILL, 5)):
                try:
                    os.killpg(pgid, sig)
                except ProcessLookupError:
                    break
                try:
                    proc.wait(timeout=grace)
                    break
                except subprocess.TimeoutExpired:
                    continue
            return proc.returncode, True


# ---------------------------------------------------------------- coverage of a nuclei run
# nuclei prints "[WRN] [template-id] Could not execute request for host:port: <reason>" per failed
# template. A few failures are normal (an HTTP template aimed at an SSH port never works), but
# several TRANSIENT ones (timeouts, resets) on one host:port mean the checks for that service did
# not really run, and their absence must not be read as "the finding is gone".
_RUN_ERR_RE = re.compile(r"\[WRN\] \[([^\]]+)\] Could not execute request for (\S+?): (.*)")
_TRANSIENT_RE = re.compile(
    r"i/o timeout|timed out|timeout|deadline exceeded|connection reset|connection refused|broken pipe|"
    r"unreachable|\beof\b", re.I)


def _norm_target(t: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", t.strip()).split("/")[0]


_DEST_RE = re.compile(r"->([\w.\-]+):(\d+)\b")


def _error_key(target: str, msg: str) -> str:
    """nuclei names the INPUT target (often a bare host, since network templates carry their own port).
    The socket error text usually names the real destination ('...->10.0.0.5:22: i/o timeout'): use that
    so the degraded unit is host:port; otherwise fall back to the target as given."""
    m = _DEST_RE.search(msg)
    if m and m.group(1) == target.rsplit(":", 1)[0].strip("[]"):
        return f"{m.group(1)}:{m.group(2)}"
    return target


def collect_transient_errors(stderr: str) -> Dict[str, Dict[str, str]]:
    """{host:port (or bare host): {template_id: first transient error message}} from nuclei's stderr."""
    out: Dict[str, Dict[str, str]] = {}
    for m in _RUN_ERR_RE.finditer(stderr or ""):
        tid, target, msg = m.group(1), _norm_target(m.group(2)), m.group(3)
        if _TRANSIENT_RE.search(msg):
            out.setdefault(_error_key(target, msg), {}).setdefault(tid, msg.strip()[:200])
    return out


def degraded_targets(errors: Dict[str, Dict[str, str]], min_templates: int = None) -> Dict[str, Dict[str, str]]:
    n = DEGRADED_MIN_TEMPLATES if min_templates is None else min_templates
    return {t: e for t, e in errors.items() if len(e) >= n}


def build_retry_cmd(target: str, template_ids: List[str], rate_limit: int, severity: str = None):
    return [
        "nuclei", "-nc", "-u", target, "-id", ",".join(template_ids),
        "-c", "1", "-retries", "1", "-timeout", "15",
        "-rate-limit", NUCLEI_RETRY_RATE,           # spaced out: one request per second by default
        "-ni", "-duc", "-v", "-severity", severity or NUCLEI_SEVERITY, "-jsonl",
    ]


def retry_degraded(result: Dict, degraded: Dict[str, Dict[str, str]], rate_limit: int, severity: str = None):
    """Re-run ONLY the templates that errored, one at a time, against ONLY the affected host:port, after a
    pause (a service that was overwhelmed by the parallel pass usually answers a calm retry).
    Merges recovered findings into `result`; returns the targets that are still degraded."""
    known = {(f.get("template_id"), f.get("host")) for f in result["findings"]}
    still: Dict[str, Dict[str, str]] = {}
    result["retried"] = {}
    for target in sorted(degraded)[:NUCLEI_RETRY_MAX_TARGETS]:
        ids = sorted(degraded[target])
        result["retried"][target] = len(ids)
        logger.warning(f"[nuclei] {target}: {len(ids)} templates hit transient errors; retrying them "
                       f"serially after {NUCLEI_RETRY_PAUSE:.0f}s")
        time.sleep(NUCLEI_RETRY_PAUSE)
        out_path = err_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as t1:
                out_path = t1.name
            with tempfile.NamedTemporaryFile(suffix=".err", delete=False) as t2:
                err_path = t2.name
            _run_streaming(build_retry_cmd(target, ids, rate_limit, severity), out_path, err_path,
                           NUCLEI_RETRY_TIMEOUT)
            for f in _read_findings(out_path):
                if keep_finding(f) and (f.get("template_id"), f.get("host")) not in known:
                    result["findings"].append(f)
                    known.add((f.get("template_id"), f.get("host")))
            left = collect_transient_errors(_read_text(err_path)).get(target, {})
            if len(left) >= DEGRADED_MIN_TEMPLATES:
                still[target] = left
            logger.info(f"[nuclei] {target}: retry recovered {len(ids) - len(left)} of {len(ids)} templates")
        except Exception as e:  # noqa: BLE001  a failed retry must never fail the scan
            logger.warning(f"[nuclei] {target}: retry failed ({e})")
            still[target] = degraded[target]
        finally:
            for pth in (out_path, err_path):
                if pth and os.path.exists(pth):
                    os.unlink(pth)
    for target in sorted(degraded)[NUCLEI_RETRY_MAX_TARGETS:]:
        still[target] = degraded[target]            # not retried: stays degraded
    _summarize(result)
    return still


def _read_text(path: str, limit: int = 200_000) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


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
            if not line.startswith("{"):
                continue                      # banner/log noise or a line cut off by a kill
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
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


def run_nuclei(hosts: List[str], rate_limit: int = 50, tags=None,
               severity: str = None, timeout: int = None) -> Dict:
    """
    Run Nuclei against a list of confirmed HTTP endpoints.
    Returns structured vulnerability data.
    """

    timeout = timeout or NUCLEI_TIMEOUT
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

    tmp_path = err_path = targets_path = None
    start = time.time()

    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name
        with tempfile.NamedTemporaryFile(suffix=".err", delete=False) as tmp:
            err_path = tmp.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            targets_path = tmp.name
            tmp.write("\n".join(hosts))

        logger.info(f"[nuclei] scanning {len(hosts)} hosts, severity={severity or NUCLEI_SEVERITY}, "
                    f"budget={timeout}s")
        returncode, timed_out = _run_streaming(
            build_nuclei_cmd(targets_path, rate_limit, tags, severity), tmp_path, err_path, timeout)
        stderr_txt = _read_text(err_path)

        # Findings are streamed to disk, so they are available even after a timeout/kill
        result["findings"] = [f for f in _read_findings(tmp_path) if keep_finding(f)]
        _summarize(result)
        duration = time.time() - start

        if timed_out:
            logger.error(f"[nuclei] hosts_in={len(hosts)} status=timeout after {timeout}s "
                         f"(kept {result['total']} findings) duration={duration:.2f}s")
            result["module_status"] = (
                f"partial (timeout, {result['total']} findings kept)" if result["total"] else "timeout")
            return result

        if returncode != 0:
            logger.error(f"[nuclei] returncode={returncode} duration={duration:.2f}s; "
                         f"stderr tail: {stderr_txt.strip()[-600:]!r}")
            result["module_status"] = "failed"
            return result

        skipped_hosts = "unresponsive" in stderr_txt
        if skipped_hosts:
            logger.warning("[nuclei] host(s) skipped as unresponsive -- results are INCOMPLETE")
            result["module_status"] = "partial (host skipped as unresponsive; lower the scan rate)"

        if tags:        # network-service pass: see which host:ports did not really get tested
            degraded = degraded_targets(collect_transient_errors(stderr_txt))
            if degraded:
                still = retry_degraded(result, degraded, rate_limit, severity)
                result["degraded"] = [{"target": t, "templates": sorted(e), "sample": next(iter(e.values()))}
                                      for t, e in sorted(still.items())]
                if still:
                    logger.warning(f"[nuclei] LOW COVERAGE on {', '.join(sorted(still))}: removals there will "
                                   f"be held, not confirmed")
                    if result["module_status"] == "ok":
                        result["module_status"] = f"ok (low coverage: {', '.join(sorted(still))})"

        if result["total"] == 0 and not skipped_hosts and not result.get("degraded"):
            executed = templates_executed(stderr_txt)
            if executed > 0:
                # Templates really ran and matched nothing: a clean result, not a suspicious one
                logger.info(f"[nuclei] clean: {executed} template executions, no findings at "
                            f"severity {severity or NUCLEI_SEVERITY}")
            else:
                result["module_status"] = "empty"
                logger.warning(f"[nuclei] 0 findings and no templates executed ({n_templates} installed); "
                               f"stderr tail: {stderr_txt.strip()[-600:]!r}")

        logger.info(f"[nuclei] hosts_in={len(hosts)} status={result['module_status']} "
                    f"findings={result['total']} duration={duration:.2f}s")

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

        for leftover in (err_path, targets_path):
            if leftover and os.path.exists(leftover):
                os.unlink(leftover)

    return result