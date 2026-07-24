"""
Directory/content discovery via feroxbuster -- brute-forces hidden paths and
endpoints per host using a wordlist, surfacing admin panels, backups, and
config files that recon (subdomain enum, port scan, HTTP probe) alone won't
find. Runs one process per host, same per-host-reliability pattern as
whatweb.py: one bad host times out on its own without killing the batch.

Rate limiting is fed straight from the target's own Target.rate_limit
(requests/sec), same value every other stage in this pipeline already
respects, so a target's configured ceiling can't be silently bypassed by
this stage alone.

Raw feroxbuster JSON output is retained on disk per scan/host (not in the
DB -- keeps Postgres rows small and backups fast) so a finding can be traced
back to the exact raw tool output for evidence/chain-of-custody purposes,
same standard a real VAPT report needs to meet.
"""
import subprocess
import json
import logging
import os
import re
import time
from urllib.parse import urlparse
from typing import List, Dict

logger = logging.getLogger(__name__)

# Available wordlists, keyed by a short name the API/UI can pass through.
# "small" is the default -- fast enough to actually finish within the
# per-host timeout at typical rate limits (raft-medium at 30k words needs
# ~50min/host at 10 req/s, well past any reasonable scan budget).
WORDLISTS = {
    "small": "/opt/wordlists/quickhits.txt",
    "medium": "/opt/wordlists/common.txt",
}
DEFAULT_WORDLIST = WORDLISTS["small"]

# Extensions worth brute-forcing alongside bare paths -- backup/source/config
# files are a real attacker-relevant finding class that a bare wordlist pass
# misses entirely (e.g. config.php.bak, db.zip).
EXTENSIONS = "php,bak,zip,config,old,txt,sql,log"

# Base output dir for raw per-host feroxbuster JSON. Mounted inside the
# backend container; caller can rsync/serve this out for report evidence.
OUTPUT_ROOT = "/app/scan_output"

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_filename(url: str) -> str:
    """
    Turns a URL into a filesystem-safe filename. Strips scheme, replaces
    anything that isn't alnum/dot/dash/underscore (colons from ports,
    slashes from paths, etc.) with underscores -- avoids path traversal or
    invalid-path errors from something like 'http://host:8080/sub/path'.
    """
    parsed = urlparse(url)
    raw = f"{parsed.hostname or 'unknown'}_{parsed.port or ''}"
    return _SAFE_NAME_RE.sub("_", raw).strip("_") or "unknown_host"


def _parse_ferox_json(raw_stdout: str) -> List[Dict]:
    """
    feroxbuster --json emits one JSON object per line (true JSON-lines,
    unlike whatweb's log-json quirk) -- but mixes in non-result message types
    (state changes, statistics) on their own lines. Keep only type=="response".
    Verified against feroxbuster 2.11.0's actual --json schema.
    """
    results = []
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "response":
            results.append(obj)
    return results


def _extract_path(entry_url: str, base_url: str) -> str:
    """
    Derive just the path/query portion of a discovered URL relative to the
    scanned base, using urllib instead of naive string replace -- naive
    replace breaks if the base URL string happens to recur inside the path
    (e.g. a redirect back to the same host).
    """
    parsed = urlparse(entry_url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return path


def run_dirbuster(
    urls: List[str],
    rate_limit: int = 10,
    wordlist: str = "small",
    scan_id: int = None,
    per_request_timeout: int = 8,
    process_timeout: int = 300,
) -> Dict:
    """
    Runs feroxbuster against each URL individually.

    rate_limit: requests/sec, pulled from the target's own Target.rate_limit --
        same throttle every other stage in this pipeline respects.
    wordlist: key from WORDLISTS ("small"/"medium"), resolved to a real path
        here so callers never need to know the container's filesystem layout.
        Falls back to the default on an unrecognized key rather than failing
        the whole scan over a typo.
    per_request_timeout: feroxbuster's own --timeout, i.e. how long a single
        HTTP request is allowed to hang before feroxbuster gives up on it.
    process_timeout: the subprocess.run() wall-clock budget for the ENTIRE
        per-host scan (all requests combined). Distinct from
        per_request_timeout -- kept as separate named args so the two never
        get confused again.
    """
    wordlist_path = WORDLISTS.get(wordlist, DEFAULT_WORDLIST)
    result = {"hosts": {}, "module_status": "ok", "failures": {}}
    if not urls:
        result["module_status"] = "no hosts provided"
        return result

    output_dir = None
    if scan_id is not None:
        output_dir = os.path.join(OUTPUT_ROOT, str(scan_id), "dirbuster")
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.warning(f"[dirbuster] could not create output dir {output_dir}: {e}")
            output_dir = None

    start = time.time()
    success_count = 0
    failure_count = 0

    for url in urls:
        try:
            proc = subprocess.run(
                [
                    "feroxbuster",
                    "--url", url,
                    "--wordlist", wordlist_path,
                    *(["-x", EXTENSIONS] if wordlist == "medium" else []),
                    "--json",
                    "--silent",
                    "--no-state",
                    "--rate-limit", str(rate_limit),
                    "--timeout", str(per_request_timeout),
                    "--depth", "1",          # no recursion -- keep scan time bounded per host
                ],
                capture_output=True,
                text=True,
                timeout=process_timeout,
            )

            # Retain raw output on disk regardless of parse outcome -- this is
            # the evidence artifact a real report/audit trail needs.
            if output_dir:
                fname = _sanitize_filename(url) + ".jsonl"
                fpath = os.path.join(output_dir, fname)
                try:
                    with open(fpath, "w") as f:
                        f.write(proc.stdout)
                        if proc.stderr:
                            f.write("\n--- stderr ---\n")
                            f.write(proc.stderr)
                except OSError as e:
                    logger.warning(f"[dirbuster] could not write raw output for {url}: {e}")

            if proc.returncode != 0 and not proc.stdout:
                # Ran but produced nothing usable -- record as a real failure,
                # not a silent empty success.
                reason = (proc.stderr or "unknown error, no stdout/stderr captured").strip()[:500]
                result["failures"][url] = reason
                failure_count += 1
                logger.warning(f"[dirbuster] {url} failed: {reason}")
                continue

            parsed = _parse_ferox_json(proc.stdout)
            paths = []
            for entry in parsed:
                entry_url = entry.get("url", "")
                paths.append({
                    "path": _extract_path(entry_url, url) if entry_url else "/",
                    "status_code": entry.get("status"),
                    "content_length": entry.get("content_length"),
                    "redirect_location": (entry.get("headers") or {}).get("location"),
                })
            result["hosts"][url] = {"paths": paths}
            success_count += 1
        except subprocess.TimeoutExpired:
            logger.warning(f"[dirbuster] timeout scanning {url}")
            result["failures"][url] = f"process timeout after {process_timeout}s"
            failure_count += 1
            continue
        except Exception as e:
            logger.warning(f"[dirbuster] error scanning {url}: {e}")
            result["failures"][url] = str(e)
            failure_count += 1
            continue

    duration = time.time() - start
    logger.info(
        f"[dirbuster] scanned={len(urls)} success={success_count} "
        f"failed={failure_count} duration={duration:.2f}s"
    )

    if success_count == 0 and failure_count > 0:
        result["module_status"] = "failed"
    elif failure_count > 0:
        result["module_status"] = f"partial ({success_count}/{len(urls)} hosts succeeded)"
    else:
        result["module_status"] = "ok"

    return result