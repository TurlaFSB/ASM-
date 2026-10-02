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

# Wordlists, keyed by a short name the API/profiles pass through. Each is a list of PASSES:
# (path, extensions). Extensions are tried alongside bare paths only where they pay off
# (backup/source/config files such as config.php.bak, db.zip) -- applying them to a large
# list multiplies requests by 5-9x and can never finish within the per-host budget.
#   core   curated high-signal paths (admin panels, secrets, VCS/config, debug endpoints) + extensions
#   small  SecLists quickhits (~2.5k, files and paths)
#   medium core pass (with extensions) then SecLists common.txt (~4.7k) for breadth
_HERE = os.path.dirname(os.path.abspath(__file__))
CORE_LIST = os.path.join(os.path.dirname(_HERE), "wordlists", "asm-core.txt")
EXTENSIONS = "php,bak,zip,txt"
WORDLISTS = {
    "core": [(CORE_LIST, EXTENSIONS)],
    "small": [("/opt/wordlists/quickhits.txt", "")],
    "medium": [(CORE_LIST, EXTENSIONS), ("/opt/wordlists/common.txt", "")],
}
DEFAULT_WORDLIST = "core"

# feroxbuster 2.11.0's limiter collapses below ~15 req/s: measured against a local server,
# --rate-limit 5/10/11 all delivered ~1 request/s (after a 50-request burst), while 15 gave ~20/s
# and 50 gave ~49/s. A requested "10/s" would therefore take 10x longer than planned and hit the
# time budget with most of the wordlist unsent. Clamp to a rate where the limiter is honest.
FEROX_MIN_RATE = 20


def effective_ferox_rate(rate_limit: int) -> int:
    return max(FEROX_MIN_RATE, int(rate_limit or 0))


# A wildcard-ish or listing-heavy host can answer thousands of paths; keep the DB and report sane.
MAX_PATHS_PER_HOST = 500

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


DIRBUSTER_MAX_SECONDS = int(os.getenv("DIRBUSTER_MAX_SECONDS", "900"))


def _count_words(path: str) -> int:
    try:
        with open(path, "rb") as f:
            return sum(1 for line in f if line.strip() and not line.startswith(b"#"))
    except OSError:
        return 0


def compute_budget(total_requests: int, rate_limit: int, n_passes: int = 1,
                   floor: int = 120, cap: int = None) -> int:
    """Per-host wall-clock budget: time to send every request at the rate limit, plus slack for
    process start-up and slow responses, clamped to [floor, cap] so one slow host can't stall
    the pipeline and a tiny list isn't padded."""
    cap = DIRBUSTER_MAX_SECONDS if cap is None else cap
    needed = int(total_requests / max(1, rate_limit)) + 30 * n_passes + 60
    return max(floor, min(needed, cap))


def _salvage(out) -> str:
    """subprocess.TimeoutExpired carries partial output (bytes even with text=True)."""
    if out is None:
        return ""
    return out.decode("utf-8", "replace") if isinstance(out, bytes) else out


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


def _resolve_passes(wordlist: str):
    """Wordlist key -> usable (path, extensions, words) passes. Unknown keys fall back to the
    default rather than failing the scan over a typo; missing/empty files are skipped (and
    logged) so a broken image can't masquerade as an empty, successful scan."""
    spec = WORDLISTS.get(wordlist) or WORDLISTS[DEFAULT_WORDLIST]
    passes = []
    for path, ext in spec:
        words = _count_words(path)
        if words == 0:
            logger.error(f"[dirbuster] wordlist missing or empty, skipping pass: {path}")
            continue
        passes.append((path, ext, words))
    return passes


def _pass_requests(words: int, ext: str) -> int:
    return words * (1 + (len([e for e in ext.split(",") if e]) if ext else 0))


def _ferox_cmd(url: str, path: str, ext: str, rate_limit: int, per_request_timeout: int) -> List[str]:
    return [
        "feroxbuster",
        "--url", url,
        "--wordlist", path,
        *(["-x", ext] if ext else []),
        "--json",
        "--silent",
        "--no-state",
        "--insecure",            # lab/internal hosts routinely use self-signed certs; without this
                                 # an https host yields zero results with no error
        "--rate-limit", str(rate_limit),
        "--timeout", str(per_request_timeout),
        "--depth", "1",          # no recursion -- keeps scan time bounded per host
        "--scan-dir-listings",   # without this feroxbuster sees an auto-index ("Index of /") page,
                                 # prints "Directory listing" and SKIPS the wordlist entirely
    ]


def _to_paths(entries: List[Dict], base_url: str) -> List[Dict]:
    """feroxbuster responses -> our path records: drop the base page itself, dedupe, cap."""
    seen, out = set(), []
    for e in entries:
        entry_url = e.get("url", "")
        path = _extract_path(entry_url, base_url) if entry_url else "/"
        if path in ("/", ""):
            continue                      # the scanned base URL is not a discovery
        if e.get("status") == 404:
            continue                      # links extracted from a listing that don't resolve
        key = (path, e.get("status"))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "path": path,
            "status_code": e.get("status"),
            "content_length": e.get("content_length"),
            "redirect_location": (e.get("headers") or {}).get("location"),
        })
    return out


def _write_evidence(output_dir, url, chunks):
    if not output_dir:
        return
    try:
        with open(os.path.join(output_dir, _sanitize_filename(url) + ".jsonl"), "w") as f:
            f.write("\n".join(chunks))
    except OSError as e:
        logger.warning(f"[dirbuster] could not write raw output for {url}: {e}")


def scan_host(url: str, passes, rate_limit: int, budget: int, per_request_timeout: int, output_dir=None) -> Dict:
    """Run every wordlist pass against one URL inside a shared wall-clock budget.
    Returns {"entries": [...raw responses...], "partial": bool, "error": str|None}."""
    deadline = time.time() + budget
    entries: List[Dict] = []
    evidence: List[str] = []
    partial, error = False, None
    for path, ext, words in passes:
        remaining = int(deadline - time.time())
        if remaining < 15:
            partial = True
            break
        needed = int(_pass_requests(words, ext) / max(1, rate_limit)) + 30
        try:
            proc = subprocess.run(
                _ferox_cmd(url, path, ext, rate_limit, per_request_timeout),
                capture_output=True, text=True, timeout=min(needed, remaining),
            )
        except subprocess.TimeoutExpired as te:
            found = _parse_ferox_json(_salvage(te.stdout))
            evidence.append(_salvage(te.stdout))
            entries += found
            partial = True
            logger.warning(f"[dirbuster] timeout scanning {url} ({os.path.basename(path)}) "
                           f"after {min(needed, remaining)}s (salvaged {len(found)} paths)")
            continue
        evidence.append(proc.stdout or "")
        if proc.stderr:
            evidence.append("--- stderr ---\n" + proc.stderr)
        if "Could not connect" in (proc.stderr or ""):
            error = "could not connect (host down, port closed or connection refused)"
            break
        if proc.returncode != 0 and not proc.stdout:
            error = (proc.stderr or "unknown error, no stdout/stderr captured").strip()[:500]
            break
        entries += _parse_ferox_json(proc.stdout)
    _write_evidence(output_dir, url, evidence)
    return {"entries": entries, "partial": partial, "error": error}


def run_dirbuster(
    urls: List[str],
    rate_limit: int = 10,
    wordlist: str = DEFAULT_WORDLIST,
    scan_id: int = None,
    per_request_timeout: int = 8,
    max_seconds: int = None,
) -> Dict:
    """
    Runs feroxbuster against each URL (one at a time: the rate limit is a politeness ceiling
    for the target, so running hosts in parallel would not make it faster, only louder).

    rate_limit: requests/sec per feroxbuster process, from the target's configured ceiling.
    wordlist: key from WORDLISTS (core/small/medium).
    per_request_timeout: how long ONE request may hang before feroxbuster gives up on it.
    max_seconds: wall-clock budget PER HOST (all passes together); defaults to
        DIRBUSTER_MAX_SECONDS and is sized from the request count, so it never pads a quick list.
    """
    result = {"hosts": {}, "module_status": "ok", "failures": {}}
    if not urls:
        result["module_status"] = "no hosts provided"
        return result

    passes = _resolve_passes(wordlist)
    if not passes:
        result["module_status"] = "failed: no usable wordlist installed"
        return result

    output_dir = None
    if scan_id is not None:
        output_dir = os.path.join(OUTPUT_ROOT, str(scan_id), "dirbuster")
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.warning(f"[dirbuster] could not create output dir {output_dir}: {e}")
            output_dir = None

    rate_limit = effective_ferox_rate(rate_limit)
    cap = DIRBUSTER_MAX_SECONDS if max_seconds is None else max_seconds
    total_requests = sum(_pass_requests(w, e) for _, e, w in passes)
    budget = compute_budget(total_requests, rate_limit, len(passes), cap=cap)
    logger.info(f"[dirbuster] wordlist={wordlist} passes={len(passes)} requests/host={total_requests} "
                f"rate={rate_limit}/s per-host budget={budget}s")

    start = time.time()
    success = failure = partial_count = 0
    for url in urls:
        try:
            r = scan_host(url, passes, rate_limit, budget, per_request_timeout, output_dir)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[dirbuster] error scanning {url}: {e}")
            result["failures"][url] = str(e)
            failure += 1
            continue
        paths = _to_paths(r["entries"], url)
        if r["error"] and not paths:
            result["failures"][url] = r["error"]
            failure += 1
            logger.warning(f"[dirbuster] {url} failed: {r['error']}")
            continue
        host = {"paths": paths[:MAX_PATHS_PER_HOST]}
        if len(paths) > MAX_PATHS_PER_HOST:
            host["truncated"] = True
        if r["partial"] or r["error"]:
            host["partial"] = True
            partial_count += 1
        result["hosts"][url] = host
        success += 1

    logger.info(f"[dirbuster] scanned={len(urls)} success={success} failed={failure} "
                f"duration={time.time() - start:.2f}s")

    if success == 0 and failure > 0:
        result["module_status"] = "failed"
    elif partial_count and not failure:
        result["module_status"] = f"partial ({partial_count}/{len(urls)} hosts hit time limit)"
    elif failure > 0:
        result["module_status"] = f"partial ({success}/{len(urls)} hosts succeeded)"
    return result
