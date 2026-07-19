"""
WhatWeb integration -- technology fingerprinting via plugin-based signature matching.
Deeper than httpx's -tech-detect (which relies on Wappalyzer-style header/body regex);
WhatWeb runs 1800+ plugins covering CMS, frameworks, JS libs, server software, admin panels.
Output merged into the same `technologies` list httpx populates on Asset -- deduped, not overwritten.
"""
import subprocess
import json
import logging
import re
import time
from typing import List, Dict

logger = logging.getLogger(__name__)

# Plugins that represent noise/metadata rather than actual technology stack --
# excluded from the technologies list (still useful data, just not "tech").
_NOISE_PLUGINS = {"Country", "IP", "Allow", "UncommonHeaders", "Title", "RedirectLocation"}


def _parse_whatweb_json(raw_stdout: str) -> List[Dict]:
    """
    whatweb --log-json=- output is NOT clean JSON-lines -- it wraps a JSON array
    with a stray plain-text summary line before the closing bracket. Extract only
    lines that parse as valid JSON objects, ignore everything else.
    """
    results = []
    for line in raw_stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def run_whatweb(urls: List[str], aggression: int = 3, timeout: int = 20) -> Dict:
    """
    Runs whatweb against each URL individually (whatweb's multi-target mode
    doesn't cleanly separate per-host JSON in this version -- one process per
    URL keeps parsing unambiguous, matches the per-host reliability pattern
    used elsewhere in this pipeline over batch-and-hope).
    """
    result = {"hosts": {}, "module_status": "ok"}
    if not urls:
        result["module_status"] = "no hosts provided"
        return result

    start = time.time()
    success_count = 0

    for url in urls:
        try:
            proc = subprocess.run(
                ["whatweb", "--log-json=-", f"-a", str(aggression), url],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            parsed = _parse_whatweb_json(proc.stdout)
            if not parsed:
                continue
            entry = parsed[0]
            plugins = entry.get("plugins", {})
            tech_names = [name for name in plugins.keys() if name not in _NOISE_PLUGINS]
            result["hosts"][url] = {
                "technologies": tech_names,
                "http_status": entry.get("http_status"),
            }
            success_count += 1
        except subprocess.TimeoutExpired:
            logger.warning(f"[whatweb] timeout scanning {url}")
            continue
        except Exception as e:
            logger.warning(f"[whatweb] error scanning {url}: {e}")
            continue

    duration = time.time() - start
    logger.info(f"[whatweb] scanned={len(urls)} success={success_count} duration={duration:.2f}s")
    if success_count == 0:
        result["module_status"] = "empty"
    return result
