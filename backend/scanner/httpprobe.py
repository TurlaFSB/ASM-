import subprocess
import json
import logging
import time
from typing import List, Dict
from backend.scanner.subdomain import _run_with_process_group_cleanup

logger = logging.getLogger(__name__)

def run_httpx(hosts: List[str], rate_limit: int = 10) -> Dict:
    result = {
        "hosts": [],
        "module_status": "ok"
    }

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    start = time.time()
    try:
        httpx_result = _run_with_process_group_cleanup(
            [
                "httpx-toolkit",
                "-silent",
                "-json",
                "-title",
                "-status-code",
                "-tech-detect",
                "-follow-redirects",
                "-rate-limit", str(rate_limit),
                "-timeout", "10",
            ],
            timeout=120,
            input_text="\n".join(hosts),
        )

        for line in httpx_result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                result["hosts"].append({
                    "url": data.get("url", ""),
                    "host": data.get("host", ""),
                    "status_code": data.get("status_code", None),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                    "content_length": data.get("content-length", 0),
                    "webserver": data.get("webserver", "")
                })
            except json.JSONDecodeError:
                continue

        duration = time.time() - start
        logger.info(f"[httpx] hosts_in={len(hosts)} status=ok results={len(result['hosts'])} duration={duration:.2f}s")

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        logger.error(f"[httpx] hosts_in={len(hosts)} status=timeout duration={duration:.2f}s")
        result["module_status"] = "timeout"
    except FileNotFoundError:
        logger.error("[httpx] tool_not_found")
        result["module_status"] = "tool_not_found"
    except Exception as e:
        duration = time.time() - start
        logger.error(f"[httpx] hosts_in={len(hosts)} status=failed error={e} duration={duration:.2f}s")
        result["module_status"] = f"failed: {e}"

    return result
