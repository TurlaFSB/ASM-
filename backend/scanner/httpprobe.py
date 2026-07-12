import subprocess
import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def run_httpx(hosts: List[str], rate_limit: int = 10) -> Dict:
    """
    Run httpx against a list of hosts.
    Returns structured HTTP data per host.
    """
    result = {
        "hosts": [],
        "module_status": "ok"
    }

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    try:
        httpx_result = subprocess.run(
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
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=120
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

    except subprocess.TimeoutExpired:
        logger.error("HTTPX timed out")
        result["module_status"] = "timeout"
    except FileNotFoundError:
        logger.error("HTTPX not found")
        result["module_status"] = "tool_not_found"
    except Exception as e:
        logger.error(f"HTTPX failed: {e}")
        result["module_status"] = f"failed: {e}"

    logger.info(f"HTTPX probed {len(result['hosts'])} live web hosts")
    return result