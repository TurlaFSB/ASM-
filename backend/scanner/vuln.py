import subprocess
import json
import logging
import tempfile
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

def run_nuclei(hosts: List[str], rate_limit: int = 10) -> Dict:
    """
    Run nuclei against a list of hosts.
    Returns structured vulnerability data per host.
    """
    result = {
        "findings": [],
        "module_status": "ok",
        "total": 0
    }

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        nuclei_result = subprocess.run(
            [
                "nuclei",
                "-silent",
                "-rate-limit", str(rate_limit),
                "-timeout", "10",
                "-severity", "critical,high,medium",
                "-jsonl-export", tmp_path,
            ],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=600
        )

        with open(tmp_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    classification = info.get("classification", {}) or {}
                    cve_ids = classification.get("cve-id") or []
                    result["findings"].append({
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
                        "cve_id": cve_ids[0] if cve_ids else None
                    })
                except json.JSONDecodeError:
                    continue

        os.unlink(tmp_path)
        result["total"] = len(result["findings"])

    except subprocess.TimeoutExpired:
        logger.error("Nuclei timed out")
        result["module_status"] = "timeout"
    except FileNotFoundError:
        logger.error("Nuclei not found")
        result["module_status"] = "tool_not_found"
    except Exception as e:
        logger.error(f"Nuclei failed: {e}")
        result["module_status"] = f"failed: {e}"

    logger.info(f"Nuclei found {result['total']} findings")
    return result