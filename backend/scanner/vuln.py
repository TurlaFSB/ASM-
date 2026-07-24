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



def check_template_freshness(max_age_days: int = 7) -> str:
    """
    Check whether local Nuclei templates are reasonably fresh.
    Templates should be updated outside the scan pipeline.
    """
    template_dir = os.path.expanduser("~/.local/nuclei-templates")

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


def run_nuclei(hosts: List[str], rate_limit: int = 50) -> Dict:
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
            [
                "nuclei",
                "-silent",

                "-l",
                targets_path,
                "-rate-limit",
                str(rate_limit),

                "-retries",
                "2",

                "-timeout",
                "10",
                "-severity",
                "critical,high,medium",

                "-tags",
                ",".join(DEFAULT_SCAN_PROFILE),

                "-jsonl-export",
                tmp_path,
            ],
            timeout=600,
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

        with open(tmp_path, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(line)
                    if not isinstance(data, dict):
                        continue

                    info = data.get("info", {})
                    classification = info.get("classification", {}) or {}
                    cve_ids = classification.get("cve-id") or []

                    result["findings"].append(
                        {
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
                        }
                    )

                except json.JSONDecodeError:
                    logger.warning(
                        "[nuclei] Skipping malformed JSON line."
                    )
                    continue

        result["total"] = len(result["findings"])

        severity_counts = {}

        for f in result["findings"]:
            s = f.get("severity","unknown")
            severity_counts[s] = severity_counts.get(s,0)+1

        result["severity_counts"] = severity_counts

        if result["total"] == 0:
            result["module_status"] = "empty"

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

        logger.error(
            f"[nuclei] "
            f"hosts_in={len(hosts)} "
            f"status=timeout "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = "timeout"

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