import subprocess
import logging
import os
import tempfile
import time
from typing import Dict, List

from backend.scanner.subdomain import _run_with_process_group_cleanup

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = "/home/worm/projects/asm-platform/screenshots"


def run_eyewitness(hosts: List[str]) -> Dict:
    """
    Run EyeWitness against a list of hosts.
    Returns screenshot paths per host.
    """

    result = {
        "screenshots": [],
        "module_status": "ok",
        "output_dir": SCREENSHOT_DIR,
    }

    # Remove duplicate hosts
    hosts = sorted(set(hosts))

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    tmp_path = None
    start = time.time()

    try:
        # EyeWitness requires targets from a file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            delete=False,
        ) as tmp:
            tmp.write("\n".join(hosts))
            tmp_path = tmp.name

        eyewitness_result = _run_with_process_group_cleanup(
            [
                "/opt/EyeWitness/eyewitness-venv/bin/python3", "/opt/EyeWitness/Python/EyeWitness.py",
                "--web",
                "-f",
                tmp_path,
                "--no-prompt",
                "-d",
                SCREENSHOT_DIR,
                "--timeout",
                "15",
            ],
            timeout=300,
        )

        if eyewitness_result.returncode != 0:
            duration = time.time() - start

            logger.error(
                f"[eyewitness] "
                f"status=failed "
                f"returncode={eyewitness_result.returncode} "
                f"duration={duration:.2f}s"
            )

            if eyewitness_result.stderr:
                logger.error(eyewitness_result.stderr.strip())

            result["module_status"] = "failed"
            return result

        # Collect screenshots
        for root, _, files in os.walk(SCREENSHOT_DIR):
            for file in files:
                if file.endswith(".png"):
                    result["screenshots"].append(
                        {
                            "file": os.path.join(root, file),
                            "name": file,
                        }
                    )

        if not result["screenshots"]:
            result["module_status"] = "empty"

        duration = time.time() - start

        logger.info(
            f"[eyewitness] "
            f"hosts_in={len(hosts)} "
            f"status={result['module_status']} "
            f"screenshots={len(result['screenshots'])} "
            f"duration={duration:.2f}s"
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start

        logger.error(
            f"[eyewitness] "
            f"status=timeout "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = "timeout"

    except FileNotFoundError:
        logger.error("[eyewitness] tool_not_found")
        result["module_status"] = "tool_not_found"

    except Exception as e:
        duration = time.time() - start

        logger.error(
            f"[eyewitness] "
            f"status=failed "
            f"error={e} "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = f"failed: {e}"

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return result