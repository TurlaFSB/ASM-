import subprocess
import os
import tempfile
import logging
from typing import List, Dict

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
        "output_dir": SCREENSHOT_DIR
    }

    if not hosts:
        result["module_status"] = "no hosts provided"
        return result

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    try:
        # Write hosts to temp file — EyeWitness requires file input
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(hosts))
            tmp_path = tmp.name

        eyewitness_result = subprocess.run(
            [
                "eyewitness",
                "--web",
                "-f", tmp_path,
                "--no-prompt",
                "-d", SCREENSHOT_DIR,
                "--timeout", "15",
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        os.unlink(tmp_path)

        # Collect all screenshots produced
        for root, dirs, files in os.walk(SCREENSHOT_DIR):
            for file in files:
                if file.endswith(".png"):
                    result["screenshots"].append({
                        "file": os.path.join(root, file),
                        "name": file
                    })

        logger.info(f"EyeWitness captured {len(result['screenshots'])} screenshots")

    except subprocess.TimeoutExpired:
        logger.error("EyeWitness timed out")
        result["module_status"] = "timeout"
    except FileNotFoundError:
        logger.error("EyeWitness not found")
        result["module_status"] = "tool_not_found"
    except Exception as e:
        logger.error(f"EyeWitness failed: {e}")
        result["module_status"] = f"failed: {e}"

    return result