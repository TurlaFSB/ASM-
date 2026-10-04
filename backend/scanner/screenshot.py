import json
import re
import subprocess
import logging
import os
import tempfile
import time
import uuid
from typing import Dict, List

from backend.scanner.subdomain import _run_with_process_group_cleanup

logger = logging.getLogger(__name__)

# Mounted as the screenshots_data volume in docker-compose
SCREENSHOT_DIR = os.getenv("SCREENSHOT_DIR", "/app/screenshots")


MAX_INDEXED = 200
_SCHEME_RE = re.compile(r"^(https?)\.")


def _norm(text: str) -> str:
    """EyeWitness names a picture after the URL with punctuation replaced; compare on letters and digits only."""
    return re.sub(r"[^a-z0-9]+", ".", (text or "").lower()).strip(".")


def build_index(screenshots: List[Dict], urls: List[str], run_dir: str) -> List[Dict]:
    """One entry per picture: which host or URL it shows and where the file is (relative to run_dir).
    Matching is by normalised name; a picture that matches no scanned URL is still listed, labelled by its file name."""
    by_name = {_norm(u): u for u in urls}
    out = []
    for shot in sorted(screenshots, key=lambda s: s["file"])[:MAX_INDEXED]:
        stem = _norm(os.path.splitext(shot["name"])[0])
        url = by_name.get(stem)
        host = url.split("://", 1)[-1].rstrip("/") if url else _SCHEME_RE.sub("", stem)
        out.append({"host": host, "url": url, "file": os.path.relpath(shot["file"], run_dir)})
    return out


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

    # EyeWitness deletes and recreates its output directory, which a mounted volume root does not allow
    # ("Device or resource busy"). Give every run its own new sub-directory instead. It also keeps this
    # run's screenshots apart from earlier runs, so only the pictures taken now are attributed to this scan.
    run_dir = os.path.join(SCREENSHOT_DIR, f"run-{uuid.uuid4().hex[:12]}")
    result["output_dir"] = run_dir

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
                run_dir,
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
        for root, _, files in os.walk(run_dir):
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
        else:
            result["run"] = os.path.basename(run_dir)
            result["index"] = build_index(result["screenshots"], hosts, run_dir)
            try:
                with open(os.path.join(run_dir, "index.json"), "w") as fh:
                    json.dump(result["index"], fh)
            except OSError:
                logger.warning("[eyewitness] could not write the screenshot index")

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