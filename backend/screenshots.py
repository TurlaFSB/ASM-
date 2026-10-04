"""Read access to the pictures EyeWitness took for a scan.

Layout on disk:  SCREENSHOT_DIR/run-<12 hex>/index.json  and the PNG files beneath it.
A scan only stores the run folder's name (scan.module_results["screenshot_run"]); everything else is read
from index.json. Clients refer to a picture by its position in that index, never by a path, and every
resolved path is checked to stay inside its run folder, so a tampered index cannot read other files.
"""
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

_RUN_RE = re.compile(r"^run-[0-9a-f]{12}$")


def _root() -> Path:
    return Path(os.getenv("SCREENSHOT_DIR", "/app/screenshots"))


def _run_dir(scan) -> Optional[Path]:
    name = (scan.module_results or {}).get("screenshot_run")
    if not isinstance(name, str) or not _RUN_RE.match(name):
        return None
    d = _root() / name
    return d if d.is_dir() else None


def list_screenshots(scan) -> List[Dict]:
    """[{id, host, url}] for the scan. Empty when it took none, or the pictures were cleaned up."""
    d = _run_dir(scan)
    if d is None:
        return []
    try:
        raw = json.loads((d / "index.json").read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [{"id": i, "host": str(e.get("host", ""))[:255], "url": e.get("url")}
            for i, e in enumerate(raw) if isinstance(e, dict)]


def screenshot_path(scan, shot_id: int) -> Optional[Path]:
    """Absolute path of picture `shot_id`, or None if it is unknown, missing or outside the run folder."""
    d = _run_dir(scan)
    if d is None or shot_id < 0:
        return None
    try:
        raw = json.loads((d / "index.json").read_text())
        rel = raw[shot_id]["file"]
    except (OSError, ValueError, IndexError, KeyError, TypeError):
        return None
    if not isinstance(rel, str):
        return None
    p = (d / rel).resolve()
    base = d.resolve()
    if base not in p.parents or p.suffix.lower() != ".png" or not p.is_file():
        return None
    return p
