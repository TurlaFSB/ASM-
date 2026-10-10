"""Guards for the repository itself: nothing invisible in source, nothing secret-shaped tracked, CI pinned."""
import re
import subprocess
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKIP_SUFFIX = (".png", ".jpg", ".ico", ".svg", ".gif", ".webp", ".woff", ".woff2", ".lock")


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [p for p in out.split("\n") if p]


def test_no_invisible_or_bidirectional_characters_in_tracked_text():
    """Invisible characters hide code from reviewers (the 'Trojan Source' attack). Write them as \\u escapes."""
    bad = []
    for rel in tracked():
        if rel.endswith(SKIP_SUFFIX) or rel.endswith("package-lock.json"):
            continue
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.split("\n"), 1):
            if any(unicodedata.category(c) == "Cf" for c in line):
                bad.append(f"{rel}:{n}")
    assert not bad, f"invisible characters in: {bad[:10]}"


@pytest.mark.parametrize("pattern", [r"(^|/)\.env($|\.docker$)", r"\.bak$", r"\.pem$", r"\.key$", r"\.p12$", r"id_rsa", r"\.sqlite3?$"])
def test_no_secret_shaped_files_are_tracked(pattern):
    hits = [p for p in tracked() if re.search(pattern, p)]
    assert not hits, hits


def test_every_workflow_action_is_pinned_to_a_commit():
    """A tag can be moved to different code; a commit hash cannot. Dependabot proposes the bumps."""
    bad = []
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for n, line in enumerate(wf.read_text(encoding="utf-8").split("\n"), 1):
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./") and not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                bad.append(f"{wf.name}:{n} {m.group(1)}")
    assert not bad, bad


def test_workflows_default_to_read_only_tokens():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = wf.read_text(encoding="utf-8")
        assert re.search(r"^permissions:", text, re.M), f"{wf.name} has no top-level permissions block"
        assert "pull_request_target" not in text, f"{wf.name} uses pull_request_target"
