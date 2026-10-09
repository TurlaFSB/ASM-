"""Release plumbing: the images overlay must cover every service that builds from source, and the changelog must
contain the dated section the release workflow looks for."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class _Loader(yaml.SafeLoader):
    pass


for _tag in ("!override", "!reset"):
    _Loader.add_constructor(_tag, lambda loader, node: None)


def _compose(name):
    return yaml.load((ROOT / name).read_text(), Loader=_Loader)


def test_images_overlay_replaces_every_built_service():
    base = _compose("docker-compose.yml")["services"]
    overlay = _compose("docker-compose.images.yml")["services"]
    built = {n for n, svc in base.items() if "build" in svc and n != "tests"
             and "pytest" not in str(svc.get("command", ""))}
    assert built, "expected services that build from source"
    for name in built:
        assert name in overlay, f"{name} would still build from source when the images overlay is used"
        assert str(overlay[name]["image"]).startswith("${ASM_"), name
        assert "build" in overlay[name] and overlay[name]["build"] is None, f"{name}: build must be reset"


def test_every_overlay_service_uses_a_project_image():
    for name, svc in _compose("docker-compose.images.yml")["services"].items():
        assert "ghcr.io/turlafsb/asm-" in svc["image"], name


def test_current_release_has_a_dated_changelog_section():
    text = (ROOT / "CHANGELOG.md").read_text()
    versions = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", text, re.M)
    assert versions, "no dated release section found"
    assert versions == sorted(versions, key=lambda v: tuple(map(int, v.split("."))), reverse=True), "newest first"


def test_release_workflow_triggers_only_on_version_tags():
    wf = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    on = wf.get("on") or wf.get(True)
    assert on["push"]["tags"] == ["v[0-9]+.[0-9]+.[0-9]+"]
    perms = wf["jobs"]["images"]["permissions"]
    assert perms["packages"] == "write" and perms["id-token"] == "write"
