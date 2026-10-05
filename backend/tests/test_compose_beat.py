"""Celery beat must never write its schedule file into the (read-only for non-root) application directory."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class _Loader(yaml.SafeLoader):
    """Compose-only tags (!override, !reset) carry no meaning for these checks."""


for _tag in ("!override", "!reset"):
    _Loader.add_constructor(_tag, lambda loader, node: loader.construct_sequence(node)
                            if isinstance(node, yaml.SequenceNode) else loader.construct_scalar(node))


def _load(name):
    return yaml.load((ROOT / name).read_text(), Loader=_Loader)


def _beat_command(name):
    cmd = _load(name)["services"]["celery_beat"]["command"]
    return cmd if isinstance(cmd, str) else " ".join(cmd)


def test_beat_schedule_file_is_in_tmp_in_every_compose_file():
    for name in ("docker-compose.yml", "docker-compose.prod.yml"):
        cmd = _beat_command(name)
        assert "beat" in cmd and "-s /tmp/celerybeat-schedule" in cmd, f"{name}: {cmd}"


def test_beat_has_a_writable_tmp_in_production():
    prod = _load("docker-compose.prod.yml")
    anchor = prod["x-app-prod"]
    assert anchor["read_only"] is True
    assert any(str(t).startswith("/tmp") for t in anchor["tmpfs"])
