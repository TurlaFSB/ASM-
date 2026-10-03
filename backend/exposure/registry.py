from typing import Dict, List

from backend.exposure.github_code import GitHubCodeCollector
from backend.exposure.hudsonrock import HudsonRockCollector
from backend.exposure.lookalikes import LookalikeCollector
from backend.exposure.ransomlook import RansomLookCollector
from backend.exposure.xposedornot import XposedOrNotCollector

_COLLECTORS = [GitHubCodeCollector(), XposedOrNotCollector(), LookalikeCollector(), RansomLookCollector(), HudsonRockCollector()]
REGISTRY: Dict[str, object] = {c.name: c for c in _COLLECTORS}


def all_sources() -> List[object]:
    return list(REGISTRY.values())


def get(name: str):
    return REGISTRY.get(name)
