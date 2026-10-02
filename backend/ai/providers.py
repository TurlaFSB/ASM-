"""LLM providers behind one tiny interface. A provider returns the model's raw text; validation,
guardrails and fallback live in the classifier, so no provider is trusted more than another."""
import json
import os
from typing import Dict, List, Optional, Protocol

import requests

from backend.ai.schema import json_schema


class LLMError(Exception):
    pass


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, messages: List[Dict], schema: Optional[dict] = None) -> str: ...


class OllamaProvider:
    """Local Ollama (e.g. qwen2.5:7b / :14b). No data leaves the machine."""
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: int = 120, session=None, num_ctx: int = 4096):
        self.base_url = base_url.rstrip("/")
        self.model, self.timeout, self.num_ctx = model, timeout, num_ctx
        self.session = session or requests.Session()

    def complete(self, messages, schema=None) -> str:
        body = {
            "model": self.model, "messages": messages, "stream": False,
            "format": schema or json_schema(),          # constrained decoding to the schema
            "options": {"temperature": 0, "num_ctx": self.num_ctx, "num_predict": 400},
        }
        try:
            r = self.session.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except (requests.RequestException, KeyError, ValueError) as e:
            raise LLMError(f"ollama request failed: {e}") from e


class MockProvider:
    """Deterministic offline provider for tests and demos. `script` maps a substring of the user
    message to the raw reply; otherwise it echoes a reasonable triage built from the rule severity."""
    name = "mock"
    model = "mock-1"

    def __init__(self, script: Optional[Dict[str, str]] = None):
        self.script = script or {}
        self.calls: List[List[Dict]] = []

    def complete(self, messages, schema=None) -> str:
        self.calls.append(messages)
        user = messages[-1]["content"]
        for needle, reply in self.script.items():
            if needle in user:
                return reply
        try:
            ev = json.loads(user.split("<event>", 1)[1].split("</event>", 1)[0])
        except (IndexError, ValueError):
            raise LLMError("mock: unparseable event")
        return json.dumps({"severity": ev.get("rule_severity", "info"),
                           "summary": ev.get("summary", "Change detected.")[:280],
                           "recommended_action": "Review this change with the asset owner."})


def provider_from_env() -> Optional[LLMProvider]:
    kind = os.getenv("ASM_LLM_PROVIDER", "none").strip().lower()
    if kind in ("", "none", "off"):
        return None
    if kind == "mock":
        return MockProvider()
    if kind == "ollama":
        return OllamaProvider(
            os.getenv("ASM_LLM_BASE_URL", "http://host.docker.internal:11434"),
            os.getenv("ASM_LLM_MODEL", "qwen2.5:7b"),
            timeout=int(os.getenv("ASM_LLM_TIMEOUT", "120")))
    raise ValueError(f"unknown ASM_LLM_PROVIDER '{kind}' (use none, ollama or mock)")
