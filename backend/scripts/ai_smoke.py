"""Check the configured LLM provider end to end with one sample event.

    docker compose exec backend python -m backend.scripts.ai_smoke
"""
import json
import sys
import time

from backend.ai.classifier import classify_event
from backend.ai.providers import provider_from_env

SAMPLE = {"category": "port", "change_type": "added", "asset": "192.168.16.128", "subject": "8000/tcp",
          "severity": "medium", "confidence": "confirmed", "fingerprint": "smoke",
          "summary": "Port 8000/tcp opened on 192.168.16.128 (SimpleHTTPServer 0.6)",
          "after": {"service": "http", "product": "SimpleHTTPServer", "version": "0.6"}}


def main() -> int:
    provider = provider_from_env()
    if provider is None:
        print("ASM_LLM_PROVIDER is none/unset: set it to ollama (or mock) in .env.docker and recreate the containers.")
        return 2
    print(f"provider={provider.name} model={provider.model}")
    t0 = time.time()
    out = classify_event(provider, SAMPLE)
    print(json.dumps(out, indent=2))
    print(f"latency={time.time() - t0:.1f}s")
    return 0 if out.get("ai_status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
