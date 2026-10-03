"""Score the configured LLM on the labelled triage cases and write a JSON report.

    docker compose exec backend python -m backend.scripts.ai_eval
    docker compose exec backend python -m backend.scripts.ai_eval --out /app/scan_output/ai_eval --tag qwen2.5-7b

Exit code 0 only if every quality gate passes.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.ai.evaluate import run_eval
from backend.ai.providers import provider_from_env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/app/scan_output/ai_eval", help="directory for the JSON report")
    ap.add_argument("--tag", default=None, help="label for the report file (default: provider and model)")
    args = ap.parse_args()
    provider = provider_from_env()
    if provider is None:
        print("ASM_LLM_PROVIDER is none/unset: set it to ollama in .env.docker and recreate the containers.")
        return 2
    print(f"provider={provider.name} model={provider.model}", flush=True)

    def progress(i, n, r):
        flag = "" if r["status"] == "ok" else f"  [{r['status']}: {r['error']}]"
        print(f"[{i:02d}/{n}] {r['id']:<28} expected={r['expected']:<8} rule={r['rule']:<8} ai={str(r['ai']):<8} "
              f"final={str(r['final']):<8} {r['seconds']:>5.1f}s{flag}", flush=True)

    t0 = time.time()
    report = run_eval(provider, progress=progress)
    report["total_seconds"] = round(time.time() - t0, 1)
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    tag = (args.tag or f"{provider.name}-{provider.model}").replace(":", "-").replace("/", "-")
    path = out / f"{tag}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2))
    print("\nMETRICS " + json.dumps(report["metrics"]))
    for k, g in report["gates"].items():
        print(f"GATE {'PASS' if g['pass'] else 'FAIL'} {k}: {g['value']} (need {g['need']})")
    print(f"WORST {report['worst']}")
    print(f"report written to {path}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
