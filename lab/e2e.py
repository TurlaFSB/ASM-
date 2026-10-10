#!/usr/bin/env python3
"""End-to-end check: start the lab stack, then run this to scan the lab host through the real API and assert the result.

    docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml up -d --build
    python3 lab/e2e.py                       # reads SECRET_KEY from the environment or .env.docker

Standard library only. Exit code 0 = the platform found what it must; 1 = it did not (problems are printed).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from expected import LAB_IP, evaluate, setup_code  # noqa: E402

API = os.environ.get("ASM_API", "http://127.0.0.1:8000")
PROFILE = os.environ.get("ASM_E2E_PROFILE", "standard")
SCAN_TIMEOUT = int(os.environ.get("ASM_E2E_TIMEOUT", "1500"))


def secret_key() -> str:
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    env = Path(__file__).resolve().parents[1] / ".env.docker"
    for line in env.read_text().splitlines():
        if line.startswith("SECRET_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("SECRET_KEY not found in the environment or .env.docker")


def call(method, path, body=None, form=None, token=None, ok=(200, 201)):
    data, headers = None, {}
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data, headers["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = r.read()
            return r.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as e:
        payload = e.read().decode("utf-8", "replace")
        if e.code in ok:
            return e.code, None
        sys.exit(f"{method} {path} -> HTTP {e.code}: {payload[:400]}")


def wait_for_api(seconds=240):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if call("GET", "/health")[0] == 200:
                return
        except (SystemExit, urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(3)
    sys.exit("the API did not become healthy in time")


def main() -> int:
    wait_for_api()
    password = "e2e-" + os.urandom(9).hex()
    _, status = call("GET", "/auth/setup-status")
    if status["needs_setup"]:
        call("POST", "/auth/setup", {"setup_code": setup_code(secret_key()), "username": "e2e_admin", "password": password})
    else:
        sys.exit("this stack already has an account; run against a fresh one (docker compose down -v)")
    _, tok = call("POST", "/auth/token", form={"username": "e2e_admin", "password": password})
    token = tok["access_token"]

    _, target = call("POST", "/targets/", {"domain": LAB_IP, "authorized": True, "authorized_by": "e2e", "rate_limit": 20}, token=token)
    _, scan = call("POST", "/scans/", {"target_id": target["id"], "profile": PROFILE}, token=token)
    sid = scan["scan_id"]
    print(f"scan {sid} started on {LAB_IP} (profile {PROFILE})", flush=True)

    end, last = time.time() + SCAN_TIMEOUT, None
    while True:
        _, s = call("GET", f"/scans/{sid}", token=token)
        stage = s.get("current_stage")
        if stage != last:
            print(f"  {s['status']}: {stage}", flush=True)
            last = stage
        if s["status"] in ("completed", "failed", "cancelled"):
            break
        if time.time() > end:
            sys.exit(f"scan did not finish within {SCAN_TIMEOUT}s")
        time.sleep(10)

    _, vulns = call("GET", f"/vulnerabilities/scan/{sid}", token=token)
    _, assets = call("GET", f"/scans/{sid}/assets", token=token)
    problems = evaluate(s, vulns, assets)
    print(json.dumps({"status": s["status"], "modules": s.get("module_results"),
                      "findings": sorted({v["template_id"] for v in vulns}), "assets": len(assets)}, indent=2, default=str))
    if problems:
        print("\nFAILED:\n  - " + "\n  - ".join(problems))
        return 1
    print("\nOK: the lab scan produced everything it must.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
