"""The end-to-end lab: its expectations are sound, and the lab's files really trip the platform's own checks."""
import functools
import http.server
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab"))
import expected  # noqa: E402

from backend.scanner.sensitive_files import run_sensitive_file_check  # noqa: E402
from backend.tests.test_compose_beat import _load  # noqa: E402


def good():
    scan = {"status": "completed", "module_results": {"portscan": "ok", "httpprobe": "ok", "sslyze": "skipped (no TLS)",
                                                      "sensitive_files": "ok", "amass": "skipped (off)"}}
    vulns = [{"template_id": "exposed-git", "severity": "high", "host": "http://172.28.0.80", "matched_at": "http://172.28.0.80/.git/HEAD"},
             {"template_id": "exposed-env", "severity": "critical", "host": "http://172.28.0.80", "matched_at": "http://172.28.0.80/.env"}]
    assets = [{"subdomain": "172.28.0.80", "ip": "172.28.0.80", "open_ports": [{"port": 80, "service": "http"}]}]
    return scan, vulns, assets


def test_setup_code_derivation_matches_the_platform():
    from backend import sessions
    from backend.config import settings
    assert expected.setup_code(settings.secret_key) == sessions.setup_code()


def test_a_correct_result_has_no_problems():
    assert expected.evaluate(*good()) == []


@pytest.mark.parametrize("mutate,needle", [
    (lambda s, v, a: s.update(status="failed"), "scan status"),
    (lambda s, v, a: s["module_results"].update(portscan="failed: timeout"), "stage portscan"),
    (lambda s, v, a: s["module_results"].update(vuln="timeout"), "stage vuln"),
    (lambda s, v, a: v.pop(0), "missing finding exposed-git"),
    (lambda s, v, a: v[0].update(severity="low"), "exposed-git has severity"),
    (lambda s, v, a: a.clear(), "no asset recorded"),
    (lambda s, v, a: a[0].update(open_ports=[{"port": 22}]), "port 80 not seen"),
])
def test_each_regression_is_reported(mutate, needle):
    scan, vulns, assets = good()
    mutate(scan, vulns, assets)
    assert any(needle in p for p in expected.evaluate(scan, vulns, assets))


def test_lab_files_produce_the_required_findings_with_the_real_check(tmp_path):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "lab" / "site"))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = run_sensitive_file_check([f"http://127.0.0.1:{srv.server_port}/"], rate_limit=1000)
    finally:
        srv.shutdown()
    got = {f["template_id"]: f for f in out["findings"]}
    assert set(expected.REQUIRED_FINDINGS) <= set(got), got.keys()
    assert out["module_status"] == "ok"


def test_the_lab_overlay_is_wired_for_a_fixed_address_and_private_targets():
    lab = _load("lab/docker-compose.lab.yml")
    assert lab["services"]["lab"]["networks"]["default"]["ipv4_address"] == expected.LAB_IP
    subnet = lab["networks"]["default"]["ipam"]["config"][0]["subnet"]
    assert subnet == "172.28.0.0/24"
    for svc in ("backend", "celery_worker"):
        assert lab["services"][svc]["environment"]["ASM_ALLOW_PRIVATE_TARGETS"] == "true"
    assert lab["services"]["lab"]["image"].startswith("nginx:")
