import json
import subprocess

import pytest

from backend.scanner import subdomain as sd


def completed(stdout, code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


def fake_runner(by_tool, seen=None):
    def run(cmd, timeout, input_text=None):
        if seen is not None:
            seen[cmd[0]] = timeout
        r = by_tool[cmd[0]]
        if isinstance(r, Exception):
            raise r
        return r
    return run


SF = "\n".join(json.dumps({"host": h}) for h in ["a.acme.com", "evil.com", "A.acme.com.", "b.acme.com"])


def test_subfinder_statuses(monkeypatch):
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({"subfinder": completed(SF)}))
    assert sd._subfinder("acme.com") == (["a.acme.com", "b.acme.com"], "ok")           # off-scope names dropped
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({"subfinder": completed("")}))
    assert sd._subfinder("acme.com") == ([], "empty")
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup",
                        fake_runner({"subfinder": subprocess.TimeoutExpired("subfinder", 1)}))
    assert sd._subfinder("acme.com") == ([], "timeout")
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({"subfinder": FileNotFoundError()}))
    assert sd._subfinder("acme.com") == ([], "not installed")
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({"subfinder": RuntimeError("x")}))
    assert sd._subfinder("acme.com") == ([], "failed: RuntimeError")


def test_amass_hang_is_reported_as_timeout_and_uses_the_configured_bound(monkeypatch):
    seen = {}
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup",
                        fake_runner({"amass": subprocess.TimeoutExpired("amass", 150)}, seen))
    monkeypatch.delenv("ASM_AMASS_TIMEOUT", raising=False)
    assert sd._amass("acme.com") == ([], "timeout") and seen["amass"] == 150
    monkeypatch.setenv("ASM_AMASS_TIMEOUT", "45")
    sd._amass("acme.com")
    assert seen["amass"] == 45
    monkeypatch.setenv("ASM_AMASS_TIMEOUT", "99999")          # clamped, never unbounded
    sd._amass("acme.com")
    assert seen["amass"] == 900
    monkeypatch.setenv("ASM_AMASS_TIMEOUT", "nonsense")
    sd._amass("acme.com")
    assert seen["amass"] == 150


@pytest.fixture(autouse=True)
def _amass_on_unless_a_test_says_otherwise(monkeypatch):
    monkeypatch.setenv("ASM_AMASS_ENABLED", "true")


@pytest.mark.parametrize("value", ["false", "0", "no", "OFF", ""])
def test_amass_is_off_unless_enabled_and_is_never_started(monkeypatch, value):
    monkeypatch.setenv("ASM_AMASS_ENABLED", value)
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", lambda *a, **k: pytest.fail("amass must not run"))
    out, status = sd._amass("acme.com")
    assert out == [] and status.startswith("skipped")


def test_amass_is_off_by_default(monkeypatch):
    monkeypatch.delenv("ASM_AMASS_ENABLED", raising=False)
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", lambda *a, **k: pytest.fail("amass must not run"))
    out, status = sd._amass("acme.com")
    assert out == [] and status.startswith("skipped") and "ASM_AMASS_ENABLED=true" in status


def test_enumerate_merges_sources_keeps_apex_and_reports_each_tool(monkeypatch):
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({
        "subfinder": completed(SF), "amass": completed("c.acme.com\nacme.com\nhttp://junk")}))
    out = sd.enumerate_subdomains("acme.com")
    assert out["subdomains"] == ["a.acme.com", "acme.com", "b.acme.com", "c.acme.com"]
    assert out["module_status"] == {"subfinder": "ok", "amass": "ok"}


def test_scan_still_proceeds_when_amass_hangs(monkeypatch):
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup", fake_runner({
        "subfinder": completed(SF), "amass": subprocess.TimeoutExpired("amass", 150)}))
    out = sd.enumerate_subdomains("acme.com")
    assert out["module_status"] == {"subfinder": "ok", "amass": "timeout"}
    assert "a.acme.com" in out["subdomains"]


def test_timeout_status_reads_as_a_warning_in_reports_and_ui_logic():
    from backend.reports import _module_state
    assert _module_state("timeout") == "warn" and _module_state("ok") == "ok"
    assert _module_state("skipped (off; set ASM_AMASS_ENABLED=true to use it)") == "skip"
    assert _module_state("not installed") == "fail"


# Shape of amass 4.x output (written from its documented format, not a live capture): a relationship graph, not a list of names.
AMASS_4_GRAPH = """example.com (FQDN) --> ns_record --> a.iana-servers.net (FQDN)
example.com (FQDN) --> ns_record --> b.iana-servers.net (FQDN)
www.example.com (FQDN) --> a_record --> 104.20.23.154 (IPAddress)
mail.example.com (FQDN) --> cname_record --> mx.example.com (FQDN)
104.20.0.0/16 (Netblock) --> contains --> 104.20.23.154 (IPAddress)
13335 (ASN) --> managed_by --> CLOUDFLARENET - Cloudflare, Inc. (RIROrganization)
evil.example.com.attacker.net (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
-oops.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)
"""


def test_amass_4_graph_output_is_parsed_and_scoped():
    assert sd.parse_amass_output(AMASS_4_GRAPH, "example.com") == [
        "example.com", "mail.example.com", "mx.example.com", "www.example.com"]


def test_amass_old_plain_output_still_parses():
    assert sd.parse_amass_output("a.acme.com\nb.acme.com\nother.net\n\n", "acme.com") == ["a.acme.com", "b.acme.com"]
    assert sd.parse_amass_output("", "acme.com") == [] and sd.parse_amass_output(None, "acme.com") == []


def test_amass_status_ok_when_graph_output_has_names(monkeypatch):
    monkeypatch.setattr(sd, "_run_with_process_group_cleanup",
                        lambda cmd, timeout, input_text=None: subprocess.CompletedProcess(cmd, 0, AMASS_4_GRAPH, ""))
    found, status = sd._amass("example.com")
    assert status == "ok" and "www.example.com" in found
