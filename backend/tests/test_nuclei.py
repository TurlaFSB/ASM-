import json
from backend.scanner import vuln as vuln_mod
from backend.scanner.vuln import _read_findings, _summarize


def test_read_findings_and_summary(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text(
        json.dumps({"host": "h", "template-id": "CVE-2021-1", "matched-at": "http://h/x",
                    "info": {"name": "n", "severity": "high",
                             "classification": {"cve-id": ["CVE-2021-1"], "cvss-score": 8.1}}}) + "\n"
        + "not json\n"
        + json.dumps({"host": "h", "template-id": "t2", "info": {"name": "m", "severity": "medium"}}) + "\n"
        + '{"host": "truncated by timeo'   # partial last line after a kill
    )
    f = _read_findings(str(p))
    assert [x["template_id"] for x in f] == ["CVE-2021-1", "t2"]
    assert f[0]["cve_id"] == "CVE-2021-1"
    r = {"findings": f}
    _summarize(r)
    assert r["total"] == 2 and r["severity_counts"] == {"high": 1, "medium": 1}


def test_read_findings_missing_file():
    assert _read_findings("/nonexistent") == []


def test_template_count(tmp_path, monkeypatch):
    import backend.scanner.vuln as v
    d = tmp_path / "nt" / "http"
    d.mkdir(parents=True)
    (d / "a.yaml").write_text("id: a")
    (d / "b.yml").write_text("id: b")
    (d / "readme.md").write_text("x")
    monkeypatch.setattr(v, "TEMPLATE_DIRS", (str(tmp_path / "nt"),))
    assert v.template_count() == 2
    monkeypatch.setattr(v, "TEMPLATE_DIRS", (str(tmp_path / "missing"),))
    assert v.template_count() == 0


def test_run_nuclei_refuses_when_no_templates(monkeypatch):
    import backend.scanner.vuln as v
    monkeypatch.setattr(v, "template_count", lambda: 0)
    r = v.run_nuclei(["http://x"], 10)
    assert r["module_status"].startswith("failed: no nuclei templates")


def test_build_cmd_not_silent_and_autoscan(monkeypatch):
    import backend.scanner.vuln as v
    monkeypatch.setattr(v, "NUCLEI_AUTOSCAN", True)
    cmd = v.build_nuclei_cmd("t.txt", 50)
    assert "-silent" not in cmd and "-as" in cmd and "-tags" not in cmd
    assert cmd[cmd.index("-mhe") + 1] == "100" and cmd[cmd.index("-rate-limit") + 1] == "50"
    monkeypatch.setattr(v, "NUCLEI_AUTOSCAN", False)
    cmd = v.build_nuclei_cmd("t.txt", 50)
    assert "-as" not in cmd and "-tags" in cmd


def test_info_findings_filtered_by_tag():
    from backend.scanner.vuln import keep_finding
    assert keep_finding({"severity": "high", "tags": ["cve"]})
    assert keep_finding({"severity": "info", "tags": ["panel", "phpmyadmin"]})
    assert keep_finding({"severity": "info", "tags": "exposure,misc"})
    assert not keep_finding({"severity": "info", "tags": ["tech", "apache"]})
    assert not keep_finding({"severity": "info", "tags": []})


def test_network_tags_from_services_and_cmd():
    import backend.scanner.vuln as v
    hosts = [{"subdomain": "h", "ports": [
        {"port": 21, "service": "ftp"}, {"port": 6667, "service": "irc"},
        {"port": 445, "service": "netbios-ssn"}, {"port": 80, "service": "http"}]}]
    assert v.network_tags_from_services(hosts) == ["ftp", "irc", "samba", "smb", "unrealircd"]
    assert v.network_tags_from_services([{"subdomain": "h", "ports": [{"port": 80, "service": "http"}]}]) == []
    cmd = v.build_nuclei_cmd("t", 5, tags=["ftp", "irc"])
    assert cmd[cmd.index("-tags") + 1] == "ftp,irc" and "-as" not in cmd


def test_templates_executed_parses_nuclei_stderr():
    import backend.scanner.vuln as v
    err = ("[INF] Executing 148 templates on http://192.168.16.128:80\n"
           "[INF] Executing 13 templates on http://192.168.16.128:8080\n[INF] Targets loaded: 2")
    assert v.templates_executed(err) == 161
    assert v.templates_executed("[INF] Executing 1 template on http://h") == 1
    assert v.templates_executed("") == 0 and v.templates_executed(None) == 0
    assert v.templates_executed("[INF] Executing Automatic scan on 2 target[s]") == 0


# ---- streaming runner: findings must survive a timeout kill ----

def _py(code):
    import sys
    return [sys.executable, "-u", "-c", code]


def test_streaming_salvages_findings_on_timeout(tmp_path):
    import time
    import backend.scanner.vuln as v
    out, err = str(tmp_path / "o.jsonl"), str(tmp_path / "o.err")
    code = ("import time,json;"
            "print(json.dumps({'template-id':'t1','host':'h','info':{'name':'n','severity':'high'}}));"
            "print('{\"template-id\": \"cut-of');"        # truncated line, as a kill can leave behind
            "time.sleep(60)")
    t = time.time()
    rc, timed_out = v._run_streaming(_py(code), out, err, timeout=2)
    assert timed_out and time.time() - t < 12            # budget respected, kill is prompt
    found = v._read_findings(out)
    assert [f["template_id"] for f in found] == ["t1"]   # complete line kept, truncated one skipped


def test_streaming_clean_exit_and_failure(tmp_path):
    import backend.scanner.vuln as v
    out, err = str(tmp_path / "o"), str(tmp_path / "e")
    rc, timed_out = v._run_streaming(_py("print('{\"template-id\":\"a\",\"info\":{}}')"), out, err, 10)
    assert (rc, timed_out) == (0, False) and len(v._read_findings(out)) == 1
    rc, timed_out = v._run_streaming(_py("import sys;sys.stderr.write('boom');sys.exit(3)"), out, err, 10)
    assert (rc, timed_out) == (3, False) and "boom" in v._read_text(err)


def test_read_findings_ignores_noise_lines(tmp_path):
    import backend.scanner.vuln as v
    p = tmp_path / "o"
    p.write_text('[INF] banner\n\n{"template-id":"x","info":{"severity":"low"}}\nnot json\n')
    assert [f["template_id"] for f in v._read_findings(str(p))] == ["x"]


def test_network_pass_uses_gentler_concurrency_and_more_retries():
    net = vuln_mod.build_nuclei_cmd("t", 5, tags=["ssh"])
    web = vuln_mod.build_nuclei_cmd("t", 5)
    assert net[net.index("-c") + 1] == vuln_mod.NUCLEI_NETWORK_CONCURRENCY
    assert net[net.index("-retries") + 1] == "2" and web[web.index("-retries") + 1] == "1"
    assert web[web.index("-c") + 1] == vuln_mod.NUCLEI_CONCURRENCY


# ---- coverage of a network run ----

def test_transient_errors_are_collected_and_protocol_mismatches_ignored():
    from backend.scanner.vuln import collect_transient_errors, degraded_targets
    err = (
        "[WRN] [CVE-2026-45695] Could not execute request for 10.0.0.5:22: [:RUNTIME] tls: first record does not "
        "look like a TLS handshake; could not tls handshake\n"
        "[WRN] [ssh-a] Could not execute request for 10.0.0.5:22: ssh: handshake failed: read tcp 1->2: i/o timeout\n"
        "[WRN] [ssh-b] Could not execute request for 10.0.0.5:22: ssh: handshake failed: EOF\n"
        "[WRN] [ftp-a] Could not execute request for 10.0.0.5:21: connection reset by peer\n")
    errs = collect_transient_errors(err)
    assert set(errs["10.0.0.5:22"]) == {"ssh-a", "ssh-b"} and set(errs["10.0.0.5:21"]) == {"ftp-a"}
    assert set(degraded_targets(errs)) == {"10.0.0.5:22"}          # one error alone is not degradation


def test_network_pass_uses_verbose_so_warnings_are_always_present():
    from backend.scanner.vuln import build_nuclei_cmd, build_retry_cmd
    assert "-v" in build_nuclei_cmd("/t", 20, tags=["ssh"]) and "-v" not in build_nuclei_cmd("/t", 20)
    cmd = build_retry_cmd("10.0.0.5:22", ["b", "a"], 50)
    assert cmd[cmd.index("-id") + 1] == "b,a" and cmd[cmd.index("-c") + 1] == "1"
    assert cmd[cmd.index("-rate-limit") + 1] == "1"


def test_retry_recovers_findings_and_reports_what_is_still_degraded(monkeypatch):
    from backend.scanner import vuln
    monkeypatch.setattr(vuln, "NUCLEI_RETRY_PAUSE", 0)
    calls = []

    def fake_run(cmd, out_path, err_path, timeout):
        calls.append(cmd)
        target = cmd[cmd.index("-u") + 1]
        if target.endswith(":22"):                   # recovers
            open(out_path, "w").write('{"template-id":"ssh-a","host":"10.0.0.5:22","info":{"name":"A","severity":"medium"}}\n')
        else:                                        # still failing
            open(err_path, "w").write(
                "[WRN] [x1] Could not execute request for 10.0.0.5:21: i/o timeout\n"
                "[WRN] [x2] Could not execute request for 10.0.0.5:21: i/o timeout\n")
        return 0, False

    monkeypatch.setattr(vuln, "_run_streaming", fake_run)
    result = {"findings": [], "total": 0}
    degraded = {"10.0.0.5:22": {"ssh-a": "i/o timeout", "ssh-b": "i/o timeout"},
                "10.0.0.5:21": {"x1": "i/o timeout", "x2": "i/o timeout"}}
    still = vuln.retry_degraded(result, degraded, 50, "info,low,medium,high,critical")
    assert [f["template_id"] for f in result["findings"]] == ["ssh-a"] and result["total"] == 1
    assert set(still) == {"10.0.0.5:21"} and len(calls) == 2


def test_run_nuclei_marks_status_and_degraded_when_retry_does_not_help(monkeypatch):
    from backend.scanner import vuln
    monkeypatch.setattr(vuln, "NUCLEI_RETRY_PAUSE", 0)
    monkeypatch.setattr(vuln, "template_count", lambda: 100)
    monkeypatch.setattr(vuln, "check_template_freshness", lambda: "fresh")
    warn = ("[WRN] [ssh-a] Could not execute request for 10.0.0.5:22: ssh: handshake failed: i/o timeout\n"
            "[WRN] [ssh-b] Could not execute request for 10.0.0.5:22: ssh: handshake failed: i/o timeout\n"
            "[INF] Executing 30 signed templates from x\n")

    def fake_run(cmd, out_path, err_path, timeout):
        open(err_path, "w").write(warn)                  # first pass AND retry both fail
        return 0, False

    monkeypatch.setattr(vuln, "_run_streaming", fake_run)
    r = vuln.run_nuclei(["10.0.0.5"], 20, tags=["ssh"])
    assert r["module_status"] == "ok (low coverage: 10.0.0.5:22)"
    assert r["degraded"][0]["target"] == "10.0.0.5:22" and r["degraded"][0]["templates"] == ["ssh-a", "ssh-b"]
    # the web pass (no tags) never does this
    r2 = vuln.run_nuclei(["http://10.0.0.5"], 20)
    assert "degraded" not in r2


def test_real_destination_port_is_taken_from_the_socket_error():
    from backend.scanner.vuln import collect_transient_errors
    err = (
        "[WRN] [ssh-a] Could not execute request for 192.168.16.128: ssh: handshake failed: read tcp "
        "172.18.0.5:41158->192.168.16.128:22: i/o timeout\n"
        "[WRN] [ssh-b] Could not execute request for 192.168.16.128: ssh: handshake failed: read tcp "
        "172.18.0.5:41160->192.168.16.128:22: i/o timeout\n"
        "[WRN] [ftp-a] Could not execute request for 192.168.16.128: connection reset by peer\n")
    errs = collect_transient_errors(err)
    assert set(errs) == {"192.168.16.128:22", "192.168.16.128"}
    assert set(errs["192.168.16.128:22"]) == {"ssh-a", "ssh-b"}
