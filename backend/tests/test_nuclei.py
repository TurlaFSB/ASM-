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
