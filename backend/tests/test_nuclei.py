import json
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
    cmd = v.build_nuclei_cmd("t.txt", "o.jsonl", 50)
    assert "-silent" not in cmd and "-as" in cmd and "-tags" not in cmd
    assert cmd[cmd.index("-mhe") + 1] == "100" and cmd[cmd.index("-rate-limit") + 1] == "50"
    monkeypatch.setattr(v, "NUCLEI_AUTOSCAN", False)
    cmd = v.build_nuclei_cmd("t.txt", "o.jsonl", 50)
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
    cmd = v.build_nuclei_cmd("t", "o", 5, tags=["ftp", "irc"])
    assert cmd[cmd.index("-tags") + 1] == "ftp,irc" and "-as" not in cmd
