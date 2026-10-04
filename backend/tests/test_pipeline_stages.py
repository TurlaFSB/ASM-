from types import SimpleNamespace

from backend import pipeline_stages as ps


def test_internal_target_detection():
    assert ps.is_internal_target("10.0.0.5") and ps.is_internal_target("router.local")
    assert not ps.is_internal_target("example.com")


def test_internal_live_hosts_ip_and_unresolvable(monkeypatch):
    assert ps.internal_live_hosts("10.1.2.3") == ([{"subdomain": "10.1.2.3", "ip": "10.1.2.3"}],
                                                  "resolved directly (internal target)")
    import socket
    def nope(_): raise socket.gaierror("no")
    monkeypatch.setattr(ps.socket, "gethostbyname", nope)
    assert ps.internal_live_hosts("ghost.lan") == ([], "resolution failed")
    monkeypatch.setattr(ps.socket, "gethostbyname", lambda _: "10.9.9.9")
    assert ps.internal_live_hosts("nas.lan")[0][0]["ip"] == "10.9.9.9"


def test_extract_cve_id_precedence():
    assert ps.extract_cve_id({"cve_id": "CVE-2020-1111", "tags": ["cve-2019-2222"]}) == "CVE-2020-1111"
    assert ps.extract_cve_id({"tags": ["http", "cve-2019-2222"]}) == "CVE-2019-2222"
    assert ps.extract_cve_id({"template_id": "cve-2018-3333", "tags": "notalist"}) == "CVE-2018-3333"
    assert ps.extract_cve_id({"template_id": "tech-detect"}) is None


def test_build_vulnerabilities_maps_fields():
    rows = ps.build_vulnerabilities([{"template_id": "t", "name": "n", "type": "http", "host": "h"}], 1, 2)
    v = rows[0]
    assert (v.target_id, v.scan_id, v.severity, v.vuln_type, v.host) == (1, 2, "info", "http", "h")
    s = ps.build_vulnerabilities([{"vuln_type": "tls", "tags": ["cve-2014-0160"]}], 1, 2,
                                 type_key="vuln_type", derive_cve=False)[0]
    assert s.vuln_type == "tls" and s.cve_id is None


def prof(**kw):
    base = dict(name="quick", run_dirbuster=False, run_nuclei_network=False, run_takeover=True,
                run_email_security=True, run_cloud_buckets=False, run_sensitive_files=True)
    base.update(kw)
    return SimpleNamespace(**base)


def test_collect_marks_skipped_modules_and_merges():
    mr = {}
    http = {"hosts": [{"url": "https://a", "technologies": ["x"]}]}
    out = ps.collect_web_results({}, prof(), False, http, mr)
    assert mr["whatweb"] == "skipped (profile: quick)" and mr["dirbuster"] == "skipped (profile: quick)"
    assert mr["nuclei_network"] == "skipped (profile: quick)"
    assert out["vuln"]["findings"] == []

    mr = {}
    res = {"whatweb": {"hosts": {"https://a": {"technologies": ["y"]}}, "module_status": "ok"},
           "nuclei": {"findings": [{"n": 1}], "module_status": "ok", "template_count": 5},
           "nuclei_network": {"findings": [{"n": 2}], "module_status": "ok", "degraded": ["h:21"]},
           "cve_match": {"findings": [{"n": 3}], "module_status": "ok", "truncated": "3 of 9"}}
    out = ps.collect_web_results(res, prof(run_nuclei_network=True), False, http, mr)
    assert http["hosts"][0]["technologies"] == ["x", "y"]
    assert [f["n"] for f in out["vuln"]["findings"]] == [1, 2, 3]
    assert mr["nuclei_network_degraded"] == ["h:21"] and mr["cve_truncated"] == "3 of 9"
    assert mr["nuclei_templates"] == 5


def test_collect_network_skipped_reasons():
    mr = {}
    ps.collect_web_results({}, prof(run_nuclei_network=True), False, {"hosts": []}, mr)
    assert mr["nuclei_network"] == "skipped (no recognised network services)"


def test_record_changes_failure_is_contained(monkeypatch):
    class DB:
        rolled = False
        def rollback(self): self.rolled = True
    import backend.diffing.service as svc
    monkeypatch.setattr(svc, "record_scan_changes", lambda *a: (_ for _ in ()).throw(ValueError("x")))
    db, mr = DB(), {}
    ps.record_changes_and_alerts(db, object(), mr)
    assert db.rolled and mr["diff"].startswith("failed")


def test_seal_failure_is_contained(monkeypatch):
    class DB:
        def rollback(self): pass
    import backend.integrity as integ
    monkeypatch.setattr(integ, "seal_scan", lambda *a: (_ for _ in ()).throw(ValueError("y")))
    mr = {}
    ps.seal_record(DB(), object(), mr)
    assert mr["integrity"].startswith("failed")


def test_posture_findings_merge_into_vulnerabilities_and_status_is_recorded():
    mr = {}
    http = {"hosts": []}
    f = {"template_id": "email-spf-missing", "name": "No SPF record", "severity": "medium", "host": "a.com"}
    out = ps.collect_web_results({"email_security": {"findings": [f], "module_status": "ok"},
                                  "takeover": {"findings": [], "module_status": "partial: 1 of 3 names"}},
                                 prof(), False, http, mr)
    assert [x["template_id"] for x in out["vuln"]["findings"]] == ["email-spf-missing"]
    assert mr["email_security"] == "ok" and mr["takeover"].startswith("partial")
    assert mr["cloud_buckets"].startswith("skipped (profile")             # disabled in this profile
    assert mr["sensitive_files"] == "skipped (not applicable to this target)"   # enabled, but did not run
