import copy

from backend.diffing.engine import diff_snapshots
from backend.diffing.snapshot import build_snapshot, compute_coverage, snapshot_hash

OK_MR = {"dns": "resolved directly (internal target)", "subfinder": "skipped (internal/IP target)",
         "portscan": "ok", "httpprobe": "ok", "whatweb": "ok", "dirbuster": "ok", "vuln": "ok",
         "nuclei_network": "ok", "cve_match": "ok"}


def _asset(ports=(80, 8181), techs=("Apache:2.4.7",), status=200, title="Index of /", sub="10.0.0.5"):
    return {"subdomain": sub, "ip": sub, "http_status": status, "http_title": title, "technologies": list(techs),
            "open_ports": [{"port": p, "protocol": "tcp", "service": "http", "product": "Apache httpd" if p == 80 else "",
                            "version": "2.4.7" if p == 80 else ""} for p in ports]}


def _snap(assets=None, paths=(), findings=(), mr=None, profile="standard"):
    return build_snapshot(profile, mr or OK_MR, assets if assets is not None else [_asset()],
                          [{"subdomain": "10.0.0.5", "path": p, "status_code": s} for p, s in paths],
                          list(findings))


def _find(tid="t1", host="10.0.0.5:445", sev="high", tags=("network",), name="SMB thing", cve=None):
    return {"template_id": tid, "host": host, "severity": sev, "tags": list(tags), "name": name, "cve_id": cve}


def _kinds(res):
    return sorted((e["category"], e["change_type"], e["subject"]) for e in res["events"])


# ---- baseline / identical ----

def test_no_baseline_means_no_events():
    r = diff_snapshots(None, _snap())
    assert r["baseline"] and r["events"] == [] and r["pending"] == []


def test_identical_snapshots_produce_nothing_and_equal_hash():
    a, b = _snap(), _snap()
    assert snapshot_hash(a) == snapshot_hash(b)
    r = diff_snapshots(a, b)
    assert not r["baseline"] and r["events"] == [] and r["pending"] == []


# ---- additions are immediate ----

def test_new_port_is_reported_immediately_with_risk_severity():
    old = _snap([_asset(ports=(80,))])
    new = _snap([_asset(ports=(80, 3306))])
    r = diff_snapshots(old, new)
    assert _kinds(r) == [("port", "added", "3306/tcp")]
    assert r["events"][0]["severity"] == "high"          # database port


def test_new_asset_does_not_spam_child_events():
    old = _snap([_asset()])
    new = _snap([_asset(), _asset(sub="10.0.0.9", ports=(22, 80), techs=("nginx:1.2",))])
    r = diff_snapshots(old, new)
    assert _kinds(r) == [("asset", "added", "10.0.0.9")]


def test_service_version_change_is_modified_not_add_remove():
    old = _snap([_asset()])
    a = _asset()
    a["open_ports"][0]["version"] = "2.4.58"
    r = diff_snapshots(old, _snap([a]))
    assert _kinds(r) == [("port", "modified", "80/tcp")]
    assert "2.4.7 -> " in r["events"][0]["summary"] or "2.4.7" in r["events"][0]["summary"]


def test_missing_banner_is_not_a_change():
    old = _snap([_asset()])
    a = _asset()
    a["open_ports"][0].update(product="", version="")        # nmap failed to grab the banner this time
    a["technologies"] = ["Apache"]                            # whatweb lost the version too
    assert diff_snapshots(old, _snap([a]))["events"] == []


def test_technology_version_change_and_addition():
    old = _snap([_asset(techs=("Apache:2.4.7", "PHP:5.4"))])
    new = _snap([_asset(techs=("Apache:2.4.7", "PHP:7.4", "jQuery:1.2"))])
    assert _kinds(diff_snapshots(old, new)) == [("technology", "added", "jQuery"), ("technology", "modified", "PHP")]


def test_noise_technologies_are_ignored():
    old = _snap([_asset(techs=("Apache:2.4.7",))])
    new = _snap([_asset(techs=("Apache:2.4.7", "Cookies", "HttpOnly", "X-Frame-Options"))])
    assert diff_snapshots(old, new)["events"] == []


# ---- removal debounce ----

def test_removal_is_pending_first_then_confirmed_on_second_scan():
    s1 = _snap([_asset(ports=(80, 8181))])
    s2 = _snap([_asset(ports=(80,))])
    r2 = diff_snapshots(s1, s2)
    assert r2["events"] == [] and [p["subject"] for p in r2["pending"]] == ["8181/tcp"]
    assert r2["pending"][0]["status"] == "pending"
    s3 = _snap([_asset(ports=(80,))])
    r3 = diff_snapshots(s2, s3, pending=r2["pending"])
    assert _kinds(r3) == [("port", "removed", "8181/tcp")] and r3["events"][0]["status"] == "confirmed"
    assert r3["pending"] == [] and r3["dismissed"] == []


def test_flapping_port_is_silently_dismissed():
    s1 = _snap([_asset(ports=(80, 8181))])
    s2 = _snap([_asset(ports=(80,))])           # 8181 missing once
    r2 = diff_snapshots(s1, s2)
    s3 = _snap([_asset(ports=(80, 8181))])       # and back
    r3 = diff_snapshots(s2, s3, pending=r2["pending"])
    assert r3["events"] == [] and r3["pending"] == [] and r3["dismissed"] == [r2["pending"][0]["fingerprint"]]


def test_asset_removal_is_debounced_and_children_not_reported():
    s1 = _snap([_asset(), _asset(sub="10.0.0.9")], paths=[("/a", 200)])
    s2 = _snap([_asset()], paths=[("/a", 200)])
    r2 = diff_snapshots(s1, s2)
    assert r2["events"] == [] and [(p["category"], p["subject"]) for p in r2["pending"]] == [("asset", "10.0.0.9")]
    r3 = diff_snapshots(s2, s2, pending=r2["pending"])
    assert _kinds(r3) == [("asset", "removed", "10.0.0.9")]


def test_pending_carries_over_when_section_not_comparable():
    s1 = _snap([_asset(ports=(80, 8181))])
    s2 = _snap([_asset(ports=(80,))])
    r2 = diff_snapshots(s1, s2)
    bad = dict(OK_MR, portscan="failed: timeout")
    s3 = _snap([_asset(ports=(80,))], mr=bad)
    r3 = diff_snapshots(s2, s3, pending=r2["pending"])
    assert r3["events"] == [] and r3["dismissed"] == [] and len(r3["pending"]) == 1
    assert any(s["section"] == "ports" for s in r3["skipped"])


# ---- coverage gating ----

def test_failed_stage_never_looks_like_everything_vanished():
    s1 = _snap([_asset()], paths=[("/admin", 200)], findings=[_find()])
    bad = dict(OK_MR, dirbuster="failed: x", nuclei_network="failed: y", portscan="failed: z")
    s2 = _snap([_asset(ports=())], paths=[], findings=[], mr=bad)
    r = diff_snapshots(s1, s2)
    assert r["events"] == [] and r["pending"] == []
    assert {s["section"] for s in r["skipped"]} >= {"ports", "paths", "findings_network"}


def test_partial_dirscan_can_add_but_never_remove_paths():
    partial = dict(OK_MR, dirbuster="partial (1/2 hosts hit time limit)")
    s1 = _snap(paths=[("/a", 200), ("/b", 200)])
    s2 = _snap(paths=[("/a", 200), ("/new", 200)], mr=partial)
    r = diff_snapshots(s1, s2)
    assert _kinds(r) == [("path", "added", "/new")] and r["pending"] == []


def test_partial_baseline_does_not_report_old_paths_as_new():
    partial = dict(OK_MR, dirbuster="partial (x)")
    s1 = _snap(paths=[("/a", 200)], mr=partial)
    s2 = _snap(paths=[("/a", 200), ("/b", 200)])
    assert diff_snapshots(s1, s2)["events"] == []


def test_profile_without_whatweb_skips_technology_section():
    prof_quick = compute_coverage("quick", OK_MR)
    assert prof_quick["technologies"] is None and prof_quick["paths"] is None


# ---- findings and paths ----

def test_new_critical_finding_and_resolution_flow():
    s1 = _snap(findings=[])
    s2 = _snap(findings=[_find(sev="critical", tid="smb-ms17", name="EternalBlue")])
    r = diff_snapshots(s1, s2)
    assert _kinds(r) == [("finding", "added", "smb-ms17|10.0.0.5:445")]
    assert r["events"][0]["severity"] == "critical" and r["events"][0]["confidence"] == "confirmed"
    r_back = diff_snapshots(s2, _snap(findings=[]))
    assert r_back["events"] == [] and len(r_back["pending"]) == 1       # resolution is debounced too


def test_inferred_findings_are_grouped_and_marked():
    f = _find(tid="nvd-CVE-2021-0001", host="10.0.0.5", tags=("version-match",), cve="CVE-2021-0001",
              name="[version match] Apache httpd 2.4.7: CVE-2021-0001", sev="critical")
    r = diff_snapshots(_snap(), _snap(findings=[f]))
    e = r["events"][0]
    assert e["group"] == "Apache httpd 2.4.7" and e["confidence"] == "inferred"


def test_severity_change_is_modified():
    s1 = _snap(findings=[_find(sev="medium")])
    s2 = _snap(findings=[_find(sev="high")])
    r = diff_snapshots(s1, s2)
    assert _kinds(r) == [("finding", "modified", "t1|10.0.0.5:445")] and r["events"][0]["severity"] == "high"


def test_sensitive_new_path_is_high_and_becoming_reachable_is_flagged():
    s1 = _snap(paths=[("/admin", 403)])
    s2 = _snap(paths=[("/admin", 200), ("/phpmyadmin", 301), ("/icons/a.gif", 200)])
    r = diff_snapshots(s1, s2)
    by = {e["subject"]: e for e in r["events"]}
    assert by["/phpmyadmin"]["severity"] == "info"          # 301 is not directly reachable content
    assert by["/icons/a.gif"]["severity"] == "low"
    assert by["/admin"]["change_type"] == "modified" and by["/admin"]["severity"] == "high"   # 403 -> 200, sensitive
    s3 = _snap(paths=[("/backup.zip", 200)])
    assert diff_snapshots(_snap(paths=[]), s3)["events"][0]["severity"] == "high"


def test_http_status_and_title_changes():
    s1 = _snap([_asset(status=200, title="Welcome")])
    s2 = _snap([_asset(status=500, title="Error")])
    assert _kinds(diff_snapshots(s1, s2)) == [("http", "modified", "status"), ("http", "modified", "title")]


def test_events_sorted_by_severity_and_not_mutating_inputs():
    old = _snap([_asset(ports=(80,))])
    new = _snap([_asset(ports=(80, 3306, 9999))], findings=[_find(sev="critical", tid="x")])
    o, n = copy.deepcopy(old), copy.deepcopy(new)
    r = diff_snapshots(old, new)
    assert [e["severity"] for e in r["events"]] == sorted((e["severity"] for e in r["events"]),
                                                          key=["critical", "high", "medium", "low", "info"].index)
    assert old == o and new == n


def test_schema_mismatch_is_treated_as_no_baseline():
    old = _snap()
    old["schema"] = 0
    assert diff_snapshots(old, _snap())["baseline"] is True


def test_shell_history_and_dotfiles_are_sensitive():
    from backend.path_flags import is_sensitive_path
    for p in ("/.bash_history", "/.bashrc", "/.profile", "/.mysql_history", "/.netrc"):
        assert is_sensitive_path(p, 200), p
    assert not is_sensitive_path("/.cache", 301)
    assert not is_sensitive_path("/index.html", 200)
