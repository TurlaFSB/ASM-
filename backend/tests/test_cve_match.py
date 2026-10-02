import json
from backend.scanner.cve_match import (
    cpe22_to_23, severity_from_cvss, parse_nvd, run_cve_match,
)
from backend.scanner.portscan import parse_nmap_xml
from backend.risk_scoring import score_asset


def test_cpe_conversion():
    assert cpe22_to_23("cpe:/a:proftpd:proftpd:1.3.5") == "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/o:linux:linux_kernel") is None        # no version -> would match everything
    assert cpe22_to_23("cpe:/h:cisco:router:1") is None
    assert cpe22_to_23("garbage") is None


def test_severity_bands():
    assert [severity_from_cvss(x) for x in (9.8, 7.5, 5.0, 2.0, 0, None)] == \
        ["critical", "high", "medium", "low", "info", "info"]


NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2015-3306", "descriptions": [{"lang": "en", "value": "mod_copy RCE"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}, "cisaExploitAdd": "2022-03-25"}},
    {"cve": {"id": "CVE-2000-0001", "descriptions": [{"lang": "en", "value": "minor"}],
             "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 3.0}}]}}},
]}


class FakeResp:
    def __init__(self, payload, code=200): self.payload, self.code = payload, code
    def raise_for_status(self):
        if self.code >= 400: raise RuntimeError(f"HTTP {self.code}")
    def json(self): return self.payload


class FakeSession:
    def __init__(self, payload=NVD, code=200): self.calls, self.payload, self.code = [], payload, code
    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(params["cpeName"]); return FakeResp(self.payload, self.code)


class FakeCache:
    def __init__(self): self.d = {}
    def get(self, k): return self.d.get(k)
    def setex(self, k, ttl, v): self.d[k] = v


HOSTS = [{"subdomain": "10.0.0.5", "ip": "10.0.0.5", "ports": [
    {"port": 21, "service": "ftp", "product": "ProFTPD", "version": "1.3.5",
     "cpe": ["cpe:/a:proftpd:proftpd:1.3.5"]},
    {"port": 22, "service": "ssh", "cpe": []},
]}]


def test_findings_threshold_kev_and_unverified_label():
    r = run_cve_match(HOSTS, session=FakeSession(), sleep=lambda s: None)
    assert r["module_status"] == "ok" and r["services_checked"] == 1
    assert len(r["findings"]) == 1                      # CVSS 3.0 filtered by default 7.0 threshold
    f = r["findings"][0]
    assert f["cve_id"] == "CVE-2015-3306" and f["severity"] == "critical" and f["host"] == "10.0.0.5"
    assert "kev" in f["tags"] and "unverified" in f["tags"]
    assert f["name"].startswith("[version match] ProFTPD 1.3.5")
    assert f["matched_at"] == "10.0.0.5:21"


def test_cache_prevents_second_lookup():
    cache, s1, s2 = FakeCache(), FakeSession(), FakeSession()
    run_cve_match(HOSTS, session=s1, cache=cache, sleep=lambda s: None)
    r = run_cve_match(HOSTS, session=s2, cache=cache, sleep=lambda s: None)
    assert len(s1.calls) == 1 and len(s2.calls) == 0 and len(r["findings"]) == 1


def test_http_failure_is_soft():
    r = run_cve_match(HOSTS, session=FakeSession(code=503), sleep=lambda s: None)
    assert r["findings"] == [] and r["module_status"].startswith("failed")


def test_no_cpe_means_no_lookup():
    h = [{"subdomain": "a", "ip": "a", "ports": [{"port": 80, "cpe": []}]}]
    s = FakeSession()
    r = run_cve_match(h, session=s, sleep=lambda x: None)
    assert s.calls == [] and r["module_status"] == "no services with version info"


def test_nmap_xml_cpe_extracted():
    xml = ('<nmaprun><host><ports><port protocol="tcp" portid="21"><state state="open"/>'
           '<service name="ftp" product="ProFTPD" version="1.3.5" extrainfo="x"><cpe>cpe:/a:proftpd:proftpd:1.3.5</cpe></service>'
           '</port></ports></host></nmaprun>')
    p = parse_nmap_xml(xml)[0]
    assert p["cpe"] == ["cpe:/a:proftpd:proftpd:1.3.5"] and p["extrainfo"] == "x"


class A:  # minimal asset stand-in
    def __init__(self, ports): self.open_ports = [{"port": n} for n in ports]; self.http_title = ""


def test_port_exposure_scoring_tiers():
    assert score_asset(A([80]), [])["risk_score"] == 0
    ms3 = score_asset(A([21, 22, 80, 111, 139, 445, 3306, 6667]), [])
    assert ms3["risk_score"] == 25 and ms3["risk_level"] == "Low"


def test_cpe_candidates_normalise_build_suffix():
    from backend.scanner.cve_match import cpe_candidates
    c = cpe_candidates("cpe:2.3:a:eclipse:jetty:8.1.7.v20120910:*:*:*:*:*:*:*")
    assert c == ["cpe:2.3:a:eclipse:jetty:8.1.7.v20120910:*:*:*:*:*:*:*",
                 "cpe:2.3:a:eclipse:jetty:8.1.7:*:*:*:*:*:*:*"]
    assert len(cpe_candidates("cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*")) == 1


def test_fallback_candidate_used_when_exact_returns_nothing():
    class Sess(FakeSession):
        def get(self, url, params=None, headers=None, timeout=None):
            self.calls.append(params["cpeName"])
            empty = {"vulnerabilities": []}
            return FakeResp(NVD if params["cpeName"].endswith("8.1.7:*:*:*:*:*:*:*") else empty)
    s = Sess()
    h = [{"subdomain": "h", "ip": "h", "ports": [{"port": 8080, "product": "Jetty",
          "version": "8.1.7.v20120910", "cpe": ["cpe:/a:eclipse:jetty:8.1.7.v20120910"]}]}]
    r = run_cve_match(h, session=s, sleep=lambda x: None)
    assert len(s.calls) == 2 and len(r["findings"]) == 1
