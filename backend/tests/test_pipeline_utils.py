from backend.pipeline_utils import (
    build_web_targets, tls_targets_from_urls, merge_http_info, pipeline_trusted_for_removals,
)

MS3 = [{"subdomain": "192.168.16.128", "ip": "192.168.16.128", "ports": [
    {"port": 22, "protocol": "tcp", "service": "ssh"},
    {"port": 80, "protocol": "tcp", "service": "http"},
    {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
    {"port": 8383, "protocol": "tcp", "service": "ssl/http"},
    {"port": 445, "protocol": "tcp", "service": "microsoft-ds"},
]}]


def test_web_targets_from_ports():
    t = build_web_targets(MS3, ["192.168.16.128"])
    assert t == ["192.168.16.128:80", "192.168.16.128:8080", "192.168.16.128:8383"]


def test_web_targets_fallback_when_nmap_empty():
    assert build_web_targets([], ["a.example.com", "a.example.com"]) == ["a.example.com"]


def test_tls_targets_only_https_with_ports():
    urls = ["http://h:80", "https://h:8443", "https://h", "https://h:8443"]
    assert tls_targets_from_urls(urls) == [("h", 8443), ("h", 443)]


def test_merge_unions_technologies_prefers_standard_port():
    hosts = [
        {"url": "http://1.2.3.4:8080", "host": "1.2.3.4", "input": "1.2.3.4:8080",
         "status_code": 404, "title": "Tomcat", "technologies": ["Tomcat"]},
        {"url": "http://1.2.3.4", "host": "1.2.3.4", "input": "1.2.3.4:80",
         "status_code": 200, "title": "Home", "technologies": ["Apache"]},
    ]
    m = merge_http_info(hosts)["1.2.3.4"]
    assert m["technologies"] == ["Apache", "Tomcat"]
    assert m["status_code"] == 200 and m["title"] == "Home"


def test_removals_not_trusted_when_dns_failed():
    assert not pipeline_trusted_for_removals({"dns": "failed: x", "subfinder": "ok"}, False)
    assert not pipeline_trusted_for_removals({"dns": "ok", "subfinder": "timeout"}, False)
    assert pipeline_trusted_for_removals({"dns": "ok", "subfinder": "ok"}, False)
    assert pipeline_trusted_for_removals({"dns": "resolved directly (internal target)"}, True)
    assert not pipeline_trusted_for_removals({"dns": "resolution failed"}, True)
