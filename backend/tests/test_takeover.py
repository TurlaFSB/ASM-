import dns.resolver

from backend.scanner import takeover as tk


class FakeResolver:
    """records: {(name, rtype): [targets] | 'NXDOMAIN' | 'NOANSWER'}; anything unlisted is NoAnswer."""
    lifetime = 5

    def __init__(self, records):
        self.records = records

    def resolve(self, name, rtype):
        v = self.records.get((name, rtype), "NOANSWER")
        if v == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if v == "NOANSWER":
            raise dns.resolver.NoAnswer()
        return [type("R", (), {"target": t})() for t in v]


def test_provider_matching_by_suffix():
    assert tk.match_provider("acme.github.io.").slug == "github-pages"
    assert tk.match_provider("x.azurewebsites.net").slug == "azure"
    assert tk.match_provider("evil-github.io.attacker.com") is None
    assert tk.match_provider("cdn.example.net") is None


def test_plain_name_without_cname_is_ignored():
    res = FakeResolver({})
    assert tk.resolve_cname_chain("www.a.com", res)["chain"] == []
    assert tk.check_name("www.a.com", "a.com", res, fetch=lambda n: "") is None


def test_dangling_azure_cname_is_a_high_candidate():
    res = FakeResolver({("blog.a.com", "CNAME"): ["a-blog.azurewebsites.net."],
                        ("a-blog.azurewebsites.net", "CNAME"): "NOANSWER",
                        ("a-blog.azurewebsites.net", "A"): "NXDOMAIN"})
    f = tk.check_name("blog.a.com", "a.com", res)
    assert f["severity"] == "high" and f["template_id"] == "takeover-azure-nxdomain"
    assert f["host"] == "blog.a.com" and "takeover" in f["tags"] and "posture" in f["tags"]


def test_dangling_cname_to_unknown_provider_is_medium_and_own_domain_is_low():
    r1 = FakeResolver({("x.a.com", "CNAME"): ["gone.thirdparty.io."], ("gone.thirdparty.io", "A"): "NXDOMAIN"})
    assert tk.check_name("x.a.com", "a.com", r1)["severity"] == "medium"
    r2 = FakeResolver({("x.a.com", "CNAME"): ["old.a.com."], ("old.a.com", "A"): "NXDOMAIN"})
    assert tk.check_name("x.a.com", "a.com", r2)["severity"] == "low"


def test_live_provider_page_fingerprint_confirms_candidate():
    res = FakeResolver({("docs.a.com", "CNAME"): ["acme.github.io."], ("acme.github.io", "A"): ["185.199.108.153"]})
    hit = tk.check_name("docs.a.com", "a.com", res,
                        fetch=lambda n: "<h1>there isn't a github pages site here.</h1>")
    assert hit["template_id"] == "takeover-github-pages" and hit["severity"] == "high"
    assert tk.check_name("docs.a.com", "a.com", res, fetch=lambda n: "<h1>welcome</h1>") is None
    assert tk.check_name("docs.a.com", "a.com", res, fetch=lambda n: "") is None   # unreachable: no claim


def test_transient_dns_failure_is_never_a_finding():
    class Flaky(FakeResolver):
        def resolve(self, name, rtype):
            if rtype == "A":
                raise dns.resolver.NoNameservers()
            return super().resolve(name, rtype)
    res = Flaky({("x.a.com", "CNAME"): ["acme.github.io."]})
    assert tk.check_name("x.a.com", "a.com", res, fetch=lambda n: "") is None


def test_cname_loop_does_not_hang():
    res = FakeResolver({("a.a.com", "CNAME"): ["b.a.com."], ("b.a.com", "CNAME"): ["a.a.com."]})
    assert tk.resolve_cname_chain("a.a.com", res)["error"] == "cname loop"


def test_run_checks_all_names_and_reports_status():
    res = FakeResolver({("blog.a.com", "CNAME"): ["a.azurewebsites.net."], ("a.azurewebsites.net", "A"): "NXDOMAIN"})
    out = tk.run_takeover_check(["blog.a.com", "www.a.com", "BLOG.a.com.", "bad name!"], "a.com",
                                resolver=res, fetch=lambda n: "")
    assert out["module_status"] == "ok" and out["checked"] == 2
    assert [f["host"] for f in out["findings"]] == ["blog.a.com"]
    assert tk.run_takeover_check([], "a.com")["module_status"] == "no names provided"


def test_one_crashing_name_degrades_status_without_losing_the_rest(monkeypatch):
    def check(n, own, resolver, fetch):
        if n == "bad.a.com":
            raise RuntimeError("boom")
        return None
    monkeypatch.setattr(tk, "check_name", check)
    out = tk.run_takeover_check(["bad.a.com", "ok.a.com"], "a.com")
    assert out["module_status"].startswith("partial: 1 of 2")
