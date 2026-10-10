import dns.resolver
import pytest

from backend.scanner import dns_hygiene as dh


class Rec:
    def __init__(self, target=None):
        self.target = target


class FakeResolver:
    """zone: {(name, type): [records] | Exception class}. Anything not listed is NoAnswer."""
    lifetime = 5

    def __init__(self, zone):
        self.zone = zone

    def resolve(self, name, rtype):
        v = self.zone.get((name, rtype), dns.resolver.NoAnswer)
        if isinstance(v, type) and issubclass(v, Exception):
            raise v()
        if isinstance(v, Exception):
            raise v
        return v


def ids(r):
    return {f["template_id"] for f in r["findings"]}


APEX = {("example.com", "SOA"): [Rec()]}


def test_dangling_name_server_is_high_and_names_the_server():
    z = {**APEX, ("example.com", "NS"): [Rec("ns1.example.com."), Rec("ns.gone-provider.net.")],
         ("ns1.example.com", "A"): [Rec()], ("ns.gone-provider.net", "A"): dns.resolver.NXDOMAIN,
         ("example.com", "CAA"): [Rec()], ("example.com", "DS"): [Rec()]}
    r = dh.run_dns_hygiene("example.com", FakeResolver(z))
    assert ids(r) == {"dns-ns-dangling"}
    f = r["findings"][0]
    assert f["severity"] == "high" and "ns.gone-provider.net" in f["matched_at"] and "posture" in f["tags"] and "dns-hygiene" in f["tags"]


def test_ipv6_only_name_server_is_not_dangling():
    z = {**APEX, ("example.com", "NS"): [Rec("ns6.example.com.")], ("ns6.example.com", "A"): dns.resolver.NoAnswer,
         ("ns6.example.com", "AAAA"): [Rec()], ("example.com", "CAA"): [Rec()], ("example.com", "DS"): [Rec()]}
    assert dh.run_dns_hygiene("example.com", FakeResolver(z))["findings"] == []


def test_a_lookup_failure_never_becomes_a_dangling_finding():
    z = {**APEX, ("example.com", "NS"): [Rec("ns1.example.com.")], ("ns1.example.com", "A"): dns.resolver.NoNameservers,
         ("example.com", "CAA"): [Rec()], ("example.com", "DS"): [Rec()]}
    assert "dns-ns-dangling" not in ids(dh.run_dns_hygiene("example.com", FakeResolver(z)))


def test_missing_caa_and_dnssec_are_info():
    z = {**APEX, ("example.com", "NS"): [], ("example.com", "DS"): dns.resolver.NoAnswer}
    r = dh.run_dns_hygiene("example.com", FakeResolver(z))
    assert ids(r) == {"dns-caa-missing", "dns-dnssec-missing"}
    assert {f["severity"] for f in r["findings"]} == {"info"}


def test_caa_inherited_from_parent_counts():
    z = {("app.example.com", "SOA"): dns.resolver.NoAnswer, ("example.com", "CAA"): [Rec()]}
    assert dh.run_dns_hygiene("app.example.com", FakeResolver(z))["findings"] == []


def test_plain_hostnames_skip_zone_only_checks():
    z = {("app.example.com", "SOA"): dns.resolver.NoAnswer, ("app.example.com", "CAA"): [Rec()]}
    # no NS / DS rows exist; asking for them would raise NoAnswer, and a host must not be reported for lacking DNSSEC
    assert dh.run_dns_hygiene("app.example.com", FakeResolver(z))["findings"] == []


def test_dnssec_present_is_clean():
    z = {**APEX, ("example.com", "NS"): [], ("example.com", "CAA"): [Rec()], ("example.com", "DS"): [Rec()]}
    assert dh.run_dns_hygiene("example.com", FakeResolver(z))["findings"] == []


def test_lookup_errors_are_reported_as_failure_not_as_findings():
    z = {("example.com", "SOA"): dns.resolver.NoNameservers}
    r = dh.run_dns_hygiene("example.com", FakeResolver(z))
    assert r["findings"] == [] and r["module_status"].startswith("failed")


def test_caa_lookup_error_says_nothing():
    z = {**APEX, ("example.com", "NS"): [], ("example.com", "DS"): [Rec()], ("example.com", "CAA"): dns.resolver.NoNameservers}
    assert dh.run_dns_hygiene("example.com", FakeResolver(z))["findings"] == []


def test_empty_domain():
    assert dh.run_dns_hygiene("", FakeResolver({}))["module_status"] == "no domain provided"


def test_dns_hygiene_tag_classifies_as_its_own_diff_source():
    from backend.diffing.snapshot import finding_source
    assert finding_source(["dns-hygiene", "posture", "dns"]) == "dns"
