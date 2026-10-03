import pytest

from backend.pipeline_utils import urls_in_scope
from backend.scanner import dns as dnsmod


def test_redirect_to_third_party_is_dropped():
    urls = ["https://app.example.com/", "http://example.com:8080/", "https://login.microsoftonline.com/x",
            "https://evil-example.com/", "https://example.com.evil.net/"]
    kept, dropped = urls_in_scope(urls, ["app.example.com"], "example.com")
    assert kept == ["https://app.example.com/", "http://example.com:8080/"]
    assert set(dropped) == {"https://login.microsoftonline.com/x", "https://evil-example.com/", "https://example.com.evil.net/"}


def test_ip_targets_keep_their_own_host_only():
    kept, dropped = urls_in_scope(["http://10.0.0.5:8181/", "http://10.0.0.6/", "https://github.com/"],
                                  ["10.0.0.5"], "10.0.0.5")
    assert kept == ["http://10.0.0.5:8181/"] and len(dropped) == 2


def test_hostless_urls_are_dropped_and_case_is_ignored():
    kept, dropped = urls_in_scope(["not a url", "HTTPS://App.Example.COM/"], ["app.example.com"], "example.com")
    assert kept == ["HTTPS://App.Example.COM/"] and dropped == ["not a url"]


class _Ans(list):
    pass


@pytest.fixture()
def fake_dns(monkeypatch):
    def install(ips):
        class R:
            lifetime = 0
            def resolve(self, name, kind):
                return _Ans(ips)
        monkeypatch.setattr(dnsmod.dns.resolver, "Resolver", R)
    return install


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "100.64.0.9", "192.168.0.1"])
def test_public_name_pointing_inside_is_not_scanned(fake_dns, monkeypatch, ip):
    monkeypatch.delenv("ASM_ALLOW_PRIVATE_TARGETS", raising=False)
    fake_dns([ip])
    assert dnsmod.resolve_host("sneaky.example.com") == {"subdomain": "sneaky.example.com", "ip": None, "alive": False}


def test_public_address_wins_over_a_private_one(fake_dns, monkeypatch):
    monkeypatch.delenv("ASM_ALLOW_PRIVATE_TARGETS", raising=False)
    fake_dns(["10.0.0.1", "93.184.216.34"])
    assert dnsmod.resolve_host("mixed.example.com")["ip"] == "93.184.216.34"


def test_lab_mode_allows_private_addresses(fake_dns, monkeypatch):
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    fake_dns(["192.168.16.128"])
    assert dnsmod.resolve_host("lab.example.com") == {"subdomain": "lab.example.com", "ip": "192.168.16.128", "alive": True}


@pytest.mark.parametrize("raw", ["--script=x.example.com", "-oN.example.com", "a b.example.com", "x;id.example.com", "ex\x00.example.com"])
def test_hostile_hostnames_are_rejected(raw):
    from backend.scanner.subdomain import normalize_hostname
    assert normalize_hostname(raw, "example.com") == ""


def test_normal_hostnames_still_pass():
    from backend.scanner.subdomain import normalize_hostname
    assert normalize_hostname("WWW.Example.com.", "example.com") == "www.example.com"
    assert normalize_hostname("a-b_c.example.com", "example.com") == "a-b_c.example.com"
