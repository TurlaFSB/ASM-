import pytest
from backend.validators import validate_target, classify_target


@pytest.fixture(autouse=True)
def _no_private(monkeypatch):
    monkeypatch.delenv("ASM_ALLOW_PRIVATE_TARGETS", raising=False)


@pytest.mark.parametrize("v,exp", [
    ("Example.COM", "example.com"),
    ("  sub.example.co.uk ", "sub.example.co.uk"),
    ("8.8.8.8", "8.8.8.8"),
    ("93.184.216.34", "93.184.216.34"),
])
def test_valid(v, exp):
    assert validate_target(v) == exp


@pytest.mark.parametrize("v", [
    "", "   ", "example", "example.com; id", "example.com && ls", "$(id).com",
    "-oN.example.com", "-iL /etc/passwd", "exa mple.com", "http://example.com",
    "example.com/path", "a" * 64 + ".com", ("a." * 130) + "com", "ex_ample.com",
    "::1", "2001:db8::1", "127.0.0.1", "169.254.169.254", "0.0.0.0",
    "224.0.0.1", "240.0.0.1", "10.0.0.5", "192.168.16.128", "172.16.0.1",
    "host.local", "999.1.1.1", "1.2.3",
])
def test_rejected_by_default(v):
    with pytest.raises(ValueError):
        validate_target(v)


def test_private_allowed_with_flag(monkeypatch):
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    assert validate_target("192.168.16.128") == "192.168.16.128"
    assert validate_target("ms3.local") == "ms3.local"


@pytest.mark.parametrize("v", ["127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "224.0.0.1"])
def test_always_blocked_even_with_flag(monkeypatch, v):
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    with pytest.raises(ValueError):
        validate_target(v)


def test_classify():
    assert classify_target("1.2.3.4") == "ip"
    assert classify_target("example.com") == "domain"
