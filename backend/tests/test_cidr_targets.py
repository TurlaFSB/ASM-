"""CIDR (network range) targets: validation, size cap, safety rules, sweep and pipeline hooks."""
import pytest

from backend import pipeline_stages as ps
from backend.exposure.base import applies_to
from backend.pipeline_utils import pipeline_trusted_for_removals
from backend.validators import cidr_hosts, classify_target, max_cidr_hosts, validate_target


def test_public_range_is_accepted_and_canonicalised():
    assert validate_target("203.0.113.0/28") == "203.0.113.0/28"
    assert validate_target("203.0.113.9/28") == "203.0.113.0/28"      # host bits are normalised away
    assert validate_target("203.0.113.7/32") == "203.0.113.7"          # one address is just an IP


def test_classification():
    assert classify_target("203.0.113.0/28") == "cidr"
    assert classify_target("203.0.113.5") == "ip"
    assert classify_target("example.com") == "domain"


@pytest.mark.parametrize("bad", ["203.0.113.0/", "203.0.113.0/33", "203.0.113/24", "a.b.c.d/24",
                                 "203.0.113.0/24/1", "example.com/24", "203.0.113.0/-1", "::1/128"])
def test_malformed_ranges_rejected(bad):
    with pytest.raises(ValueError):
        validate_target(bad)


def test_size_cap_default_and_override(monkeypatch):
    assert validate_target("198.51.100.0/24") == "198.51.100.0/24"     # 256 addresses is the default limit
    with pytest.raises(ValueError, match="limit is 256"):
        validate_target("198.51.0.0/23")
    monkeypatch.setenv("ASM_MAX_CIDR_HOSTS", "512")
    assert validate_target("198.51.0.0/23") == "198.51.0.0/23"
    monkeypatch.setenv("ASM_MAX_CIDR_HOSTS", "999999")                  # hard ceiling holds
    assert max_cidr_hosts() == 1024
    with pytest.raises(ValueError):
        validate_target("198.51.0.0/21")
    monkeypatch.setenv("ASM_MAX_CIDR_HOSTS", "junk")
    assert max_cidr_hosts() == 256


@pytest.mark.parametrize("bad", ["127.0.0.0/30", "169.254.169.0/28", "224.0.0.0/30", "240.0.0.0/28", "0.0.0.0/28"])
def test_dangerous_ranges_always_blocked(bad, monkeypatch):
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    with pytest.raises(ValueError, match="not allowed"):
        validate_target(bad)


def test_private_ranges_need_the_flag(monkeypatch):
    monkeypatch.delenv("ASM_ALLOW_PRIVATE_TARGETS", raising=False)
    for rng in ("10.0.0.0/28", "192.168.1.0/24", "172.20.0.0/28"):
        with pytest.raises(ValueError, match="Private ranges are disabled"):
            validate_target(rng)
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"


def test_ranges_next_to_private_space_follow_the_rule(monkeypatch):
    monkeypatch.delenv("ASM_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setenv("ASM_MAX_CIDR_HOSTS", "1024")
    assert validate_target("9.255.252.0/22") == "9.255.252.0/22"      # last public block before 10/8
    with pytest.raises(ValueError):
        validate_target("10.0.0.0/22")


def test_hosts_exclude_network_and_broadcast():
    h = cidr_hosts("203.0.113.0/29")
    assert h[0] == "203.0.113.1" and h[-1] == "203.0.113.6" and len(h) == 6
    assert len(cidr_hosts("203.0.113.0/31")) == 2


def test_sweep_keeps_only_answering_hosts():
    live, status = ps.sweep_range("203.0.113.0/29", probe=lambda ip, t: ip.endswith((".2", ".5")))
    assert [h["ip"] for h in live] == ["203.0.113.2", "203.0.113.5"]
    assert all(h["subdomain"] == h["ip"] for h in live)
    assert status.startswith("resolved") and "2 of 6" in status


def test_empty_sweep_does_not_license_removals():
    live, status = ps.sweep_range("203.0.113.0/29", probe=lambda ip, t: False)
    assert live == []
    assert not pipeline_trusted_for_removals({"dns": status}, True)
    assert pipeline_trusted_for_removals({"dns": "resolved directly (range sweep: 1 of 6 addresses answered)"}, True)


def test_pipeline_treats_range_as_internal_and_dispatches_to_sweep(monkeypatch):
    assert ps.is_internal_target("203.0.113.0/28")
    monkeypatch.setattr(ps, "sweep_range", lambda c: ([{"subdomain": "203.0.113.1", "ip": "203.0.113.1"}], "resolved directly (x)"))
    hosts, status = ps.internal_live_hosts("203.0.113.0/28")
    assert hosts[0]["ip"] == "203.0.113.1" and status.startswith("resolved")


def test_exposure_sources_do_not_apply_to_a_range():
    assert applies_to("203.0.113.0/28") is False
    assert applies_to("example.com") is True
