from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base
from backend.exposure import lookalikes as L, registry, runner
from backend.exposure.base import CollectorError, Findings, NotApplicable
from backend.models import Target
from backend.models.exposure import CollectorRun, ExposureFinding


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


def rec(a=(), mx=(), ns=()):
    return {"a": list(a), "mx": list(mx), "ns": list(ns)}


def fake_dns(table):
    def lookup(name):
        if isinstance(table.get(name), Exception):
            raise table[name]
        return table.get(name)
    return lookup


# ------------------------------------------------------------------ generation

def test_registrable_parts():
    assert L.registrable_parts("www.acme.com") == ("acme", "com")
    assert L.registrable_parts("shop.acme.co.uk") == ("acme", "co.uk")
    assert L.registrable_parts("acme.in") == ("acme", "in")
    for bad in ("10.0.0.5", "ms3.local", "localhost", "", "singlelabel", "host.internal"):
        assert L.registrable_parts(bad) is None


def test_candidates_cover_the_main_tricks_and_are_clean():
    names = dict(L.generate_candidates("acme.com"))
    assert names["acem.com"] == "transposition" and names["acm.com"] == "omission"
    assert names["acme-login.com"] == "keyword" and names["login-acme.com"] == "keyword"
    assert names["acme.net"] == "tld" and names["4cme.com"] == "homoglyph"
    assert any(t == "idn" and n.startswith("xn--") for n, t in names.items())
    assert "acme.com" not in names
    assert all(L.ASCII_NAME_OK.match(n) for n in names)           # only valid, ASCII (punycode) hostnames
    assert len(names) == len(set(names))


def test_candidates_bounded_and_most_suspicious_first():
    c = L.generate_candidates("internationalbusinessmachines.com", limit=50)
    assert len(c) == 50
    big = L.generate_candidates("internationalbusinessmachines.com")
    assert len(big) <= L.MAX_CANDIDATES
    assert big[0][1] in ("homoglyph", "idn")
    assert L.generate_candidates("10.1.1.1") == []


def test_generated_idn_names_decode_back_to_lookalikes():
    for name, tech in L.generate_candidates("acme.com"):
        if tech == "idn":
            shown = name.encode("ascii").decode("idna")
            assert shown != name and shown.endswith(".com")


# ------------------------------------------------------------------ collection

def test_not_applicable_for_ip_and_internal():
    for d in ("192.168.1.5", "ms3.local"):
        with pytest.raises(NotApplicable):
            L.LookalikeCollector(resolver=fake_dns({})).collect(d, None, None)


def test_only_registered_names_are_reported_with_severity_rules():
    table = {
        "acme.com": rec(["1.1.1.1"], ["mx.acme.com"], ["ns1.acme.com"]),
        "acem.com": rec(["9.9.9.9"], ["mail.evil.example"], ["ns.evil.example"]),    # A + MX
        "acm.com": rec(["9.9.9.8"], [], ["ns.evil.example"]),                         # A only
        "acme.net": rec([], [], ["ns.parking.example"]),                              # delegation only
        "acme-login.com": rec([], [], ["ns.parking.example"]),                        # keyword bumps low -> medium
        "acme.org": rec(["1.1.1.1"], [], ["ns.other.example"]),                       # same IP as the real site
        "acme.io": rec([], [], ["ns1.acme.com"]),                                     # same name servers as the real site
    }
    out = {f.key: f for f in L.LookalikeCollector(resolver=fake_dns(table)).collect("acme.com", None, None)}
    assert set(out) == {"acem.com", "acm.com", "acme.net", "acme-login.com", "acme.org", "acme.io"}
    assert out["acem.com"].severity == "high" and out["acm.com"].severity == "medium"
    assert out["acme.net"].severity == "low" and out["acme-login.com"].severity == "medium"
    assert out["acme.org"].severity == "info" and out["acme.io"].severity == "info"
    assert out["acem.com"].evidence["technique"] == "transposition"
    assert out["acem.com"].evidence["mx"] == ["mail.evil.example"] and out["acem.com"].kind == "lookalike"


def test_idn_finding_shows_unicode_and_keeps_punycode_key():
    puny, _ = next((n, t) for n, t in L.generate_candidates("acme.com") if t == "idn")
    out = L.LookalikeCollector(resolver=fake_dns({puny: rec(["9.9.9.9"], [], [])})).collect("acme.com", None, None)
    f = out[0]
    assert f.key == puny and f.evidence["displays_as"] and "displays as" in f.summary and f.severity == "high"


def test_resolver_trouble_is_not_treated_as_clean():
    names = [n for n, _ in L.generate_candidates("acme.com")]
    boom = {n: TimeoutError(n) for n in names}
    with pytest.raises(CollectorError) as e:
        L.LookalikeCollector(resolver=fake_dns(boom)).collect("acme.com", None, None)
    assert "unreliable" in e.value.label


def test_deadline_gives_incomplete_results(monkeypatch):
    c = L.LookalikeCollector(resolver=fake_dns({"acem.com": rec(["9.9.9.9"], [], [])}))
    ticks = iter(range(0, 10_000, 100))             # every call to "now" jumps 100 s forward
    c._now = lambda: next(ticks)
    out = c.collect("acme.com", None, None)
    assert isinstance(out, Findings) and out.complete is False


# ------------------------------------------------------------------ runner interplay

@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


T0 = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _target(db, domain, sources=("lookalike_domains",)):
    t = Target(domain=domain, authorized=True, authorized_by="me", is_active=True, exposure_sources=list(sources))
    db.add(t); db.commit()
    return t


def test_registered_with_default_collector_is_available():
    assert registry.get("lookalike_domains") is not None and registry.get("lookalike_domains").configured()


def test_skipped_run_is_recorded_and_not_retried_every_hour(db):
    t = _target(db, "10.0.0.9")
    r = runner.run_collectors(db, t, now=T0)
    assert r["lookalike_domains"]["status"] == "skipped"
    run = db.query(CollectorRun).one()
    assert run.status == "skipped" and "public domain" in run.error
    r = runner.run_collectors(db, t, now=T0 + timedelta(hours=2))
    assert r["lookalike_domains"]["status"] == "too_soon"


def test_incomplete_run_never_resolves_old_findings_and_escalation_alerts(db, monkeypatch):
    t = _target(db, "acme.com")
    table = {"acem.com": rec([], [], ["ns.x.example"])}                 # low at first
    coll = L.LookalikeCollector(resolver=fake_dns(table))
    monkeypatch.setitem(registry.REGISTRY, "lookalike_domains", coll)
    runner.run_collectors(db, t, now=T0)
    f = db.query(ExposureFinding).one()
    assert f.severity == "low" and f.kind == "lookalike"
    # it gains a web server and mail: severity escalates and is reported again
    table["acem.com"] = rec(["9.9.9.9"], ["mx.x.example"], ["ns.x.example"])
    r = runner.run_collectors(db, t, now=T0 + timedelta(days=2))
    assert r["lookalike_domains"]["new"] == 1 and db.query(ExposureFinding).one().severity == "high"
    # three incomplete runs that do not even see it must not mark it resolved
    ticks = iter(range(0, 10 ** 6, 100))
    coll._now = lambda: next(ticks)
    table.clear()
    for i in range(3, 6):
        runner.run_collectors(db, t, now=T0 + timedelta(days=i * 2))
    assert db.query(ExposureFinding).one().status == "open"
