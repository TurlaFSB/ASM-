from types import SimpleNamespace as NS

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import risk_scoring as rs
from backend.db import Base
from backend.models import Asset, Scan, Target
from backend.models.vulnerability import Vulnerability


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


@pytest.fixture(autouse=True)
def no_kev(monkeypatch):
    monkeypatch.setattr(rs, "is_known_exploited", lambda cve: False)


def V(sev="info", cvss=None, cve=None):
    return NS(severity=sev, cvss_score=cvss, cve_id=cve)


def A(ports=(), title=""):
    return NS(open_ports=list(ports), http_title=title, subdomain="a.example.com")


def test_cvss_score_wins_else_severity_midpoint():
    assert rs.cvss_for_vuln(V("low", cvss=9.8)) == 9.8
    assert rs.cvss_for_vuln(V("high")) == 7.5
    assert rs.cvss_for_vuln(V("weird")) == 0.5
    assert rs.cvss_for_vuln(V("high", cvss="not-a-number")) == 7.5


@pytest.mark.parametrize("score,level", [(95, "Critical"), (80, "Critical"), (79, "High"), (60, "High"),
                                          (59, "Medium"), (35, "Medium"), (34, "Low"), (10, "Low"), (9, "Informational")])
def test_bands(score, level):
    r = rs.score_asset(A(), [V(cvss=score / 10)])
    assert r["risk_level"] == level and r["risk_score"] == round(score, 1)


def test_no_findings_is_informational_and_max_not_sum():
    assert rs.score_asset(A(), [])["risk_level"] == "Informational"
    one = rs.score_asset(A(), [V("high", cvss=7.0)])
    mixed = rs.score_asset(A(), [V("high", cvss=7.0), V("low"), V("info"), V("info")])
    assert one["risk_score"] == mixed["risk_score"] == 70.0       # low/info findings add nothing


def test_multiple_serious_findings_bonus_is_capped():
    base = rs.score_asset(A(), [V("high", cvss=5.0)])["risk_score"]               # medium-ish base
    three = rs.score_asset(A(), [V("high", cvss=5.0)] * 3)["risk_score"]
    many = rs.score_asset(A(), [V("critical", cvss=5.0)] * 20)["risk_score"]
    assert three == base + 10 and many == base + 15


def test_port_and_admin_bonuses_and_clamp():
    assert rs.score_asset(A(ports=[445]), [V("high", cvss=5.0)])["risk_score"] == 65.0
    capped = rs.score_asset(A(ports=[{"port": 445}, {"port": 3389}, {"port": 23}, {"port": 6379}]), [V("high", cvss=5.0)])
    assert capped["risk_score"] == 75.0                                           # +25 cap
    assert rs.score_asset(A(title="Admin Login"), [V("high", cvss=5.0)])["risk_score"] == 55.0
    assert rs.score_asset(A(ports=[2375, 445]), [V("critical", cvss=10.0)])["risk_score"] == 100.0


def test_known_exploited_forces_critical(monkeypatch):
    monkeypatch.setattr(rs, "is_known_exploited", lambda cve: cve == "CVE-2024-0001")
    r = rs.score_asset(A(), [V("low", cvss=2.0, cve="CVE-2024-0001")])
    assert r["risk_level"] == "Critical" and r["known_exploited"] is True and r["risk_score"] >= 90


def test_extract_host():
    assert rs._extract_host("https://a.example.com:8443/x") == "a.example.com"
    assert rs._extract_host("a.example.com:80") == "a.example.com"
    assert rs._extract_host("a.example.com/path") == "a.example.com"


def test_score_all_assets_persists_per_host(monkeypatch):
    monkeypatch.setattr(rs, "evaluate_exploitability",
                        lambda v, a: {"is_exploitable_confirmed": False, "exploitability_reasons": []})
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="example.com", authorized=True, authorized_by="me", is_active=True)
    db.add(t); db.commit()
    s = Scan(target_id=t.id, status="completed"); db.add(s); db.commit()
    risky = Asset(target_id=t.id, subdomain="risky.example.com", open_ports=[445])
    quiet = Asset(target_id=t.id, subdomain="quiet.example.com", open_ports=[])
    db.add_all([risky, quiet]); db.commit()
    db.add(Vulnerability(target_id=t.id, scan_id=s.id, template_id="t1", host="https://risky.example.com:8443", name="x", severity="critical",
                         cvss_score=9.5, cve_id="CVE-2024-1"))
    db.commit()
    rs.score_all_assets(db, t.id, s.id)
    db.refresh(risky); db.refresh(quiet)
    assert risky.risk_level == "Critical" and quiet.risk_level == "Informational"
