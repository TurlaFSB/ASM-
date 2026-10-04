from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import triage as tg
from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.audit_log import AuditLog
from backend.models.finding_triage import FindingTriage
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.tests.test_vuln_api import _jsonb_as_json  # noqa: F401  (JSONB shim for SQLite)


def test_finding_key_is_stable_and_specific():
    a = tg.finding_key("tpl", "CVE-2020-1", "Host.Test", "http://host.test:8080/x")
    assert a == tg.finding_key("TPL", "cve-2020-1", "host.test", "http://host.test:8080/y")      # case and path do not matter
    assert a != tg.finding_key("tpl", "CVE-2020-1", "host.test", "http://host.test:9090/x")      # port does
    assert a != tg.finding_key("tpl", "CVE-2020-2", "host.test", "http://host.test:8080/x")      # CVE does
    assert len(a) == 32


def _t(status, **kw):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(status=status, expires_at=kw.get("expires_at"), updated_at=kw.get("updated_at", now))


def test_suppression_rules():
    now = datetime.now(timezone.utc)
    assert not tg.is_suppressing(None, now)
    assert not tg.is_suppressing(_t("in_progress"), now)
    assert tg.is_suppressing(_t("false_positive"), now)
    assert tg.is_suppressing(_t("accepted_risk", expires_at=now + timedelta(days=1)), now)
    assert not tg.is_suppressing(_t("accepted_risk", expires_at=now - timedelta(seconds=1)), now)       # review date passed
    decided = now - timedelta(hours=1)
    assert tg.is_suppressing(_t("resolved", updated_at=decided), decided - timedelta(days=1))          # seen before the fix
    assert not tg.is_suppressing(_t("resolved", updated_at=decided), decided + timedelta(minutes=5))   # seen again after: reappeared


@pytest.fixture()
def env():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="acme.test", authorized=True, authorized_by="me", is_active=True)
    db.add(t); db.commit()
    s1 = Scan(target_id=t.id, status="completed"); db.add(s1); db.commit()

    def v(name, sev="high", scan=s1, created=None, tags=None):
        row = Vulnerability(target_id=t.id, scan_id=scan.id, template_id=name, name=name, severity=sev, host="acme.test",
                            matched_at="https://acme.test:443/", tags=tags or [])
        if created:
            row.created_at = created
        db.add(row); db.commit()
        return row

    state = SimpleNamespace(admin=True)
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(username="pranav", role="admin" if state.admin else "viewer")
    yield db, t, s1, v, TestClient(app), state
    app.dependency_overrides.clear()


def names(c, **params):
    return sorted(r["name"] for r in c.get("/vulnerabilities/", params=params).json())


def triage(c, ids, status, **kw):
    return c.post("/vulnerabilities/triage", json={"ids": ids, "status": status, **kw})


def test_false_positive_needs_a_reason_and_hides_the_finding(env):
    db, t, s1, v, c, _ = env
    a, b = v("a"), v("b")
    assert triage(c, [a.id], "false_positive").status_code == 422
    assert triage(c, [a.id], "false_positive", note="  ").status_code == 422
    r = triage(c, [a.id], "false_positive", note="Banner is spoofed by the WAF")
    assert r.status_code == 200 and r.json() == {"updated": 1}
    assert names(c) == ["b"]
    assert names(c, triage="all") == ["a", "b"]
    assert names(c, triage="triaged") == ["a"]
    shown = {r["name"]: r for r in c.get("/vulnerabilities/", params={"triage": "all"}).json()}
    assert shown["a"]["triage"]["status"] == "false_positive" and shown["a"]["triage"]["suppressed"] is True
    assert shown["a"]["triage"]["by"] == "pranav" and shown["b"]["triage"] is None
    assert c.get("/vulnerabilities/summary").json() == {"high": 1}
    assert c.get("/vulnerabilities/hidden-count").json() == {"hidden": 1}
    assert db.query(AuditLog).filter_by(action="finding_triaged").count() >= 1


def test_decision_carries_over_to_the_next_scan(env):
    db, t, s1, v, c, _ = env
    a = v("a")
    triage(c, [a.id], "false_positive", note="not real")
    s2 = Scan(target_id=t.id, status="completed"); db.add(s2); db.commit()
    v("a", scan=s2)                      # same finding, found again by a newer scan
    v("c", scan=s2)
    assert names(c) == ["c"]


def test_accepted_risk_comes_back_after_its_review_date(env):
    db, t, s1, v, c, _ = env
    a = v("a")
    assert triage(c, [a.id], "accepted_risk", note="Patched in Q4", expires_in_days=0).status_code == 422
    assert triage(c, [a.id], "accepted_risk", note="Patched in Q4", expires_in_days=400).status_code == 422
    assert triage(c, [a.id], "accepted_risk", note="Patched in Q4", expires_in_days=30).status_code == 200
    assert names(c) == []
    row = db.query(FindingTriage).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(days=1); db.commit()
    assert names(c) == ["a"]                                  # review date passed: visible again


def test_resolved_hides_until_a_later_scan_sees_it_again(env):
    db, t, s1, v, c, _ = env
    old = datetime.now(timezone.utc) - timedelta(days=2)
    a = v("a", created=old)
    assert triage(c, [a.id], "resolved").status_code == 200
    assert names(c) == []
    v("a", created=datetime.now(timezone.utc) + timedelta(minutes=5))   # a later scan reports it again
    assert names(c, scope="all") == ["a"]                                # only the new row shows: it reappeared


def test_in_progress_keeps_it_visible_and_open_clears_the_decision(env):
    db, t, s1, v, c, _ = env
    a = v("a")
    triage(c, [a.id], "in_progress", note="ticket 42")
    assert names(c) == ["a"]
    assert c.get("/vulnerabilities/").json()[0]["triage"]["status"] == "in_progress"
    triage(c, [a.id], "false_positive", note="nope")
    assert names(c) == []
    assert triage(c, [a.id], "open").status_code == 200
    assert names(c) == ["a"] and db.query(FindingTriage).count() == 0


def test_bulk_unknown_status_and_permissions(env):
    db, t, s1, v, c, state = env
    rows = [v(f"x{i}") for i in range(3)]
    assert triage(c, [r.id for r in rows], "false_positive", note="scanner noise").json() == {"updated": 3}
    assert triage(c, [999], "resolved").status_code == 404
    assert triage(c, [rows[0].id], "bogus").status_code == 422
    assert triage(c, [], "resolved").status_code == 422
    state.admin = False
    assert triage(c, [rows[0].id], "open").status_code == 403


def test_rollup_carries_triage_per_cve(env):
    db, t, s1, v, c, _ = env
    row = Vulnerability(target_id=t.id, scan_id=s1.id, template_id="cve-match", name="[version match] Apache httpd 2.4.7: CVE-2017-1234 thing",
                        severity="high", host="acme.test", cve_id="CVE-2017-1234", tags=["version-match"], matched_at="acme.test:80")
    db.add(row); db.commit()
    triage(c, [row.id], "accepted_risk", note="behind VPN")
    assert c.get("/vulnerabilities/rollup").json()["items"] == []
    item = c.get("/vulnerabilities/rollup", params={"triage": "all"}).json()["items"][0]
    assert item["cves"][0]["triage"]["status"] == "accepted_risk"


def test_report_leaves_out_triaged_findings(env):
    db, t, s1, v, c, _ = env
    a, b = v("keepme"), v("hideme")
    triage(c, [b.id], "false_positive", note="not real")
    from backend import reports
    kept, hidden = reports.triage_split(db, db.query(Vulnerability).filter(Vulnerability.scan_id == s1.id).all())
    assert [x.name for x in kept] == ["keepme"] and [x.name for x in hidden] == ["hideme"]
