from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.diffing.service import record_scan_changes, rebuild_scan_changes
from backend.main import app
from backend.models import Target
from backend.models.asset import Asset
from backend.models.change_event import ChangeEvent
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.scan_asset import ScanAsset
from backend.models.scan_snapshot import ScanSnapshot
from backend.models.vulnerability import Vulnerability

MR = {"dns": "resolved directly (internal target)", "subfinder": "skipped (internal/IP target)",
      "portscan": "ok", "httpprobe": "ok", "whatweb": "ok", "dirbuster": "ok", "vuln": "ok",
      "nuclei_network": "ok", "cve_match": "ok", "sslyze": "no hosts provided"}


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me")
    s.add(t); s.commit()
    s.target = t
    return s


def run_scan(db, ports, paths=(), findings=(), mr=None, profile="standard"):
    """Simulate what the pipeline persists for one finished scan, then record its changes."""
    t = db.target
    scan = Scan(target_id=t.id, status="completed", profile=profile, module_results=dict(mr or MR),
                completed_at=datetime.now(timezone.utc))
    db.add(scan); db.commit()
    a = db.query(Asset).filter(Asset.target_id == t.id, Asset.subdomain == "10.0.0.5").first()
    if not a:
        a = Asset(target_id=t.id, subdomain="10.0.0.5", ip="10.0.0.5"); db.add(a); db.commit()
    a.open_ports = [{"port": p, "protocol": "tcp", "service": "http"} for p in ports]
    a.technologies = ["Apache:2.4.7"]; a.http_status = 200; a.http_title = "x"
    db.add(ScanAsset(scan_id=scan.id, asset_id=a.id))
    for p, st in paths:
        db.add(DiscoveredPath(asset_id=a.id, scan_id=scan.id, path=p, status_code=st))
    for tid, sev in findings:
        db.add(Vulnerability(target_id=t.id, scan_id=scan.id, template_id=tid, name=tid, severity=sev,
                             host="10.0.0.5:445", tags=["network"]))
    db.commit()
    return scan, record_scan_changes(db, scan)


def test_first_scan_records_baseline_only(db):
    scan, summ = run_scan(db, [80])
    assert summ["baseline"] is True and db.query(ChangeEvent).count() == 0
    assert db.query(ScanSnapshot).filter_by(scan_id=scan.id).count() == 1


def test_second_scan_records_events_against_previous(db):
    s1, _ = run_scan(db, [80])
    s2, summ = run_scan(db, [80, 3306], paths=[("/admin", 200)], findings=[("smb-x", "critical")])
    ev = db.query(ChangeEvent).filter_by(scan_id=s2.id, status="confirmed").all()
    assert {(e.category, e.subject) for e in ev} == {("port", "3306/tcp"), ("path", "/admin"),
                                                     ("finding", "smb-x|10.0.0.5:445")}
    assert all(e.baseline_scan_id == s1.id for e in ev)
    assert summ["events"] == 3 and summ["by_severity"]["critical"] == 1


def test_recording_is_idempotent(db):
    scan, _ = run_scan(db, [80])
    again = record_scan_changes(db, scan)
    assert again.get("skipped_existing") and db.query(ScanSnapshot).count() == 1


def test_flap_end_to_end_pending_then_dismissed(db):
    run_scan(db, [80, 8181])
    _, s2 = run_scan(db, [80])                      # 8181 missing once
    assert s2["events"] == 0 and s2["pending"] == 1
    assert db.query(ChangeEvent).filter_by(status="pending").count() == 1
    _, s3 = run_scan(db, [80, 8181])                # back again
    assert s3["events"] == 0
    assert db.query(ChangeEvent).filter_by(status="pending").count() == 0
    assert db.query(ChangeEvent).filter_by(status="dismissed").count() == 1


def test_removal_confirmed_on_second_missing_scan(db):
    run_scan(db, [80, 8181]); run_scan(db, [80])
    s3, summ = run_scan(db, [80])
    assert summ["events"] == 1
    confirmed = db.query(ChangeEvent).filter_by(status="confirmed").all()
    assert [(e.change_type, e.subject, e.scan_id) for e in confirmed] == [("removed", "8181/tcp", s3.id)]
    assert db.query(ChangeEvent).filter_by(status="superseded").count() == 1
    assert db.query(ChangeEvent).filter_by(status="pending").count() == 0


def test_different_profiles_never_diffed_against_each_other(db):
    run_scan(db, [80, 8181, 21], profile="standard")
    _, summ = run_scan(db, [80], profile="quick",
                       mr=dict(MR, whatweb="skipped (profile: quick)", dirbuster="skipped (profile: quick)"))
    assert summ["baseline"] is True                  # first quick scan: nothing comparable yet


def test_failed_stage_does_not_create_events(db):
    run_scan(db, [80, 8181], findings=[("smb-x", "high")])
    _, summ = run_scan(db, [], mr=dict(MR, portscan="failed: timeout", nuclei_network="failed: x"))
    assert summ["events"] == 0 and summ["pending"] == 0


@pytest.fixture()
def api(db):
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_changes_api_filters_and_scan_view(db, api):
    run_scan(db, [80])
    s2, _ = run_scan(db, [80, 3306], findings=[("smb-x", "critical")])
    r = api.get("/changes/", params={"target_id": db.target.id, "severity": "critical,high"})
    assert r.status_code == 200 and {e["category"] for e in r.json()} == {"port", "finding"}
    assert api.get("/changes/", params={"severity": "bogus"}).status_code == 422
    v = api.get(f"/changes/scans/{s2.id}").json()
    assert v["scan_id"] == s2.id and v["counts"]["critical"] == 1 and v["counts"]["high"] == 1
    assert [e["severity"] for e in v["events"]] == sorted((e["severity"] for e in v["events"]),
                                                          key=["critical", "high", "medium", "low", "info"].index)
    assert api.get("/changes/scans/9999").status_code == 404


def test_report_uses_diff_events_and_legacy_fallback_for_old_scans(db):
    from backend import reports
    s1, _ = run_scan(db, [80])
    s2, summ = run_scan(db, [80, 3306], findings=[("smb-x", "critical")])
    s2.module_results = dict(s2.module_results, diff_detail=summ); db.commit()
    ctx = reports.build_report_context(db, s2.id)
    ch = ctx["changes"]
    assert ch and not ch["is_baseline"] and ch["baseline_scan_id"] == s1.id and ch["total"] == 2
    assert {e["category"] for e in ch["events"]} == {"port", "finding"}
    assert reports.build_report_context(db, s1.id)["changes"]["is_baseline"] is True
    assert reports.generate_pdf_report(db, s2.id).startswith(b"%PDF")
    legacy = Scan(target_id=db.target.id, status="completed", profile="standard", module_results=dict(MR))
    db.add(legacy); db.commit()
    assert reports.build_report_context(db, legacy.id)["changes"] is None      # pre-engine scan: legacy view
    assert reports.generate_pdf_report(db, legacy.id).startswith(b"%PDF")


def _run_like_pipeline(db, ports, mr=None):
    """The live pipeline calls record_scan_changes BEFORE scan.module_results is saved."""
    t = db.target
    scan = Scan(target_id=t.id, status="running", profile="standard", module_results=None)
    db.add(scan); db.commit()
    a = db.query(Asset).filter(Asset.target_id == t.id).first()
    if not a:
        a = Asset(target_id=t.id, subdomain="10.0.0.5", ip="10.0.0.5"); db.add(a); db.commit()
    a.open_ports = [{"port": p, "protocol": "tcp", "service": "http"} for p in ports]
    a.technologies = ["Apache:2.4.7"]; a.http_status = 200; a.http_title = "x"
    db.add(ScanAsset(scan_id=scan.id, asset_id=a.id)); db.commit()
    live = dict(mr or MR)
    summ = record_scan_changes(db, scan, live)
    scan.module_results = live; scan.status = "completed"; db.commit()      # what the pipeline does afterwards
    return scan, summ


def test_live_pipeline_ordering_still_detects_changes(db):
    _run_like_pipeline(db, [80])
    _, summ = _run_like_pipeline(db, [80, 8000])
    assert summ["events"] == 1
    assert db.query(ChangeEvent).filter_by(subject="8000/tcp", change_type="added").count() == 1


def test_baseline_written_without_module_results_is_healed(db):
    s1, _ = run_scan(db, [80])
    snap = db.query(ScanSnapshot).filter_by(scan_id=s1.id).one()
    snap.data = dict(snap.data, coverage={k: None for k in snap.data["coverage"]})      # the old buggy snapshot
    db.commit()
    _, summ = run_scan(db, [80, 8000])
    assert summ["events"] == 1


def test_rebuild_recomputes_newest_scan_and_refuses_older(db):
    s1, _ = run_scan(db, [80])
    s2, _ = run_scan(db, [80, 8000])
    from backend.diffing.service import rebuild_scan_changes
    db.query(ChangeEvent).delete(); db.commit()                                         # simulate lost events
    db.query(ScanSnapshot).filter_by(scan_id=s2.id).delete(); db.commit()
    again = rebuild_scan_changes(db, s2)
    assert again["events"] == 1 and db.query(ChangeEvent).filter_by(status="confirmed").count() == 1
    with pytest.raises(ValueError):
        rebuild_scan_changes(db, s1)


def test_reappearing_finding_is_labelled_not_hidden(db):
    run_scan(db, [80], findings=[("ssh-weak", "low")])
    run_scan(db, [80])                               # missing once: pending
    gone, _ = run_scan(db, [80])                     # missing twice: removal confirmed
    back, summ = run_scan(db, [80], findings=[("ssh-weak", "low")])
    assert summ["events"] == 1                       # still reported
    ev = db.query(ChangeEvent).filter_by(scan_id=back.id, change_type="added").one()
    assert f"scan {gone.id}" in ev.summary and ev.after["reappeared_after_scan"] == gone.id
    assert ev.severity == "low"                      # severity untouched


def test_genuinely_new_finding_has_no_reappeared_label(db):
    run_scan(db, [80])
    s, _ = run_scan(db, [80], findings=[("smb-x", "high")])
    ev = db.query(ChangeEvent).filter_by(scan_id=s.id, change_type="added").one()
    assert "reappeared" not in ev.summary


def test_rebuild_reproduces_a_scan_that_dismissed_a_flap(db):
    run_scan(db, [80, 8181])
    run_scan(db, [80])                                   # 8181 missing once: pending
    s3, live = run_scan(db, [80, 8181])                  # back: pending dismissed, nothing reported
    assert live["events"] == 0 and live["dismissed"] == 1
    again = rebuild_scan_changes(db, s3)
    assert again["events"] == 0 and again["dismissed"] == 1          # same as the live run, no phantom 'added'
    assert db.query(ChangeEvent).filter_by(status="dismissed").count() == 1
    assert db.query(ChangeEvent).filter_by(status="pending").count() == 0


def test_rebuild_reproduces_a_scan_that_confirmed_a_removal(db):
    run_scan(db, [80, 8181]); run_scan(db, [80])
    s3, live = run_scan(db, [80])
    assert live["events"] == 1
    again = rebuild_scan_changes(db, s3)
    assert again["events"] == 1 and again["pending"] == 0
    assert db.query(ChangeEvent).filter_by(status="superseded").count() == 1
