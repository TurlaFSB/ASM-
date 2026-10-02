from datetime import datetime, timezone, timedelta

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import reports
from backend.db import Base
from backend.models import Target
from backend.models.alert import Alert
from backend.models.asset import Asset
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.scan_asset import ScanAsset
from backend.models.vulnerability import Vulnerability


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    now = datetime.now(timezone.utc)
    t = Target(domain="10.0.0.5", authorized=True, authorized_by="me")
    s.add(t); s.commit()
    scan = Scan(target_id=t.id, status="completed", profile="quick", started_at=now - timedelta(minutes=3),
                completed_at=now, module_results={"profile": "quick", "portscan": "ok", "whatweb": "skipped (profile: quick)",
                                                  "dirbuster": "partial (1/2 hosts hit time limit)", "vuln": "failed: boom"})
    other = Scan(target_id=t.id, status="completed", profile="standard")
    s.add_all([scan, other]); s.commit()
    a_in = Asset(target_id=t.id, subdomain="10.0.0.5", ip="10.0.0.5", status="active", risk_score=80, risk_level="High",
                 http_title="<script>alert(1)</script>", open_ports=[{"port": 80, "service": "http"}])
    a_old = Asset(target_id=t.id, subdomain="old.example", status="disappeared")
    s.add_all([a_in, a_old]); s.commit()
    s.add(ScanAsset(scan_id=scan.id, asset_id=a_in.id))

    def v(sev, name, host="10.0.0.5:80", cve=None, cvss=None, tags=None, desc="", tid="t"):
        s.add(Vulnerability(target_id=t.id, scan_id=scan.id, template_id=tid, name=name, severity=sev, host=host,
                            cve_id=cve, cvss_score=cvss, tags=tags or [], description=desc))
    v("critical", "vm-crit", cve="CVE-2015-3306", cvss=9.8, tags=["version-match", "unverified", "kev"], desc="x" * 2000)
    v("critical", "real-crit", cve="CVE-2010-2075", cvss=9.8, tags=["irc"])
    v("high", "vm-crit-dup-host", host="10.0.0.5:8080", cve="CVE-2015-3306", cvss=9.8, tags=["version-match"])
    v("medium", "exposed panel", tags=["panel", "exposure"], desc="<img src='file:///etc/passwd'>")
    v("info", "dir listing", tags=["exposure"])
    v("high", "evil-cve", cve="CVE-2020-1234\"><script>", tags=[])
    s.add(DiscoveredPath(asset_id=a_in.id, scan_id=scan.id, path="/backup.zip", status_code=200, content_length=10))
    s.add(DiscoveredPath(asset_id=a_in.id, scan_id=scan.id, path="/images", status_code=200, content_length=10))
    s.add(Alert(target_id=t.id, scan_id=scan.id, alert_type="changed_asset", asset_subdomain="10.0.0.5",
                detail={"old_ports": [22], "new_ports": [21, 22], "old_technologies": [], "new_technologies": ["PHP"]}))
    s.commit()
    s.scan_id = scan.id
    return s


def test_inventory_is_scoped_to_scan_and_sorted(db):
    ctx = reports.build_report_context(db, db.scan_id)
    assert [a.subdomain for a in ctx["assets"]] == ["10.0.0.5"]       # disappeared asset not included


def test_counts_include_info_and_split_verified(db):
    ctx = reports.build_report_context(db, db.scan_id)
    assert ctx["severity_counts"] == {"critical": 2, "high": 2, "medium": 1, "low": 0, "info": 1}
    assert ctx["unverified_counts"]["critical"] == 1 and ctx["confirmed_counts"]["critical"] == 1
    assert ctx["risk_rating"] == "Critical" and ctx["rating_basis"] is None   # one confirmed critical exists


def test_rating_basis_when_only_unverified(db):
    db.query(Vulnerability).filter(Vulnerability.name == "real-crit").delete(); db.commit()
    ctx = reports.build_report_context(db, db.scan_id)
    assert ctx["rating_basis"] and "version" in ctx["rating_basis"]


def test_ordering_kev_first_and_description_truncated(db):
    ctx = reports.build_report_context(db, db.scan_id)
    first = ctx["vulnerabilities"][0]
    assert first["name"] == "vm-crit" and first["kev"] is True       # KEV outranks a confirmed critical of equal CVSS
    assert len(first["description"]) <= reports.MAX_DESC + 2


def test_invalid_cve_id_is_never_linked(db):
    ctx = reports.build_report_context(db, db.scan_id)
    evil = next(v for v in ctx["vulnerabilities"] if v["name"] == "evil-cve")
    assert evil["cve_id"] is None


def test_priorities_dedupe_by_finding_and_aggregate_hosts(db):
    for host in ("10.0.0.5:21", "10.0.0.6:21"):
        db.add(Vulnerability(target_id=1, scan_id=db.scan_id, template_id="t", name="ftp-anon", severity="critical",
                             host=host, cve_id="CVE-2015-3306", tags=["misconfig"]))
    db.commit()
    ctx = reports.build_report_context(db, db.scan_id)
    rows = [p for p in ctx["priorities"] if p["name"] == "ftp-anon"]
    assert len(rows) == 1 and len(rows[0]["hosts"]) == 2
    assert all(p["severity"] != "info" for p in ctx["priorities"])


def test_guidance_for_non_cve_findings(db):
    ctx = reports.build_report_context(db, db.scan_id)
    panel = next(v for v in ctx["vulnerabilities"] if v["name"] == "exposed panel")
    assert "Restrict access" in panel["guidance"]


def test_coverage_and_limitations(db):
    ctx = reports.build_report_context(db, db.scan_id)
    states = {c["label"]: c["state"] for c in ctx["coverage"]}
    assert states["Port & service scan (nmap)"] == "ok"
    assert states["Technology fingerprinting (whatweb)"] == "skip"
    assert states["Directory discovery (feroxbuster)"] == "warn"
    assert states["Web vulnerability scan (nuclei)"] == "fail"
    assert len(ctx["limitations"]) == 2 and ctx["profile"].name == "quick"


def test_sensitive_paths_flagged(db):
    ctx = reports.build_report_context(db, db.scan_id)
    assert [p["path"] for p in ctx["sensitive_paths"]] == ["/backup.zip"]


def test_describe_change_is_readable_not_a_dict():
    lines = reports.describe_change({"old_ports": [22], "new_ports": [21, 22], "old_technologies": ["A"],
                                     "new_technologies": ["B"], "old_http_status": 200, "new_http_status": 500})
    assert "Ports opened: 21" in lines and "Technologies added: B" in lines and "Technologies removed: A" in lines
    assert any("200" in l and "500" in l for l in lines)
    assert reports.describe_change(None) == [] and reports.describe_change({}) == ["Content fingerprint changed."]


def test_html_is_escaped(db):
    ctx = reports.build_report_context(db, db.scan_id)
    env = Environment(loader=FileSystemLoader(str(reports.TEMPLATE_DIR)), autoescape=select_autoescape(["html"], default=True))
    html = env.get_template("report.html").render(**ctx)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src='file:///etc/passwd'>" not in html and "&lt;img" in html


def test_resource_loading_is_denied():
    with pytest.raises(ValueError):
        reports._deny_fetch("file:///etc/passwd")


def test_pdf_generates(db):
    pdf = reports.generate_pdf_report(db, db.scan_id)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 5000


def test_unknown_scan_raises(db):
    with pytest.raises(ValueError):
        reports.build_report_context(db, 9999)


def test_inferred_cves_group_per_component_and_shrink_remediation(db):
    for i, (cve, sev, tags) in enumerate([("CVE-2021-40438", "critical", ["version-match", "kev"]),
                                           ("CVE-2017-3167", "critical", ["version-match"]),
                                           ("CVE-2019-0001", "high", ["version-match"])]):
        db.add(Vulnerability(target_id=1, scan_id=db.scan_id, template_id=f"nvd-{cve}", severity=sev,
                             name=f"[version match] Apache httpd 2.4.7: {cve}", host="10.0.0.5", cve_id=cve,
                             cvss_score=9.0 - i, tags=tags,
                             description="Crafted request does bad things. Matched by service version (cpe:2.3:a:x). Unverified."))
    db.commit()
    ctx = reports.build_report_context(db, db.scan_id)
    groups = [g for g in ctx["inferred_groups"] if g["component"] == "Apache httpd 2.4.7"]
    assert len(groups) == 1 and groups[0]["count"] == 3 and groups[0]["kev_count"] == 1
    assert groups[0]["rows"][0]["cve_id"] == "CVE-2021-40438"              # KEV first
    assert groups[0]["rows"][0]["summary"] == "Crafted request does bad things."
    assert groups[0]["verify_sla"] == "48 hours"
    assert all(v["name"].startswith("[version match]") is False for v in ctx["confirmed_vulns"])
    assert not any(p["name"].startswith("[version match]") for p in ctx["priorities"])


def test_clean_technologies_drops_noise_and_duplicates():
    from backend.tech_utils import clean_technologies
    raw = ["Apache", "Apache HTTP Server:2.4.7", "Cookies", "HTTPServer", "HttpOnly", "Index-Of", "Java",
           "Jetty", "Jetty:8.1.7", "X-Frame-Options", "Ubuntu"]
    assert clean_technologies(raw) == ["Apache:2.4.7", "Java", "Jetty:8.1.7", "Ubuntu"]


def test_top_actions_rank_kev_and_severity(db):
    ctx = reports.build_report_context(db, db.scan_id)
    acts = ctx["top_actions"]
    assert 0 < len(acts) <= 5
    sev = ["critical", "high", "medium", "low", "info"]
    assert [sev.index(a["severity"]) for a in acts] == sorted(sev.index(a["severity"]) for a in acts)
