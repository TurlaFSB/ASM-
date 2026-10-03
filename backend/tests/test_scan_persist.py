from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base
from backend.models.asset import Asset
from backend.models.discovered_path import DiscoveredPath
from backend.models.scan import Scan
from backend.models.target import Target
from backend.scan_persist import save_discovered_paths, upsert_assets


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


FULL = SimpleNamespace(nmap_ports="1000", run_whatweb=True)
QUICK = SimpleNamespace(nmap_ports="100", run_whatweb=False)
OK = {"dns": "ok", "subfinder": "ok"}


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    t = Target(domain="example.org", is_active=True)
    s.add(t)
    s.commit()
    sc = Scan(target_id=t.id, status="running")
    s.add(sc)
    s.commit()
    s.tid, s.sid = t.id, sc.id
    yield s
    s.close()


def host(name, ip="1.1.1.1"):
    return {"subdomain": name, "ip": ip}


def ports(*nums):
    return [{"port": n, "service": "x"} for n in nums]


def run(db, hosts, port_map, http=None, prof=FULL, results=OK):
    port_data = {"hosts": [{"subdomain": k, "ports": v} for k, v in port_map.items()]}
    http_data = {"hosts": http or []}
    return upsert_assets(db, db.tid, hosts, port_data, http_data, prof, dict(results), False)


def test_first_scan_creates_new_assets(db):
    new, changed, gone, seen = run(db, [host("a.example.org")], {"a.example.org": ports(80, 443)})
    assert (new, changed, gone) == (1, 0, 0)
    a = db.query(Asset).one()
    assert a.status == "new" and a.content_hash and len(seen) == 1


def test_unchanged_asset_goes_active_and_changed_one_is_flagged(db):
    run(db, [host("a.example.org")], {"a.example.org": ports(80)})
    new, changed, gone, _ = run(db, [host("a.example.org")], {"a.example.org": ports(80)})
    assert (new, changed, gone) == (0, 0, 0) and db.query(Asset).one().status == "active"
    new, changed, gone, _ = run(db, [host("a.example.org")], {"a.example.org": ports(80, 8080)})
    assert changed == 1 and db.query(Asset).one().status == "changed"


def test_missing_host_disappears_only_when_discovery_is_trusted(db):
    run(db, [host("a.example.org"), host("b.example.org")], {"a.example.org": ports(80), "b.example.org": ports(80)})
    *_, = run(db, [host("a.example.org")], {"a.example.org": ports(80)}, results={"dns": "failed", "subfinder": "ok"})
    assert db.query(Asset).filter_by(subdomain="b.example.org").one().status != "disappeared"
    _, _, gone, _ = run(db, [host("a.example.org")], {"a.example.org": ports(80)})
    assert gone == 1 and db.query(Asset).filter_by(subdomain="b.example.org").one().status == "disappeared"


def test_nmap_failure_keeps_last_known_ports(db):
    run(db, [host("a.example.org")], {"a.example.org": ports(80, 443)})
    _, changed, _, _ = run(db, [host("a.example.org")], {})          # nmap produced nothing for the host
    assert changed == 0
    assert [p["port"] for p in db.query(Asset).one().open_ports] == [80, 443]


def test_quick_profile_never_removes_what_a_deep_scan_found(db):
    http = [{"host": "a.example.org", "url": "https://a.example.org", "technologies": ["nginx", "php"], "status_code": 200, "title": "T"}]
    run(db, [host("a.example.org")], {"a.example.org": ports(22, 80, 443)}, http=http)
    http_quick = [{"host": "a.example.org", "url": "https://a.example.org", "technologies": [], "status_code": 200, "title": "T"}]
    _, changed, _, _ = run(db, [host("a.example.org")], {"a.example.org": ports(80)}, http=http_quick, prof=QUICK)
    a = db.query(Asset).one()
    assert changed == 0
    assert {p["port"] for p in a.open_ports} == {22, 80, 443} and set(a.technologies) == {"nginx", "php"}


def test_http_info_is_merged_across_ports_into_one_record(db):
    http = [
        {"host": "a.example.org", "url": "https://a.example.org", "technologies": ["nginx"], "status_code": 200, "title": "Home"},
        {"host": "a.example.org", "url": "http://a.example.org:8080", "technologies": ["tomcat"], "status_code": 404, "title": "x"},
    ]
    run(db, [host("a.example.org")], {"a.example.org": ports(443, 8080)}, http=http)
    a = db.query(Asset).one()
    assert set(a.technologies) == {"nginx", "tomcat"} and a.http_status == 200 and a.http_title == "Home"


def test_discovered_paths_attach_to_the_right_asset(db):
    run(db, [host("a.example.org")], {"a.example.org": ports(443)})
    data = {"hosts": {
        "https://a.example.org": {"paths": [{"path": "/admin", "status_code": 403, "content_length": 10}, {"path": "", "status_code": 200}]},
        "https://unknown.example.org": {"paths": [{"path": "/x", "status_code": 200}]},
    }}
    assert save_discovered_paths(db, db.tid, db.sid, data) == 2
    rows = db.query(DiscoveredPath).order_by(DiscoveredPath.id).all()
    assert [r.path for r in rows] == ["/admin", "/"] and all(r.port == 443 for r in rows)


def test_no_dirbuster_results_saves_nothing(db):
    assert save_discovered_paths(db, db.tid, db.sid, {"hosts": {}}) == 0
