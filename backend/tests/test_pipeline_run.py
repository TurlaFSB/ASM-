"""End-to-end test of tasks.run_scan with every external tool replaced by a stub.

Real database schema (sqlite), real persistence, diffing, sealing and risk scoring: only the network-facing
scanners, Redis and Celery plumbing are faked.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import cancellation as cx
from backend import tasks
from backend.db import Base
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.vulnerability import Vulnerability


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


class FakeLock:
    held = set()

    def __init__(self, key): self.key = key
    def acquire(self, blocking=False):
        if self.key in FakeLock.held:
            return False
        FakeLock.held.add(self.key)
        return True
    def release(self): FakeLock.held.discard(self.key)
    def extend(self, *a, **k): pass


class FakeRedis:
    store = {}

    @classmethod
    def from_url(cls, *a, **k): return cls()
    def get(self, k): return self.store.get(k)
    def setex(self, k, ttl, v): self.store[k] = v
    def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None)
            FakeLock.held.discard(k)
    def lock(self, key, timeout=None, thread_local=True): return FakeLock(key)


@pytest.fixture()
def env(monkeypatch):
    FakeRedis.store.clear()
    FakeLock.held.clear()
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng)
    import backend.db as dbmod
    monkeypatch.setattr(dbmod, "SessionLocal", Session)
    monkeypatch.setattr(tasks.redis, "Redis", FakeRedis)
    monkeypatch.setattr(tasks.run_scan, "update_state", lambda **k: None)
    queued = []
    monkeypatch.setattr(tasks.prebuild_report, "delay", lambda sid: queued.append(sid))
    monkeypatch.setattr(cx, "kill_descendants", lambda *a, **k: [])

    import backend.kev as kev
    monkeypatch.setattr(kev, "_fetch_kev_catalog", lambda: {"CVE-2021-41773"})

    calls = {}

    def stub(modpath, name, result):
        import importlib
        mod = importlib.import_module(modpath)
        def fn(*a, **k):
            calls[name] = (a, k)
            return result(*a, **k) if callable(result) else result
        monkeypatch.setattr(mod, name, fn)

    stub("backend.scanner.subdomain", "enumerate_subdomains", {
        "subdomains": ["example.org", "www.example.org"], "module_status": {"subfinder": "ok", "amass": "ok"}})
    stub("backend.scanner.dns", "resolve_subdomains", {
        "live": [{"subdomain": "example.org", "ip": "93.184.216.34"},
                 {"subdomain": "www.example.org", "ip": "93.184.216.34"}], "module_status": "ok"})
    stub("backend.scanner.whois_lookup", "run_whois_asn", {"domain_whois": {"registrar": "X"}, "asn": None})
    stub("backend.scanner.portscan", "scan_multiple_hosts", lambda hosts, *a, **k: {
        "hosts": [{"subdomain": h["subdomain"], "ip": h["ip"], "ports": [
            {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18"}]}
            for h in hosts], "module_status": "ok"})
    stub("backend.scanner.httpprobe", "run_httpx", {
        "hosts": [{"url": "https://example.org", "host": "example.org", "input": "example.org:443",
                   "status_code": 200, "title": "Hi", "technologies": ["nginx"]},
                  {"url": "https://evil.net", "host": "evil.net", "input": "example.org:443",
                   "status_code": 200, "title": "x", "technologies": []}],
        "module_status": "ok"})
    stub("backend.scanner.whatweb", "run_whatweb", {
        "hosts": {"https://example.org": {"technologies": ["HSTS"]}}, "module_status": "ok"})
    stub("backend.scanner.dirbuster", "run_dirbuster", {"hosts": {}, "module_status": "ok"})
    stub("backend.scanner.vuln", "run_nuclei", {
        "findings": [{"template_id": "CVE-2021-41773", "name": "Apache traversal", "severity": "critical",
                      "matched_at": "https://example.org/x", "host": "example.org", "tags": ["cve"]}],
        "module_status": "ok", "template_count": 10})
    stub("backend.scanner.sslyze_scan", "run_sslyze", {
        "findings": [{"template_id": "tls-old", "name": "TLS 1.0", "severity": "medium",
                      "host": "example.org", "vuln_type": "tls"}], "module_status": "ok"})
    stub("backend.scanner.screenshot", "run_eyewitness", {"screenshots": [], "module_status": "ok"})
    stub("backend.scanner.cve_match", "run_cve_match", {"findings": [], "module_status": "ok"})
    stub("backend.scanner.takeover", "run_takeover_check", {
        "findings": [{"template_id": "takeover-github-pages", "name": "Subdomain takeover candidate (GitHub Pages)",
                      "severity": "high", "host": "old.example.org", "vuln_type": "subdomain-takeover",
                      "tags": ["takeover", "posture", "dns"]}], "module_status": "ok"})
    stub("backend.scanner.emailsec", "run_email_security", {"findings": [], "module_status": "ok"})
    stub("backend.scanner.cloudbucket", "run_cloud_bucket_check", {"findings": [], "module_status": "ok"})
    stub("backend.scanner.sensitive_files", "run_sensitive_file_check", {"findings": [], "module_status": "ok"})

    s = Session()
    t = Target(domain="example.org", is_active=True, authorized=True)
    s.add(t)
    s.commit()
    env_obj = type("Env", (), {})()
    env_obj.Session, env_obj.target_id, env_obj.calls, env_obj.queued = Session, t.id, calls, queued
    env_obj.stub = stub

    def new_scan(status="pending"):
        d = Session()
        sc = Scan(target_id=t.id, status=status)
        d.add(sc)
        d.commit()
        sid = sc.id
        d.close()
        return sid
    env_obj.new_scan = new_scan
    s.close()
    return env_obj


def run(env, scan_id, domain="example.org", **kw):
    return tasks.run_scan(env.target_id, domain, 10, scan_id, None, False, kw.get("profile", "standard"))


def test_full_pipeline_completes_and_persists(env):
    sid = env.new_scan()
    res = run(env, sid)
    assert res["status"] == "completed" and res["total_assets"] == 2 and res["new_assets"] == 2
    db = env.Session()
    scan = db.get(Scan, sid)
    assert scan.status == "completed" and scan.completed_at
    mr = scan.module_results
    assert mr["profile"] == "standard" and mr["portscan"] == "ok"
    assert mr["scope_filter"].startswith("dropped 1")          # evil.net redirect was out of scope
    assert mr["integrity"].startswith("sealed") and mr["diff"].startswith("baseline")
    assert {a.subdomain for a in db.query(Asset).all()} == {"example.org", "www.example.org"}
    vulns = db.query(Vulnerability).all()
    assert {v.template_id for v in vulns} == {"CVE-2021-41773", "tls-old", "takeover-github-pages"}
    assert mr["takeover"] == "ok" and mr["email_security"] == "ok" and mr["sensitive_files"] == "ok"
    nuclei = next(v for v in vulns if v.template_id == "CVE-2021-41773")
    assert nuclei.cve_id == "CVE-2021-41773" and nuclei.finding_key
    assert env.queued == [sid]
    assert nuclei.id and db.query(Asset).first().risk_score is not None
    assert db.get(Asset, db.query(Asset).first().id).technologies   # whatweb + httpx merged
    db.close()
    assert not FakeLock.held and not FakeRedis.store.get(cx.owner_key(env.target_id))


def test_second_scan_is_not_baseline_and_reports_no_changes(env):
    run(env, env.new_scan())
    sid2 = env.new_scan()
    run(env, sid2)
    db = env.Session()
    mr = db.get(Scan, sid2).module_results
    assert mr["diff"].startswith("ok")
    assert db.query(Asset).count() == 2
    db.close()


def test_ip_target_skips_discovery(env):
    sid = env.new_scan()
    res = run(env, sid, domain="203.0.113.7")
    mr = res["module_results"]
    assert mr["subfinder"].startswith("skipped") and mr["dns"].startswith("resolved directly")
    assert "enumerate_subdomains" not in env.calls and "resolve_subdomains" not in env.calls
    assert res["total_assets"] == 1
    # DNS-name based posture checks make no sense for an IP; the file check still runs against its web ports
    assert "run_takeover_check" not in env.calls and "run_email_security" not in env.calls
    assert "run_cloud_bucket_check" not in env.calls
    assert mr["takeover"].startswith("skipped") and mr["email_security"].startswith("skipped")


def test_cancelled_before_start_never_runs(env):
    sid = env.new_scan(status="cancelled")
    assert run(env, sid)["status"] == "cancelled"
    assert "enumerate_subdomains" not in env.calls
    sid2 = env.new_scan()
    FakeRedis.store[cx.flag_key(sid2)] = "1"
    assert run(env, sid2)["status"] == "cancelled"
    db = env.Session()
    assert db.get(Scan, sid2).status == "cancelled"
    db.close()


def test_duplicate_delivery_of_completed_scan_is_ignored(env):
    sid = env.new_scan(status="completed")
    res = run(env, sid)
    assert res == {"scan_id": sid, "status": "completed", "duplicate": True}
    assert "enumerate_subdomains" not in env.calls


def test_stage_failure_marks_scan_failed_and_releases_lock(env):
    def boom(*a, **k): raise RuntimeError("nmap exploded")
    env.stub("backend.scanner.portscan", "scan_multiple_hosts", boom)
    sid = env.new_scan()
    with pytest.raises(RuntimeError):
        run(env, sid)
    db = env.Session()
    sc = db.get(Scan, sid)
    assert sc.status == "failed" and "nmap exploded" in sc.error_log
    db.close()
    assert not FakeLock.held


def test_stale_lock_is_cleared_and_scan_proceeds(env):
    FakeLock.held.add(cx.lock_key(env.target_id))               # crashed worker left the lock behind
    FakeRedis.store[cx.owner_key(env.target_id)] = "9999"       # owner scan does not exist
    sid = env.new_scan()
    assert run(env, sid)["status"] == "completed"


def test_live_lock_makes_scan_retry(env):
    other = env.new_scan(status="running")
    FakeLock.held.add(cx.lock_key(env.target_id))
    FakeRedis.store[cx.owner_key(env.target_id)] = str(other)
    from celery.exceptions import Retry
    with pytest.raises(Retry):          # the DB allows one active scan per target, so this is a queued duplicate
        run(env, None)
