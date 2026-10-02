import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend.scan_profiles import PROFILES, DEFAULT_PROFILE, get_profile, is_valid_profile
from backend.scanner.portscan import build_nmap_cmd
from backend.scanner.vuln import build_nuclei_cmd
from backend.scanner.dirbuster import compute_process_timeout
from backend.pipeline_utils import merge_known_ports, merge_known_technologies
from backend.db import Base, get_db
from backend.main import app
from backend.auth import get_current_user
from backend.models import Target
from backend.models.scan import Scan
import backend.api.scans as scans_api


@compiles(JSONB, "sqlite")
def _jsonb_as_json(type_, compiler, **kw):
    return "JSON"


# ---------- profile definitions ----------

def test_three_profiles_and_default_exists():
    assert set(PROFILES) == {"quick", "standard", "deep"}
    assert DEFAULT_PROFILE in PROFILES


def test_get_profile_is_case_insensitive_and_falls_back():
    assert get_profile("QUICK").name == "quick"
    assert get_profile("nonsense").name == DEFAULT_PROFILE
    assert get_profile(None).name == DEFAULT_PROFILE


def test_is_valid_profile():
    assert is_valid_profile("Deep") and not is_valid_profile("") and not is_valid_profile(None)
    assert not is_valid_profile("turbo")


def test_depth_is_monotonic():
    q, s, d = PROFILES["quick"], PROFILES["standard"], PROFILES["deep"]
    assert not q.run_dirbuster and s.run_dirbuster and d.run_dirbuster
    assert q.nuclei_timeout < s.nuclei_timeout <= d.nuclei_timeout
    assert q.nmap_host_timeout < s.nmap_host_timeout < d.nmap_host_timeout
    assert d.dirbuster_cap > s.dirbuster_cap and d.wordlist == "medium"


def test_quick_keeps_the_signal_stages():
    q = PROFILES["quick"]
    assert q.run_cve_match and q.run_nuclei_network and q.run_nuclei
    assert q.nuclei_severity == "high,critical"


def test_public_view_lists_stages():
    p = PROFILES["quick"].public()
    assert p["name"] == "quick" and p["estimate"] and "CVE match" in p["stages"]
    assert "dirs (small)" not in p["stages"]
    assert any(x.startswith("dirs") for x in PROFILES["deep"].public()["stages"])


# ---------- profile -> scanner arguments ----------

def test_nmap_ports_mapping():
    assert build_nmap_cmd("h", 10, "100")[build_nmap_cmd("h", 10, "100").index("--top-ports") + 1] == "100"
    assert "-p-" in build_nmap_cmd("h", 10, "all")
    assert "--top-ports" not in build_nmap_cmd("h", 10, "all")
    junk = build_nmap_cmd("h", 10, "9999; rm -rf /")        # never reaches the command line
    assert junk[junk.index("--top-ports") + 1] == "1000" and "rm" not in " ".join(junk)


def test_nmap_host_timeout_from_profile():
    cmd = build_nmap_cmd("h", 10, "all", 1800)
    assert cmd[cmd.index("--host-timeout") + 1] == "1800s"


def test_nuclei_severity_override_and_default():
    cmd = build_nuclei_cmd("t", "o", 5, severity="high,critical")
    assert cmd[cmd.index("-severity") + 1] == "high,critical"
    cmd = build_nuclei_cmd("t", "o", 5)
    assert "critical" in cmd[cmd.index("-severity") + 1] and "info" in cmd[cmd.index("-severity") + 1]


def test_dirbuster_cap_bounds_timeout():
    assert compute_process_timeout(100000, 1, True, cap=300) == 300
    assert compute_process_timeout(10, 100, False, cap=300) == 120   # floor still applies


# ---------- like-with-like merging for narrow profiles ----------

def test_narrow_scan_never_closes_known_ports():
    prev = [{"port": 21, "service": "ftp"}, {"port": 8080, "service": "http"}]
    cur = [{"port": 21, "service": "ftp2"}, {"port": 22, "service": "ssh"}]
    merged = merge_known_ports(prev, cur)
    assert [p["port"] for p in merged] == [21, 22, 8080]
    assert merged[0]["service"] == "ftp2"          # fresh observation wins
    assert merge_known_ports(None, cur) == cur


def test_technologies_union():
    assert merge_known_technologies(["Apache"], ["PHP", "Apache"]) == ["Apache", "PHP"]
    assert merge_known_technologies(None, None) == []


# ---------- API ----------

@pytest.fixture()
def client(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    db.add(Target(domain="203.0.113.7", authorized=True, authorized_by="me", is_active=True))
    db.commit()

    sent = {}

    class _Task:
        id = "task-1"

    def fake_delay(**kw):
        sent.update(kw)
        return _Task()

    monkeypatch.setattr(scans_api.run_scan, "delay", fake_delay)
    monkeypatch.setenv("ASM_ALLOW_PRIVATE_TARGETS", "true")
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: type("U", (), {"username": "tester"})()
    c = TestClient(app)
    c.sent, c.db = sent, db
    yield c
    app.dependency_overrides.clear()


def test_profiles_endpoint(client):
    body = client.get("/scans/profiles").json()
    assert body["default"] == DEFAULT_PROFILE
    assert [p["name"] for p in body["profiles"]] == ["quick", "standard", "deep"]


def test_scan_uses_target_default_profile(client):
    client.patch("/targets/1/profile", json={"default_profile": "deep"})
    r = client.post("/scans/", json={"target_id": 1})
    assert r.status_code == 200 and r.json()["profile"] == "deep"
    assert client.sent["profile"] == "deep" and client.sent["enable_dirbuster"] is True
    assert client.db.query(Scan).first().profile == "deep"


def test_request_profile_overrides_default(client):
    r = client.post("/scans/", json={"target_id": 1, "profile": "quick"})
    assert r.json()["profile"] == "quick"
    assert client.sent["enable_dirbuster"] is False      # quick has no directory discovery


def test_dirbuster_veto(client):
    client.post("/scans/", json={"target_id": 1, "profile": "deep", "run_dirbuster": False})
    assert client.sent["enable_dirbuster"] is False


def test_target_toggle_vetoes_dirs(client):
    t = client.db.query(Target).first(); t.dirbuster_enabled = False; client.db.commit()
    client.post("/scans/", json={"target_id": 1, "profile": "standard"})
    assert client.sent["enable_dirbuster"] is False


def test_unknown_profile_rejected(client):
    r = client.post("/scans/", json={"target_id": 1, "profile": "turbo"})
    assert r.status_code == 422 and not client.sent


def test_patch_profile_validates(client):
    assert client.patch("/targets/1/profile", json={"default_profile": "turbo"}).status_code == 422
    r = client.patch("/targets/1/profile", json={"default_profile": "QUICK"})
    assert r.status_code == 200 and r.json()["default_profile"] == "quick"
    assert client.patch("/targets/99/profile", json={"default_profile": "deep"}).status_code == 404


# ---------- migrations ----------

def test_alembic_has_single_linear_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config("backend/alembic.ini")
    script = ScriptDirectory.from_config(cfg)
    assert len(script.get_heads()) == 1
    revs = list(script.walk_revisions())
    assert [r.revision for r in revs][-1] == "0001" and revs[0].revision == script.get_heads()[0]
