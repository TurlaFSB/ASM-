"""Large result sets: every list endpoint pages, reports the total, and stays fast at thousands of rows."""
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import get_current_user
from backend.db import Base, get_db
from backend.main import app
from backend.models import Target
from backend.models.asset import Asset
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.tests.test_vuln_api import _jsonb_as_json  # noqa: F401  (registers the sqlite JSONB shim)

N = 6000
SEV = ["critical", "high", "medium", "low", "info"]


@pytest.fixture()
def big():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="big.example", authorized=True, authorized_by="me")
    db.add(t); db.commit()
    s = Scan(target_id=t.id, status="completed"); db.add(s); db.commit()
    db.bulk_save_objects([
        Vulnerability(target_id=t.id, scan_id=s.id, template_id=f"t{i}", name=f"finding-{i}", severity=SEV[i % 5],
                      host=f"h{i % 300}.big.example", tags=[], matched_at=f"h{i % 300}.big.example:443")
        for i in range(N)])
    db.bulk_save_objects([Asset(target_id=t.id, subdomain=f"h{i}.big.example") for i in range(N)])
    db.commit()
    app.dependency_overrides[get_db] = lambda: (yield db)
    app.dependency_overrides[get_current_user] = lambda: object()
    yield TestClient(app), t.id, s.id
    app.dependency_overrides.clear()


def _pages(client, url, size):
    seen, offset, total = [], 0, None
    while True:
        r = client.get(url, params={"limit": size, "offset": offset})
        assert r.status_code == 200
        total = int(r.headers["X-Total-Count"])
        rows = r.json()
        if not rows:
            return seen, total
        seen += rows
        offset += size


@pytest.mark.parametrize("path", ["/vulnerabilities/target/{t}", "/vulnerabilities/scan/{s}"])
def test_vulnerability_lists_page_without_gaps_or_repeats(big, path):
    client, t, s = big
    rows, total = _pages(client, path.format(t=t, s=s), 2500)
    assert total == N and len(rows) == N and len({r["id"] for r in rows}) == N


def test_scan_assets_page(big):
    client, t, s = big
    rows, total = _pages(client, f"/scans/{s}/assets", 2000)
    assert total == N and len({r["id"] for r in rows}) == N


def test_main_list_is_capped_and_ordered_by_severity(big):
    client, _, _ = big
    r = client.get("/vulnerabilities/", params={"limit": 1000})
    rows = r.json()
    assert len(rows) == 1000 and rows[0]["severity"] == "critical"
    assert client.get("/vulnerabilities/", params={"limit": 5000}).status_code == 422   # above the documented cap


def test_summary_and_rollup_stay_fast_on_thousands_of_rows(big):
    client, _, _ = big
    for url in ("/vulnerabilities/summary", "/vulnerabilities/rollup", "/vulnerabilities/?limit=1000"):
        start = time.perf_counter()
        assert client.get(url).status_code == 200
        assert time.perf_counter() - start < 5, url
    assert sum(client.get("/vulnerabilities/summary").json().values()) == N
