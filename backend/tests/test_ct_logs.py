"""Certificate transparency collector: parsing, scoping, freshness, baseline silence."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base
from backend.exposure import registry, runner
from backend.exposure.base import CollectorError, NotApplicable, RateLimited
from backend.exposure.ct_logs import CTLogCollector
from backend.exposure.http import ALLOWED_HOSTS, Response
from backend.models import Target
from backend.models.exposure import ExposureFinding


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


class FakeHttp:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, params=None, headers=None, max_bytes=None):
        self.calls.append((url, params, max_bytes))
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def ts(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def cert(names, days_ago=100, issuer="C=US, O=Let's Encrypt, CN=R11", cid=1):
    return {"id": cid, "issuer_name": issuer, "name_value": "\n".join(names), "not_before": ts(days_ago)}


def body(rows, status=200):
    return Response(status, json.dumps(rows).encode(), {})


def run(rows, domain="acme.com"):
    return CTLogCollector().collect(domain, FakeHttp(body(rows)), lambda s: None)


def test_registered_and_host_allowed():
    assert registry.get("ct_logs") is not None
    assert "crt.sh" in ALLOWED_HOSTS


def test_query_uses_wildcard_expired_filter_and_larger_cap():
    http = FakeHttp(body([]))
    CTLogCollector().collect("Acme.com", http, lambda s: None)
    url, params, cap = http.calls[0]
    assert url == "https://crt.sh/" and params["q"] == "%.acme.com" and params["exclude"] == "expired"
    assert cap and cap > 2 * 1024 * 1024


def test_names_split_deduplicated_and_scoped():
    found = run([
        cert(["www.acme.com", "api.acme.com\nwww.acme.com"], cid=1),
        cert(["acme.com", "*.acme.com", "other.org", "acme.com.evil.net", "evilacme.com"], cid=2),
        cert(["user@acme.com", "bad name.acme.com", "-x.acme.com"], cid=3),
    ])
    assert sorted(f.key for f in found) == ["*.acme.com", "acme.com", "api.acme.com", "www.acme.com"]
    assert found.complete is True


def test_fresh_names_are_low_and_old_ones_info():
    found = {f.key: f for f in run([cert(["new.acme.com"], days_ago=2), cert(["old.acme.com"], days_ago=400)])}
    assert found["new.acme.com"].severity == "low" and found["new.acme.com"].evidence["fresh"] is True
    assert found["old.acme.com"].severity == "info"


def test_newest_certificate_decides_freshness():
    found = {f.key: f for f in run([cert(["a.acme.com"], days_ago=300, cid=1), cert(["a.acme.com"], days_ago=1, cid=2)])}
    assert found["a.acme.com"].severity == "low"


def test_wildcard_is_called_out_and_link_is_safe():
    f = run([cert(["*.acme.com"])])[0]
    assert f.evidence["wildcard"] is True and "Wildcard" in f.summary
    assert f.url.startswith("https://crt.sh/?q=") and "%2A" in f.url


def test_text_from_the_log_is_cleaned():
    f = run([cert(["a.acme.com"], issuer="CN=Evil‮ CA\x00")])[0]
    assert "‮" not in f.summary and "\x00" not in f.summary


def test_too_many_names_marks_run_incomplete(monkeypatch):
    import backend.exposure.ct_logs as ct
    monkeypatch.setattr(ct, "MAX_NAMES", 3)
    found = run([cert([f"h{i}.acme.com" for i in range(5)])])
    assert len(found) == 3 and found.complete is False


@pytest.mark.parametrize("response,exc", [
    (Response(429, b"", {}), RateLimited),
    (Response(502, b"<html>", {}), CollectorError),
    (Response(200, b"<html>not json</html>", {}), CollectorError),
    (Response(200, b'{"error": "x"}', {}), CollectorError),
])
def test_upstream_trouble_is_an_error_not_an_empty_result(response, exc):
    with pytest.raises(exc):
        CTLogCollector().collect("acme.com", FakeHttp(response), lambda s: None)


def test_empty_answers_mean_no_certificates():
    assert list(CTLogCollector().collect("acme.com", FakeHttp(Response(200, b"", {})), lambda s: None)) == []
    assert list(CTLogCollector().collect("acme.com", FakeHttp(Response(404, b"", {})), lambda s: None)) == []
    assert list(run([])) == []


def test_ip_and_internal_targets_are_not_applicable():
    for t in ("203.0.113.5", "203.0.113.0/28", "host.local"):
        with pytest.raises(NotApplicable):
            CTLogCollector().collect(t, FakeHttp(body([])), lambda s: None)


@pytest.fixture()
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


def test_first_run_is_a_silent_baseline_then_new_names_notify(db, monkeypatch):
    t = Target(domain="acme.com", authorized=True, authorized_by="me", is_active=True,
               alert_min_severity="low", exposure_sources=["ct_logs"])
    db.add(t); db.commit()
    sent = []
    monkeypatch.setattr(runner, "notify_exposure", lambda db_, tgt, items, sleep=None: sent.append([f.title for f, _ in items]))
    t0 = datetime.now(timezone.utc)
    out = runner.run_collectors(db, t, http=FakeHttp(body([cert(["www.acme.com"], days_ago=1)])), now=t0)
    assert out["ct_logs"]["status"] == "ok" and out["ct_logs"]["new"] == 1
    assert sent == []                                              # baseline: stored, not announced
    assert db.query(ExposureFinding).count() == 1

    later = t0 + timedelta(hours=7)
    out = runner.run_collectors(db, t, http=FakeHttp(body([cert(["www.acme.com"]), cert(["vpn2.acme.com"], days_ago=0)])), now=later)
    assert out["ct_logs"]["new"] == 1
    assert sent == [["Certificate issued for vpn2.acme.com"]]
