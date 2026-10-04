import pytest

from backend.tests.test_notifications import db, client  # noqa: F401 (fixtures)
from backend.validators import normalize_tags
from backend.models import Target


def test_normalisation():
    assert normalize_tags([" Prod ", "team a", "PROD", "", "env:eu-1"]) == ["prod", "team-a", "env:eu-1"]
    assert normalize_tags(None) == []


@pytest.mark.parametrize("bad", ["-x", "a/b", "<b>", "x" * 33, "ünï", "a\nb"])
def test_bad_tags_rejected(bad):
    with pytest.raises(ValueError):
        normalize_tags([bad])


def test_tag_cap():
    with pytest.raises(ValueError):
        normalize_tags([f"t{i}" for i in range(11)])


def test_update_and_read_back(client, db):
    tid = db.target.id
    r = client.put(f"/targets/{tid}/tags", json={"tags": ["Prod", "team a", "prod"]})
    assert r.status_code == 200 and r.json()["tags"] == ["prod", "team-a"]
    assert client.get(f"/targets/{tid}").json()["tags"] == ["prod", "team-a"]
    assert client.put(f"/targets/{tid}/tags", json={"tags": ["bad/tag"]}).status_code == 422
    assert client.put(f"/targets/{tid}/tags", json={"tags": []}).json()["tags"] == []
    assert db.query(Target).get(tid).tags is None


def test_untagged_target_serialises_as_empty_list(client, db):
    assert client.get(f"/targets/{db.target.id}").json()["tags"] == []


def test_filter_by_tag(client, db):
    other = Target(domain="10.0.0.6", authorized=True, authorized_by="me", tags=["staging"])
    db.add(other); db.commit()
    client.put(f"/targets/{db.target.id}/tags", json={"tags": ["prod", "staging"]})
    names = lambda r: sorted(t["domain"] for t in r.json())
    assert names(client.get("/targets/?tag=staging")) == ["10.0.0.5", "10.0.0.6"]
    assert names(client.get("/targets/?tag=PROD")) == ["10.0.0.5"]
    assert client.get("/targets/?tag=none").json() == []
    assert len(client.get("/targets/").json()) == 2


def test_create_with_tags(client, db, monkeypatch):
    r = client.post("/targets/", json={"domain": "example.org", "authorized": True, "authorized_by": "me",
                                       "tags": ["Web", "web", "eu"]})
    assert r.status_code == 200, r.text
    assert r.json()["tags"] == ["web", "eu"]
    assert client.post("/targets/", json={"domain": "example.net", "authorized": True, "authorized_by": "me",
                                          "tags": ["no good"]}).json()["tags"] == ["no-good"]
