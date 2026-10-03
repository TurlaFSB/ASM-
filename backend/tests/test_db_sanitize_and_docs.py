from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from backend.db import Base
from backend.db_sanitize import clean
from backend.models import Target


@compiles(JSONB, "sqlite")
def _j(type_, compiler, **kw):
    return "JSON"


def test_clean_nested():
    assert clean({"a\x00": ["x\x00y", {"k": "v\x00"}], "n": 1}) == {"a": ["xy", {"k": "v"}], "n": 1}


def test_nul_stripped_on_insert_and_update():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Target(domain="exa\x00mple.com", authorized=True, authorized_by="a\x00b", is_active=True)
    db.add(t); db.commit()
    assert t.domain == "example.com" and t.authorized_by == "ab"
    t.authorized_by = "c\x00d"; db.commit()
    assert t.authorized_by == "cd"


def test_docs_disabled_in_production(monkeypatch):
    import importlib
    import backend.main as m
    monkeypatch.setattr(m.settings, "app_env", "production")
    app = importlib.reload(m).app
    assert app.docs_url is None and app.openapi_url is None
    monkeypatch.setattr(m.settings, "app_env", "development")
    assert importlib.reload(m).app.docs_url == "/docs"
