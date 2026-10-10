"""Break-glass password reset: new password works, old one and every session stop working, MFA clears only on request."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth import pwd_context, verify_password
from backend.db import Base
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.scripts import reset_password as rp
from backend.tests.test_auth_api import _j  # noqa: F401  (sqlite JSONB shim)


@pytest.fixture()
def db(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    s = S()
    s.add(User(username="root1", hashed_password=pwd_context.hash("old password 123"), role="admin", is_active=False,
               token_version=3, mfa_enabled=True, mfa_secret="x", mfa_recovery=["h"]))
    s.commit()
    monkeypatch.setattr(rp, "SessionLocal", lambda: S())
    return s


def feed(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr(rp.getpass, "getpass", lambda prompt="": next(it))


def user(db):
    db.expire_all()
    return db.query(User).filter_by(username="root1").one()


def test_resets_password_ends_sessions_and_keeps_mfa_by_default(db, monkeypatch, capsys):
    feed(monkeypatch, "brand new password 9", "brand new password 9")
    assert rp.main(["root1"]) == 0
    u = user(db)
    assert verify_password("brand new password 9", u.hashed_password) and u.token_version == 4
    assert u.is_active and u.mfa_enabled                      # reactivated, MFA untouched
    assert db.query(AuditLog).filter_by(action="cli_password_reset").count() == 1


def test_clear_mfa_flag_turns_it_off(db, monkeypatch):
    feed(monkeypatch, "brand new password 9", "brand new password 9")
    assert rp.main(["root1", "--clear-mfa"]) == 0
    u = user(db)
    assert not u.mfa_enabled and u.mfa_secret is None and u.mfa_recovery is None


@pytest.mark.parametrize("answers,argv", [(("short", "short"), ["root1"]), (("brand new password 9", "different one 99"), ["root1"])])
def test_bad_or_mismatched_password_changes_nothing(db, monkeypatch, answers, argv):
    feed(monkeypatch, *answers)
    assert rp.main(argv) == 1
    assert verify_password("old password 123", user(db).hashed_password)


def test_unknown_user_and_bad_usage(db, monkeypatch):
    assert rp.main(["ghost"]) == 1
    assert rp.main([]) == 2
