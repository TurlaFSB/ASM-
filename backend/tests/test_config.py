import pytest
from pydantic import ValidationError
from backend.config import Settings


def _mk(key):
    return Settings(database_url="postgresql+psycopg://u:p@h/db", redis_url="redis://h/0", secret_key=key)


def test_short_secret_rejected():
    with pytest.raises(ValidationError):
        _mk("short")


def test_placeholder_secret_rejected():
    with pytest.raises(ValidationError):
        _mk("CHANGE_ME_GENERATE_WITH_OPENSSL_" + "x" * 10)


def test_good_secret_ok():
    assert _mk("a" * 40).secret_key == "a" * 40
