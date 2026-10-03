import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException

from backend import auth
from backend.config import settings


class _DB:
    def __init__(self, user): self.user = user
    def query(self, *a): return self
    def filter(self, *a): return self
    def first(self): return self.user


def _token(payload, key=None, alg="HS256"):
    return jwt.encode(payload, key or settings.secret_key, algorithm=alg)


def test_valid_token_roundtrip():
    t = auth.create_access_token({"sub": "pranav"})
    u = auth.get_current_user(t, _DB(SimpleNamespace(username="pranav")))
    assert u.username == "pranav"
    assert jwt.decode(t, settings.secret_key, algorithms=["HS256"])["sub"] == "pranav"


@pytest.mark.parametrize("make", [
    lambda: _token({"sub": "x", "exp": int(time.time()) - 5}),                 # expired
    lambda: _token({"sub": "x", "exp": int(time.time()) + 600}, key="y" * 40),  # signed with another key
    lambda: jwt.encode({"sub": "x"}, key=None, algorithm="none"),              # alg=none
    lambda: _token({"exp": int(time.time()) + 600}),                           # no subject
    lambda: "not.a.token",
])
def test_bad_tokens_rejected(make):
    with pytest.raises(HTTPException) as e:
        auth.get_current_user(make(), _DB(SimpleNamespace(username="x")))
    assert e.value.status_code == 401


def test_unknown_or_inactive_user_rejected():
    with pytest.raises(HTTPException):
        auth.get_current_user(auth.create_access_token({"sub": "ghost"}), _DB(None))
