"""Two-step sign-in with an authenticator app (TOTP, RFC 6238), implemented on the standard library.

* The shared secret is stored encrypted (Fernet, key derived from SECRET_KEY), never in clear.
* A code is accepted once: the newest accepted 30-second step is remembered, so a code seen over a shoulder or in a
  proxy log cannot be replayed within its validity window.
* Recovery codes are random, shown once, stored only as SHA-256 hashes and burn on use.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from backend.config import settings

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1                       # accept one step either side for clock drift
ISSUER = "ASM Platform"
RECOVERY_COUNT = 10


def _fernet() -> Fernet:
    key = hashlib.sha256(b"asm-mfa-v1|" + settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(stored: Optional[str]) -> Optional[str]:
    if not stored:
        return None
    try:
        return _fernet().decrypt(stored.encode()).decode()
    except InvalidToken:         # SECRET_KEY was rotated: the secret can no longer be read, so the code cannot match
        return None


def _code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(value).zfill(DIGITS)


def verify_code(secret: str, code: str, last_step: Optional[int] = None, now: Optional[float] = None) -> Optional[int]:
    """The accepted step number, or None. A step at or below `last_step` is a replay and is refused."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code_at(secret, step), code):
            return step
    return None


def provisioning_uri(username: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{username}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"


def _hash_recovery(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace("-", "").encode()).hexdigest()


def new_recovery_codes() -> Tuple[List[str], List[str]]:
    """(codes to show once, hashes to store)."""
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_COUNT)]
    return codes, [_hash_recovery(c) for c in codes]


def consume_recovery(stored: Optional[List[str]], code: str) -> Optional[List[str]]:
    """The remaining hashes if `code` was valid (and is now spent), else None."""
    wanted = _hash_recovery(code)
    for h in stored or []:
        if hmac.compare_digest(h, wanted):
            return [x for x in stored if x != h]
    return None


def looks_like_recovery(code: str) -> bool:
    c = (code or "").strip().lower().replace("-", "")
    return len(c) == 12 and all(ch in "0123456789abcdef" for ch in c)
