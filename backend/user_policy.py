"""Rules for usernames and passwords, shared by the setup screen, user management, password change and the CLI."""
import re
from typing import Optional

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 72          # bcrypt ignores everything after 72 bytes, so longer passwords are refused, not truncated
ROLES = ("admin", "viewer")


def validate_username(username: str) -> Optional[str]:
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 64:
        return "Username must be at most 64 characters."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Username may only contain letters, numbers, underscores, dots and hyphens."
    return None


def validate_password(password: str, username: str = "") -> Optional[str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    if username and password.lower() == username.lower():
        return "Password must not be the same as the username."
    if len(set(password)) < 4:
        return "Password is too repetitive."
    return None
