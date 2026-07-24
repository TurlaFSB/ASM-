"""
Bootstrap script to create the first (or an additional) admin user.

Usage:
    python3 -m backend.scripts.create_admin

Run from the project root with the venv active. Prompts interactively for
username and password (hidden input via getpass — never appears in shell
history, process list, or logs).
"""

import getpass
import re
import sys

from backend.db import SessionLocal
from backend.models.user import User
from backend.auth import pwd_context

MIN_PASSWORD_LENGTH = 5


def validate_username(username: str) -> str | None:
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Username may only contain letters, numbers, underscores, dots, and hyphens."
    return None


def validate_password(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    # bcrypt silently truncates input beyond 72 bytes — warn rather than fail,
    # since truncation still produces a usable (if slightly weaker) hash.
    if len(password.encode("utf-8")) > 72:
        print("Warning: password exceeds bcrypt's 72-byte limit and will be truncated.")
    return None


def main() -> int:
    db = SessionLocal()
    try:
        username = input("Admin username: ").strip()
        err = validate_username(username)
        if err:
            print(f"Error: {err}")
            return 1

        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"Error: a user with username '{username}' already exists.")
            return 1

        password = getpass.getpass("Admin password: ")
        err = validate_password(password)
        if err:
            print(f"Error: {err}")
            return 1

        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: passwords do not match.")
            return 1

        hashed = pwd_context.hash(password)
        user = User(
            username=username,
            hashed_password=hashed,
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Admin user '{username}' created successfully.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
