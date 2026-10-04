"""
Bootstrap script to create the first (or an additional) admin user.

Usage:
    python3 -m backend.scripts.create_admin            # admin (can change things)
    python3 -m backend.scripts.create_admin --viewer   # read-only account

Run from the project root with the venv active. Prompts interactively for
username and password (hidden input via getpass — never appears in shell
history, process list, or logs).
"""

import getpass
import sys

from backend.db import SessionLocal
from backend.models.user import User
from backend.auth import pwd_context

from backend.user_policy import validate_password, validate_username  # noqa: E402


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
        err = validate_password(password, username)
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
            role="viewer" if "--viewer" in sys.argv[1:] else "admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"{'Viewer' if '--viewer' in sys.argv[1:] else 'Admin'} user '{username}' created successfully.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
