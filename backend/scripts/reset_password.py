"""
Break-glass recovery for a locked-out account (for example the only admin who forgot the password).

Usage (from the project root, or `docker compose exec backend python -m backend.scripts.reset_password`):
    python3 -m backend.scripts.reset_password <username>             # new password
    python3 -m backend.scripts.reset_password <username> --clear-mfa # also turn off two-step sign-in

Needs shell access to the server, which is the proof of ownership. The password is typed with hidden input. All
sessions and script tokens of that account are ended.
"""
import getpass
import sys
from datetime import datetime, timezone

from backend.audit import log_action
from backend.auth import pwd_context
from backend.db import SessionLocal
from backend.models.user import User
from backend.user_policy import validate_password


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    clear_mfa = "--clear-mfa" in args
    names = [a for a in args if not a.startswith("--")]
    if len(names) != 1:
        print(__doc__)
        return 2
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == names[0]).first()
        if not user:
            print(f"Error: no user named '{names[0]}'.")
            return 1
        password = getpass.getpass("New password: ")
        err = validate_password(password, user.username)
        if err:
            print(f"Error: {err}")
            return 1
        if password != getpass.getpass("Confirm password: "):
            print("Error: passwords do not match.")
            return 1
        user.hashed_password = pwd_context.hash(password)
        user.token_version = (user.token_version or 0) + 1
        user.password_changed_at = datetime.now(timezone.utc)
        user.is_active = True
        if clear_mfa:
            user.mfa_enabled, user.mfa_secret, user.mfa_last_step, user.mfa_recovery = False, None, None, None
        db.commit()
        from backend import api_tokens
        api_tokens.revoke_all(db, user.id)
        log_action(db, "cli", "cli_password_reset", detail={"user": user.username, "mfa_cleared": clear_mfa})
        print(f"Password reset for '{user.username}'." + (" Two-step sign-in turned off." if clear_mfa else ""))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
