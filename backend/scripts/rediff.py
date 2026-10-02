"""Recompute the change events for one scan from its stored data.

    docker compose exec backend python -m backend.scripts.rediff <scan_id>

Only for the newest scan of its profile (see rebuild_scan_changes).
"""
import sys

from backend.db import SessionLocal
from backend.diffing.service import rebuild_scan_changes
from backend.models.scan import Scan


def main(argv) -> int:
    if len(argv) != 2 or not argv[1].isdigit():
        print(__doc__)
        return 2
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == int(argv[1])).first()
        if not scan:
            print(f"scan {argv[1]} not found")
            return 1
        summary = rebuild_scan_changes(db, scan)
        print(f"scan {scan.id}: {summary['events']} changes, {summary['pending']} pending, "
              f"baseline scan {summary.get('baseline_scan_id')}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
