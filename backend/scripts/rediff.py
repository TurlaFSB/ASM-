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
        from backend.models.change_event import ChangeEvent
        rows = (db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id)
                .order_by(ChangeEvent.severity, ChangeEvent.category, ChangeEvent.id).all())
        for r in rows:
            print(f"  [{r.status:9}] {r.severity:8} {r.category:10} {r.change_type:8} {r.summary[:110]}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
