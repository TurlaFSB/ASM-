"""Show what the stored snapshots of the given scans contain, for diagnosing diff results.

    docker compose exec backend python -m backend.scripts.snapshot_findings <scan_id> [<scan_id> ...] [--host 192.168.16.128:22] [--events]

Prints each snapshot's schema, coverage map and the findings (optionally only those whose host
contains --host). With --events it also lists every change event row recorded by or settled by
those scans (id, status, which scan settled it), which shows a pending removal's whole lifecycle.
"""
import sys

from backend.db import SessionLocal
from backend.models.scan_snapshot import ScanSnapshot


def main(argv) -> int:
    args = argv[1:]
    host = None
    if "--host" in args:
        i = args.index("--host")
        host = args[i + 1] if i + 1 < len(args) else None
        args = args[:i] + args[i + 2:]
    show_events = "--events" in args
    args = [a for a in args if a != "--events"]
    ids = [int(a) for a in args if a.isdigit()]
    if not ids:
        print(__doc__)
        return 2
    db = SessionLocal()
    try:
        for sid in ids:
            snap = db.query(ScanSnapshot).filter(ScanSnapshot.scan_id == sid).first()
            if not snap:
                print(f"scan {sid}: no snapshot")
                continue
            d = snap.data
            cov = d.get("coverage", {})
            print(f"scan {sid}: schema={snap.schema_version} profile={snap.profile} "
                  f"findings_network={cov.get('findings_network')} total_findings={len(d.get('findings', {}))}")
            for key, f in sorted(d.get("findings", {}).items()):
                if host is None or host in (f.get("host") or ""):
                    print(f"    {f.get('source'):8} {f.get('severity'):8} {f.get('name')}  [{key}]")
        if show_events:
            from sqlalchemy import or_
            from backend.models.change_event import ChangeEvent
            rows = (db.query(ChangeEvent).filter(or_(ChangeEvent.scan_id.in_(ids),
                                                     ChangeEvent.resolved_by_scan_id.in_(ids)))
                    .order_by(ChangeEvent.id).all())
            print("change events (id scan status resolved_by type summary):")
            for r in rows:
                if host is None or host in (r.summary or ""):
                    print(f"  #{r.id:<5} scan={r.scan_id:<3} {r.status:10} by={r.resolved_by_scan_id} "
                          f"{r.change_type:8} {r.summary[:90]}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
