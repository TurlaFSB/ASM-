"""Show what the stored snapshots of the given scans contain, for diagnosing diff results.

    docker compose exec backend python -m backend.scripts.snapshot_findings <scan_id> [<scan_id> ...] [--host 192.168.16.128:22]

Prints each snapshot's schema, coverage map and the findings (optionally only those whose host
contains --host).
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
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
