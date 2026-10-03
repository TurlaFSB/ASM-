"""Run AI triage on the confirmed change events of an existing scan (backfill, or an end-to-end check).

    docker compose exec backend python -m backend.scripts.ai_triage_scan <scan_id>
    docker compose exec backend python -m backend.scripts.ai_triage_scan <scan_id> --force   # redo events already triaged
"""
import argparse
import sys

from backend.ai.triage import triage_scan_events
from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan


def run(db, scan_id: int, force: bool = False) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        return {"error": f"scan {scan_id} not found"}
    if force:
        for e in db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan_id):
            e.ai_status = e.ai_severity = e.final_severity = e.ai_summary = e.ai_action = e.ai_model = e.ai_error = None
        db.commit()
    result = triage_scan_events(db, scan)
    rows = db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan_id, ChangeEvent.status == "confirmed").order_by(ChangeEvent.id).all()
    return {"result": result, "events": [
        {"id": e.id, "category": e.category, "change": e.change_type, "subject": e.subject, "rule": e.severity,
         "ai_status": e.ai_status, "ai": e.ai_severity, "final": e.final_severity or e.severity,
         "summary": e.ai_summary, "action": e.ai_action, "error": e.ai_error} for e in rows]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scan_id", type=int)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    from backend.db import SessionLocal
    db = SessionLocal()
    try:
        out = run(db, args.scan_id, args.force)
    finally:
        db.close()
    if "error" in out:
        print(out["error"])
        return 2
    print("TRIAGE", out["result"])
    for e in out["events"]:
        print(f"#{e['id']} {e['category']}/{e['change']} {e['subject']} rule={e['rule']} ai={e['ai']} final={e['final']} "
              f"[{e['ai_status']}] {e['summary']} | {e['action']} | {e['error']}")
    return 0 if out["result"]["status"] in ("ok", "partial", "disabled") else 1


if __name__ == "__main__":
    sys.exit(main())
