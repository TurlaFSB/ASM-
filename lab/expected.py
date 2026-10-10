"""What the end-to-end scan of the lab must produce. Kept apart from the driver so it can be unit-tested offline."""
import hashlib
import hmac
from typing import Dict, List

LAB_IP = "172.28.0.80"

# template_id -> minimum severity rank allowed (lower is worse); both come from the platform's own content-verified checks
REQUIRED_FINDINGS = {"exposed-git": "high", "exposed-env": "high"}
REQUIRED_PORTS = {80}
# Stages that must not have failed. (A stage may legitimately be "ok", "empty" or "skipped"; "failed"/"timeout" is a bug.)
BAD_STATUS_PREFIXES = ("failed", "timeout", "error", "not installed")
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def setup_code(secret_key: str) -> str:
    """Same derivation as backend.sessions.setup_code (kept in step by a unit test)."""
    h = hmac.new(secret_key.encode(), b"asm-first-run-setup-v1", hashlib.sha256).hexdigest()[:12]
    return "-".join(h[i:i + 4] for i in range(0, 12, 4))


def evaluate(scan: Dict, vulns: List[Dict], assets: List[Dict]) -> List[str]:
    """Problems found in the result of the lab scan; an empty list means the platform did its job."""
    problems: List[str] = []
    if scan.get("status") != "completed":
        problems.append(f"scan status is {scan.get('status')!r}, expected 'completed' (error: {scan.get('error_log')})")
    for module, status in sorted((scan.get("module_results") or {}).items()):
        if isinstance(status, str) and status.lower().startswith(BAD_STATUS_PREFIXES):
            problems.append(f"stage {module} reported {status!r}")
    found = {v.get("template_id"): v for v in vulns if v.get("host") in (LAB_IP, f"{LAB_IP}:80") or LAB_IP in str(v.get("matched_at", ""))}
    for tid, worst in REQUIRED_FINDINGS.items():
        v = found.get(tid)
        if v is None:
            problems.append(f"missing finding {tid} on {LAB_IP}")
        elif RANK.get(str(v.get("severity", "")).lower(), 9) > RANK[worst]:
            problems.append(f"finding {tid} has severity {v.get('severity')!r}, expected {worst} or worse")
    lab = [a for a in assets if a.get("subdomain") == LAB_IP or a.get("ip") == LAB_IP]
    if not lab:
        problems.append(f"no asset recorded for {LAB_IP}")
    else:
        ports = {int(p.get("port")) for a in lab for p in (a.get("open_ports") or []) if str(p.get("port", "")).isdigit()}
        for p in sorted(REQUIRED_PORTS - ports):
            problems.append(f"port {p} not seen open on {LAB_IP} (saw {sorted(ports)})")
    return problems
