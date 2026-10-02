"""Shared rule for flagging discovered web paths that deserve attention (reports + API)."""
import re

SENSITIVE_RE = re.compile(
    r"admin|backup|\.(zip|sql|bak|old|tar|gz)$|\.git|\.env|config|phpmyadmin|manager|console|login|"
    r"\.htpasswd|id_rsa|\.ssh|\.aws|dump|passwd|actuator|swagger|phpinfo", re.I)
# Statuses that mean the content is actually reachable (or exists behind auth)
REACHABLE = (200, 401, 403)


def is_sensitive_path(path: str, status) -> bool:
    return status in REACHABLE and bool(SENSITIVE_RE.search(path or ""))
