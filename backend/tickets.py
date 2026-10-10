"""Open a ticket in GitHub Issues or Jira for each new confirmed change that is serious enough.

Rules (they mirror notifications.py, so a ticket is never opened for something the team was not also told about):
  * Only CONFIRMED "added" change events at or above the target's ticket threshold (default high) qualify.
    A baseline scan has no events, so the first scan of a target opens nothing.
  * One ticket per change fingerprint, ever. The (target, fingerprint) row is written BEFORE the tracker is
    called, so a retried task or a second scan cannot open a duplicate. A failed attempt is retried on later
    scans a few times, then left visible as failed.
  * At most ASM_TICKETS_MAX_PER_SCAN (default 10) tickets per scan; the rest stay visible on the Changes page.
  * Credentials live in environment variables, never in the database or in API responses. Error text kept
    for display is a short label; it never contains a URL, header or token.
  * Text that came from the scanned target is defanged (mentions) before it reaches the tracker.
  * Nothing here may raise into the scan pipeline.
"""
import logging
import os
import re
import time
from typing import Dict, List, Optional, Tuple

import requests
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.models.change_event import ChangeEvent
from backend.models.scan import Scan
from backend.models.target import Target
from backend.models.ticket import Ticket
from backend.notifications import effective_severity, meets_threshold
from backend.rollup import sev_rank

logger = logging.getLogger(__name__)

PROVIDERS = ("github", "jira")
MAX_ATTEMPTS = 4
TIMEOUT = (5, 15)
GITHUB_API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,9}$")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")


class TicketError(Exception):
    """Short, display-safe reason (no URL, header or token)."""

    def __init__(self, label: str):
        super().__init__(label)
        self.label = label


# --------------------------------------------------------------------------- configuration

def max_per_scan() -> int:
    try:
        return max(1, min(int(os.getenv("ASM_TICKETS_MAX_PER_SCAN", "10")), 50))
    except ValueError:
        return 10


def provider_name() -> Optional[str]:
    p = os.getenv("ASM_TICKETS_PROVIDER", "").strip().lower()
    return p if p in PROVIDERS else None


def jira_base() -> str:
    return os.getenv("ASM_JIRA_URL", "").strip().rstrip("/")


def missing_settings(provider: Optional[str]) -> List[str]:
    if provider == "github":
        need = {"ASM_TICKETS_GITHUB_TOKEN": os.getenv("ASM_TICKETS_GITHUB_TOKEN", "").strip()}
    elif provider == "jira":
        need = {"ASM_JIRA_URL": jira_base(), "ASM_JIRA_EMAIL": os.getenv("ASM_JIRA_EMAIL", "").strip(),
                "ASM_JIRA_TOKEN": os.getenv("ASM_JIRA_TOKEN", "").strip()}
        if jira_base() and not jira_base().startswith("https://"):
            return ["ASM_JIRA_URL (must start with https://)"]
    else:
        return ["ASM_TICKETS_PROVIDER"]
    return [k for k, v in need.items() if not v]


def status() -> Dict:
    p = provider_name()
    miss = missing_settings(p)
    return {"provider": p, "configured": p is not None and not miss, "missing": miss if p else ["ASM_TICKETS_PROVIDER"]}


def validate_destination(provider: Optional[str], value: str) -> str:
    """Normalise a destination for the configured provider. Raises ValueError with a message the user can act on."""
    v = (value or "").strip()
    if not v:
        return ""
    if provider == "github" or (provider is None and "/" in v):
        if not _REPO.match(v) or any(part in (".", "..") for part in v.split("/")):
            raise ValueError("Use the form owner/repository, for example acme/security-findings")
        return v
    if provider == "jira" or provider is None:
        v = v.upper()
        if not _JIRA_KEY.match(v):
            raise ValueError("Use the Jira project key, for example SEC")
        return v
    raise ValueError("Ticketing is not set up on this server")


# --------------------------------------------------------------------------- text

def _safe(text, limit: int) -> str:
    """Untrusted text: no control or bidi characters, bounded, and @mentions broken so nobody is pinged."""
    s = _CTRL.sub("", str(text if text is not None else ""))
    s = " ".join(s.split())
    return s.replace("@", "@​")[:limit]


def build_ticket(target: Target, scan: Scan, e: ChangeEvent) -> Dict:
    sev = effective_severity(e)
    title = f"[ASM] {sev.capitalize()}: {_safe(e.summary, 150)}"[:200]
    lines = [("Target", target.domain), ("Asset", e.asset or "-"), ("Severity", sev), ("Kind", f"{e.category} {e.change_type}"),
             ("Seen in", f"scan #{scan.id} ({scan.profile})")]
    if e.confidence and e.confidence != "confirmed":
        lines.append(("Confidence", e.confidence))
    details = [f"{k}: {_safe(v, 200)}" for k, v in lines]
    extra = []
    if e.ai_summary:
        extra.append(f"Assessment: {_safe(e.ai_summary, 600)}")
    if e.ai_action:
        extra.append(f"Suggested action: {_safe(e.ai_action, 600)}")
    link = os.getenv("ASM_PUBLIC_URL", "").strip().rstrip("/")
    if link.startswith(("http://", "https://")):
        extra.append(f"Details: {link}/changes")
    return {"title": title, "summary": _safe(e.summary, 1000), "details": details, "extra": extra, "severity": sev}


def _github_body(t: Dict) -> str:
    out = [t["summary"], "", *[f"- {d}" for d in t["details"]]]
    if t["extra"]:
        out += [""] + [f"{x}\n" for x in t["extra"]]
    out += ["", "_Opened automatically by ASM Platform. Close this issue once the finding is fixed or accepted._"]
    return "\n".join(out)


def _adf_paragraph(text: str) -> Dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _jira_body(t: Dict) -> Dict:
    paras = [t["summary"], *t["details"], *t["extra"], "Opened automatically by ASM Platform."]
    return {"type": "doc", "version": 1, "content": [_adf_paragraph(p) for p in paras if p]}


# --------------------------------------------------------------------------- providers

def _raise_for(r, what: str):
    code = r.status_code
    if code in (401,):
        raise TicketError(f"{what} rejected the credentials")
    if code == 403:
        raise TicketError(f"{what} refused access (permissions or rate limit)")
    if code in (404, 410):
        raise TicketError("destination not found, or the credentials cannot see it")
    if code == 429:
        raise TicketError(f"{what} rate limit")
    if code == 422 or code == 400:
        raise TicketError(f"{what} refused the ticket (check the project settings)")
    raise TicketError(f"{what} error (HTTP {code})")


def _call(http, method: str, url: str, **kw):
    try:
        return getattr(http, method)(url, timeout=TIMEOUT, allow_redirects=False, **kw)
    except requests.exceptions.Timeout:
        raise TicketError("timeout")
    except requests.exceptions.SSLError:
        raise TicketError("tls error")
    except requests.exceptions.RequestException:
        raise TicketError("connection error")


def _gh_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {os.getenv('ASM_TICKETS_GITHUB_TOKEN', '').strip()}",
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ASM-Platform-Tickets/1"}


def _jira_auth() -> Tuple[str, str]:
    return os.getenv("ASM_JIRA_EMAIL", "").strip(), os.getenv("ASM_JIRA_TOKEN", "").strip()


def create_github(http, dest: str, t: Dict) -> Tuple[str, str]:
    r = _call(http, "post", f"{GITHUB_API}/repos/{dest}/issues", headers=_gh_headers(),
              json={"title": t["title"], "body": _github_body(t), "labels": ["asm", f"severity:{t['severity']}"]})
    if r.status_code != 201:
        _raise_for(r, "GitHub")
    try:
        d = r.json()
        url = str(d["html_url"])
        if not url.startswith("https://github.com/"):
            raise ValueError("unexpected link")        # it becomes a clickable link in the UI: https and GitHub only
        return f"#{int(d['number'])}", url
    except (ValueError, KeyError, TypeError):
        raise TicketError("unexpected response from GitHub")


def create_jira(http, dest: str, t: Dict) -> Tuple[str, str]:
    issue_type = os.getenv("ASM_JIRA_ISSUE_TYPE", "Task").strip() or "Task"
    r = _call(http, "post", f"{jira_base()}/rest/api/3/issue", auth=_jira_auth(),
              headers={"Accept": "application/json", "User-Agent": "ASM-Platform-Tickets/1"},
              json={"fields": {"project": {"key": dest}, "summary": t["title"][:250], "issuetype": {"name": issue_type},
                               "description": _jira_body(t), "labels": ["asm", f"severity-{t['severity']}"]}})
    if r.status_code != 201:
        _raise_for(r, "Jira")
    try:
        key = str(r.json()["key"])
        return key, f"{jira_base()}/browse/{key}"
    except (ValueError, KeyError, TypeError):
        raise TicketError("unexpected response from Jira")


def create_ticket(http, provider: str, dest: str, t: Dict) -> Tuple[str, str]:
    return (create_github if provider == "github" else create_jira)(http, dest, t)


def check_destination(http, provider: str, dest: str) -> str:
    """Read-only probe used by 'Check connection'. Returns a short confirmation or raises TicketError."""
    if provider == "github":
        r = _call(http, "get", f"{GITHUB_API}/repos/{dest}", headers=_gh_headers())
        if r.status_code != 200:
            _raise_for(r, "GitHub")
        try:
            if r.json().get("has_issues") is False:
                raise TicketError("issues are turned off for this repository")
        except ValueError:
            raise TicketError("unexpected response from GitHub")
        return f"Repository {dest} is reachable and accepts issues"
    r = _call(http, "get", f"{jira_base()}/rest/api/3/project/{dest}", auth=_jira_auth(),
              headers={"Accept": "application/json", "User-Agent": "ASM-Platform-Tickets/1"})
    if r.status_code != 200:
        _raise_for(r, "Jira")
    return f"Jira project {dest} is reachable"


# --------------------------------------------------------------------------- entry point

def _attempt(db: Session, http, provider: str, row: Ticket, target: Target, scan: Scan, e: ChangeEvent) -> bool:
    row.attempts = (row.attempts or 0) + 1
    try:
        key, url = create_ticket(http, provider, row.destination, build_ticket(target, scan, e))
        row.status, row.external_key, row.url, row.error = "created", key, url, None
        ok = True
    except TicketError as err:
        row.status, row.error = "failed", err.label[:200]
        ok = False
    except Exception:  # noqa: BLE001
        logger.exception("[tickets] unexpected error")
        row.status, row.error = "failed", "internal error"
        ok = False
    db.commit()
    return ok


def create_for_scan(db: Session, scan: Scan, http=requests, sleep=time.sleep) -> Dict:
    """Open tickets for one scan's qualifying changes, and retry earlier failures. Never raises."""
    out = {"status": "off", "created": 0, "failed": 0, "omitted": 0}
    try:
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        provider = provider_name()
        if target is None or not target.ticket_destination or provider is None:
            return out
        if missing_settings(provider):
            out["status"] = "not configured"
            return out
        dest, minimum = target.ticket_destination, target.ticket_min_severity or "high"
        budget = max_per_scan()
        known = {f for (f,) in db.query(Ticket.fingerprint).filter(Ticket.target_id == target.id).all()}

        events = [e for e in db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id, ChangeEvent.status == "confirmed",
                                                         ChangeEvent.change_type == "added").order_by(ChangeEvent.id).all()
                  if meets_threshold(effective_severity(e), minimum) and e.fingerprint not in known]
        events.sort(key=lambda e: (sev_rank(effective_severity(e)), e.id))

        retries = (db.query(Ticket).filter(Ticket.target_id == target.id, Ticket.status == "failed",
                                           Ticket.attempts < MAX_ATTEMPTS, Ticket.destination == dest)
                   .order_by(Ticket.id).limit(budget).all())

        done = 0
        for row in retries:
            ev = db.query(ChangeEvent).filter(ChangeEvent.id == row.change_event_id).first() if row.change_event_id else None
            if ev is None or done >= budget:
                continue
            if done:
                sleep(0.5)
            done += 1
            out["created" if _attempt(db, http, provider, row, target, scan, ev) else "failed"] += 1

        for e in events:
            if done >= budget:
                out["omitted"] += 1
                continue
            row = Ticket(target_id=target.id, scan_id=scan.id, change_event_id=e.id, fingerprint=e.fingerprint,
                         provider=provider, destination=dest, severity=effective_severity(e),
                         title=build_ticket(target, scan, e)["title"], status="failed", attempts=0)
            db.add(row)
            try:
                db.commit()                      # reserve first: the unique key is what prevents duplicates
            except IntegrityError:
                db.rollback()
                continue
            if done:
                sleep(0.5)
            done += 1
            out["created" if _attempt(db, http, provider, row, target, scan, e) else "failed"] += 1
        out["status"] = "ok"
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("[tickets] failed")
        out["status"] = "error"
    return out
