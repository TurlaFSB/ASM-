"""Infostealer exposure for the target's domain, from Hudson Rock's free Cavalier OSINT lookup (no key).

Hudson Rock's terms for this free endpoint could not be read when this collector was written (the pages are
JavaScript apps behind a bot challenge). So it is OFF until the operator sets ASM_HUDSONROCK_ACK=true to state that
they have read Hudson Rock's terms and that this use is allowed. One request per target per day.

Only aggregate numbers and the portal URLs of the target's own services are kept. The response's per-credential
list (`data`), when present, is ignored: no email, username or password is ever read into the database.
"""
import os
from datetime import datetime, timezone
from typing import Dict, Optional

from backend.exposure.base import CollectorError, Finding, Findings, NotApplicable, RateLimited, clean_text, safe_https_url
from backend.exposure.lookalikes import registrable_parts

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
VIEW = "https://www.hudsonrock.com/search/domain/"
ACK_VAR = "ASM_HUDSONROCK_ACK"


def _int(v) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _when(v) -> Optional[datetime]:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _days_ago(d: Optional[datetime], now: datetime) -> Optional[int]:
    return None if d is None else max(0, (now - d).days)


def rate(employees: int, users: int, emp_age: Optional[int], user_age: Optional[int]) -> Optional[str]:
    """Stolen employee credentials are the serious case; customer-only exposure is lower."""
    if employees > 0:
        if emp_age is not None and emp_age <= 30:
            return "critical"
        if emp_age is not None and emp_age <= 180:
            return "high"
        return "medium"
    if users > 0:
        return "medium" if user_age is not None and user_age <= 90 else "low"
    return None


class HudsonRockCollector:
    name = "hudsonrock"
    needs = "ASM_HUDSONROCK_ACK"
    label = "Infostealer exposure (Hudson Rock)"
    description = ("How many employee and customer credentials for this domain were captured by infostealer malware. "
                   "Aggregate counts only. Free; read Hudson Rock's terms first and set ASM_HUDSONROCK_ACK=true.")
    min_interval_seconds = 24 * 3600

    def configured(self) -> bool:
        return os.environ.get(ACK_VAR, "").strip().lower() in ("1", "true", "yes")

    def collect(self, domain: str, http, sleep, now: Optional[datetime] = None) -> Findings:
        if not self.configured():
            raise CollectorError("not configured")
        parts = registrable_parts(domain)
        if parts is None:
            raise NotApplicable("needs a public domain name, not an IP or internal host")
        full = f"{parts[0]}.{parts[1]}"
        r = http.get(API, params={"domain": full}, headers={"Accept": "application/json"})
        if r.status == 429:
            raise RateLimited(None)
        if r.status != 200:
            raise CollectorError("upstream error")
        try:
            data = r.json()
        except ValueError:
            raise CollectorError("unexpected response")
        if not isinstance(data, dict) or not any(k in data for k in ("employees", "users", "total")):
            raise CollectorError("unexpected response")

        now = now or datetime.now(timezone.utc)
        emp, usr, third = _int(data.get("employees")), _int(data.get("users")), _int(data.get("third_parties"))
        emp_when, usr_when = _when(data.get("last_employee_compromised")), _when(data.get("last_user_compromised"))
        sev = rate(emp, usr, _days_ago(emp_when, now), _days_ago(usr_when, now))
        if sev is None:
            return Findings([])

        stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
        urls = [u for u in (safe_https_url(x, None) for x in (stats.get("employees_urls") or [])[:20]) if u][:5]
        pw = data.get("employeePasswords") if isinstance(data.get("employeePasswords"), dict) else {}
        strength: Dict[str, int] = {k: _int((pw.get(k) or {}).get("qty")) for k in ("too_weak", "weak", "medium", "strong")
                                    if isinstance(pw.get(k), dict)}
        fam = data.get("stealerFamilies") if isinstance(data.get("stealerFamilies"), dict) else {}
        families = sorted(((clean_text(k, 30), _int(v)) for k, v in fam.items() if k != "total"), key=lambda kv: -kv[1])[:5]

        last = emp_when or usr_when
        summary = (f"Hudson Rock reports {emp:,} employee and {usr:,} customer credential sets for {full} captured by infostealer "
                   f"malware{f', the most recent on {last.date().isoformat()}' if last else ''}. These come from a third-party "
                   "database and can include old or duplicate captures. Reset passwords and require MFA for the affected "
                   "accounts, and review the source page for details.")
        return Findings([Finding(
            source=self.name, kind="infostealer", key=f"infostealer|{full}",
            title=f"Infostealer-captured credentials for {full}", summary=summary[:600], severity=sev,
            url=VIEW + full,
            evidence={"employees": emp, "users": usr, "third_parties": third,
                      "total_stealers": _int(data.get("totalStealers")),
                      "last_employee_compromised": emp_when.date().isoformat() if emp_when else None,
                      "last_user_compromised": usr_when.date().isoformat() if usr_when else None,
                      "employee_password_strength": strength, "stealer_families": [{"name": n, "count": c} for n, c in families],
                      "employee_portal_urls": urls, "credit": "Hudson Rock (free OSINT lookup)"},
        )])
