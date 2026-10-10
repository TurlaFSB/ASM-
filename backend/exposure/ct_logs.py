"""Certificate Transparency monitoring: host names that publicly trusted certificates were issued for.

Every publicly trusted certificate is logged. Watching the log for a target's domain shows new host names
(a forgotten staging site, a shadow-IT service, a name an attacker obtained a certificate for) the day a
certificate is issued, long before DNS-based discovery would find them.

Source: crt.sh (free, no key). Each distinct host name is one finding. A name whose newest certificate was
issued in the last two weeks is "low" (worth a look); older names are "info" (inventory). The first run for
a target is a silent baseline, so enabling the source does not announce everything that already exists.
The response is parsed defensively; anything unrecognised is reported as an error, never as "no certificates".
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from urllib.parse import quote

from backend.exposure.base import (CollectorError, Finding, Findings, RateLimited, clean_text,
                                   require_public_domain, safe_https_url)

API = "https://crt.sh/"
FRESH_DAYS = 14
MAX_NAMES = 2000
MAX_BYTES = 8 * 1024 * 1024
_NAME = re.compile(r"^(\*\.)?(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))+$")


def _parse_time(value):
    s = str(value or "").strip().replace("T", " ")[:19]
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _in_scope(name: str, domain: str) -> bool:
    bare = name[2:] if name.startswith("*.") else name
    return bare == domain or bare.endswith("." + domain)


class CTLogCollector:
    name = "ct_logs"
    label = "Certificate transparency"
    description = ("Host names that publicly trusted certificates were issued for (crt.sh, free, no key). "
                   "The first run records what already exists without alerting.")
    min_interval_seconds = 6 * 3600
    silent_baseline = True

    def configured(self) -> bool:
        return True

    def collect(self, domain: str, http, sleep) -> List[Finding]:
        require_public_domain(domain)
        domain = domain.lower().strip(".")
        r = http.get(API, params={"q": f"%.{domain}", "output": "json", "exclude": "expired", "deduplicate": "Y"},
                     headers={"Accept": "application/json"}, max_bytes=MAX_BYTES)
        if r.status == 429:
            raise RateLimited(None)
        if r.status == 404:
            return Findings([])
        if r.status != 200:
            raise CollectorError("crt.sh unavailable")      # it is often overloaded; the next run retries
        if not r.body.strip():
            return Findings([])
        try:
            rows = r.json()
        except ValueError:
            raise CollectorError("unexpected response")
        if not isinstance(rows, list):
            raise CollectorError("unexpected response")

        newest: Dict[str, dict] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            issued = _parse_time(row.get("not_before"))
            issuer = clean_text(row.get("issuer_name", ""), 120)
            cert_id = row.get("id")
            for raw in str(row.get("name_value", "")).splitlines():
                name = clean_text(raw, 255).lower().strip(".")
                if not _NAME.match(name) or not _in_scope(name, domain):
                    continue
                cur = newest.get(name)
                if cur is None or (issued and (cur["issued"] is None or issued > cur["issued"])):
                    newest[name] = {"issued": issued, "issuer": issuer, "id": cert_id}
                    continue
        complete = len(newest) <= MAX_NAMES
        now = datetime.now(timezone.utc)
        out: List[Finding] = []
        for name in sorted(newest)[:MAX_NAMES]:
            c = newest[name]
            fresh = bool(c["issued"] and now - c["issued"] <= timedelta(days=FRESH_DAYS))
            when = c["issued"].date().isoformat() if c["issued"] else "an unknown date"
            wild = name.startswith("*.")
            summary = f"A certificate for {name} was issued on {when}"
            if c["issuer"]:
                summary += f" by {c['issuer']}"
            summary += ". " + ("Wildcard certificates cover every subdomain, so check who holds the key."
                               if wild else "Make sure this host is one you know about.")
            out.append(Finding(
                source=self.name, kind="certificate", key=name,
                title=f"Certificate issued for {name}"[:200], summary=summary[:500],
                severity="low" if fresh else "info",
                url=safe_https_url(f"https://crt.sh/?q={quote(name, safe='')}", ("crt.sh",)),
                evidence={"name": name, "issued": c["issued"].isoformat() if c["issued"] else None,
                          "issuer": c["issuer"] or None, "wildcard": wild, "fresh": fresh},
            ))
        return Findings(out, complete=complete)
