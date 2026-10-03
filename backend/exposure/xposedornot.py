"""Public breach records for the target's own domain, from XposedOrNot (free, no key).

GET /v1/breaches?domain=<domain> lists breaches where the *domain's own service* was the victim.
(Which employee emails appear in breaches needs XposedOrNot's keyed domain API, which is out of scope.)
The response format is parsed defensively; anything unrecognised is reported as an error, never as "clean".
"""
from typing import List

from backend.exposure.base import CollectorError, Finding, RateLimited, clean_text, require_public_domain, safe_https_url

API = "https://api.xposedornot.com/v1/breaches"
LIST_KEYS = ("exposedBreaches", "breaches", "data", "Breaches")
SENSITIVE_DATA = ("password", "credit", "card", "ssn", "social security", "bank", "passport", "secret")


def _get(d: dict, *names, default=None):
    low = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return default


class XposedOrNotCollector:
    name = "xposedornot"
    label = "XposedOrNot breach records"
    description = "Public data-breach records for this domain's own service. Free, no key."
    min_interval_seconds = 24 * 3600

    def configured(self) -> bool:
        return True

    def collect(self, domain: str, http, sleep) -> List[Finding]:
        require_public_domain(domain)
        r = http.get(API, params={"domain": domain.lower()}, headers={"Accept": "application/json"})
        if r.status == 429:
            raise RateLimited(None)
        if r.status == 404:
            return []
        if r.status != 200:
            raise CollectorError("upstream error")
        try:
            data = r.json()
        except ValueError:
            raise CollectorError("unexpected response")
        items = self._items(data)
        out: List[Finding] = []
        for b in items:
            if not isinstance(b, dict):
                continue
            f = self._to_finding(domain, b)
            if f:
                out.append(f)
        return out

    @staticmethod
    def _items(data) -> list:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in LIST_KEYS:
                if isinstance(data.get(k), list):
                    return data[k]
            # Real "nothing found" answer (HTTP 200): {"status":"Not Found","message":"No breaches found ...","exposedBreaches":null}
            if str(data.get("status", "")).lower() == "not found" and data.get("exposedBreaches") is None:
                return []
            err = str(_get(data, "error", "message", default="")).lower()
            if "not found" in err or "no breach" in err:
                return []
        raise CollectorError("unexpected response")

    @staticmethod
    def _to_finding(domain: str, b: dict):
        bid = clean_text(_get(b, "breachID", "breach_id", "id", "name", default=""), 80)
        if not bid:
            return None
        date = clean_text(_get(b, "breachedDate", "breached_date", "date", default=""), 40)
        records = _get(b, "exposedRecords", "records", default=None)
        data_types = _get(b, "exposedData", "exposed_data", default=[]) or []
        if isinstance(data_types, str):
            data_types = [x for x in data_types.replace(";", ",").split(",")]
        data_types = [clean_text(x, 40) for x in data_types if clean_text(x, 40)][:8]
        pw_risk = str(_get(b, "passwordRisk", "password_risk", default="")).lower()
        verified = _get(b, "verified", default=True)
        sensitive = _get(b, "sensitive", default=False) is True
        hard_data = any(any(w in t.lower() for w in SENSITIVE_DATA if w != "password") for t in data_types)
        pw_exposed = any("password" in t.lower() for t in data_types)
        # Passwords exposed are serious unless the source says they are hashed in a way that is hard to crack.
        if sensitive or hard_data or pw_risk in ("plaintext", "easytocrack") or (pw_exposed and pw_risk != "hardtocrack"):
            sev = "high"
        else:
            sev = "medium"
        if verified is False or str(verified).lower() == "no":
            sev = "low" if sev == "medium" else "medium"
        if len(date) >= 10 and date[4:5] == "-":
            date = date[:10]
        bits = [f"Breach {bid}"]
        if date:
            bits.append(f"dated {date}")
        if isinstance(records, int):
            bits.append(f"{records:,} records")
        summary = ", ".join(bits) + "."
        if data_types:
            summary += f" Exposed data: {', '.join(data_types)}."
        return Finding(
            source="xposedornot", kind="breach", key=bid,
            title=f"Public breach record: {bid}"[:200], summary=summary[:500], severity=sev,
            url=safe_https_url(_get(b, "referenceURL", "reference_url", default=None), None),
            evidence={"breach": bid, "date": date, "records": records if isinstance(records, int) else None,
                      "exposed_data": data_types, "verified": bool(verified) if isinstance(verified, bool) else None,
                      "password_risk": pw_risk or None},
        )
