"""Is the target named on a ransomware leak site? Data from RansomLook (https://www.ransomlook.io), which publishes
its search API without a key under CC BY 4.0 (commercial use allowed with credit; the credit is shown in the UI
and README).

Only the public listing text is read. Nothing linked from a listing is ever fetched: no onion pages, no archives,
no screenshots, no magnet links, and none of those links is stored. A listing is the attacker's claim, so it is
reported as "named on", never as confirmed data theft.
"""
import re
from typing import Dict, List

from backend.exposure.base import CollectorError, Finding, Findings, clean_text
from backend.exposure.lookalikes import registrable_parts

API = "https://www.ransomlook.io/api/search"
HOME = "https://www.ransomlook.io/"
MIN_LABEL_LEN = 6            # shorter brand names ("acme", "bank") match far too many unrelated victims
PAUSE_SECONDS = 3
DESCRIPTION_CHARS = 300


def _boundary(term: str):
    return re.compile(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])")


class RansomLookCollector:
    name = "ransomlook"
    label = "Ransomware leak sites"
    description = ("Whether this domain or organisation name is listed as a victim on ransomware leak sites. "
                   "Data: RansomLook.io, CC BY 4.0. Free, no key.")
    min_interval_seconds = 24 * 3600

    def configured(self) -> bool:
        return True

    def collect(self, domain: str, http, sleep) -> Findings:
        parts = registrable_parts(domain)
        if parts is None:
            from backend.exposure.base import NotApplicable
            raise NotApplicable("needs a public domain name, not an IP or internal host")
        label, tld = parts
        full = f"{label}.{tld}"
        queries = [(full, "domain")]
        if len(label) >= MIN_LABEL_LEN:
            queries.append((label, "name"))

        by_key: Dict[str, Finding] = {}
        complete = True
        for i, (term, kind) in enumerate(queries):
            if i:
                sleep(PAUSE_SECONDS)
            try:
                r = http.get(API, params={"q": term}, headers={"Accept": "application/json"})
            except CollectorError as e:
                if i > 0 and e.label == "response too large":
                    complete = False          # a very common name: skip it rather than lose the whole run
                    continue
                raise
            if r.status == 429:
                from backend.exposure.base import RateLimited
                raise RateLimited(None)
            if r.status != 200:
                raise CollectorError("upstream error")
            try:
                data = r.json()
            except ValueError:
                raise CollectorError("unexpected response")
            if not isinstance(data, dict) or "posts" not in data:
                raise CollectorError("unexpected response")
            for p in data.get("posts") or []:
                f = self._post_to_finding(p, full, label, kind)
                if f and (f.key not in by_key or _rank(f.severity) < _rank(by_key[f.key].severity)):
                    by_key[f.key] = f
        return Findings(by_key.values(), complete=complete)

    @staticmethod
    def _post_to_finding(p, full: str, label: str, kind: str):
        if not isinstance(p, dict):
            return None
        title = clean_text(p.get("post_title"), 200)
        group = clean_text(p.get("group_name"), 60)
        if not title or not group:
            return None
        desc = clean_text(p.get("description"), 4000)
        dom_rx, name_rx = _boundary(full), _boundary(label)
        in_title_domain = bool(dom_rx.search(title.lower()))
        in_title_name = len(label) >= MIN_LABEL_LEN and bool(name_rx.search(title.lower()))
        in_desc_domain = bool(dom_rx.search(desc.lower()))
        if in_title_domain:
            sev, how = "critical", f"the title contains {full}"
        elif in_title_name:
            sev, how = "high", f"the title contains the name \"{label}\""
        elif in_desc_domain:
            sev, how = "high", f"the description mentions {full}"
        else:
            return None                       # a keyword hit with no real link to this target
        when = clean_text(p.get("discovered"), 19)[:10]
        summary = (f"{group} listed \"{title}\"{f' on {when}' if when else ''}; {how}. "
                   "This is the attacker's claim. Check with your incident-response contact whether this is your "
                   "organisation or a supplier, and do not open anything linked from the listing.")
        return Finding(
            source="ransomlook", kind="ransomware_listing", key=f"{group.lower()}|{title.lower()}",
            title=f"Named on a ransomware leak site: {group}"[:200], summary=summary[:600], severity=sev, url=HOME,
            evidence={"group": group, "listed_title": title, "discovered": when or None, "matched": how,
                      "description_excerpt": desc[:DESCRIPTION_CHARS] or None,
                      "credit": "RansomLook.io, CC BY 4.0"},
        )


_SEV = ("critical", "high", "medium", "low", "info")


def _rank(s: str) -> int:
    return _SEV.index(s) if s in _SEV else len(_SEV)
