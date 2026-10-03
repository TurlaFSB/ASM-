"""Public code on GitHub that mentions the target's domain next to credential-like text.

Needs a free GitHub token in ASM_GITHUB_TOKEN (code search is not available anonymously).
Uses the text-match fragments GitHub returns, so no file is downloaded. Fragments are scanned in memory and
only masked traces are kept.
"""
import os
from typing import Dict, List

from backend.exposure.base import CollectorError, Finding, RateLimited, clean_text, require_public_domain, safe_https_url
from backend.exposure.masking import HARD_RULES, is_doc_path, path_severity, scan_fragment

API = "https://api.github.com/search/code"
QUERY_SUFFIXES = ["password", "secret", "api_key", "filename:.env"]
PAUSE_SECONDS = 7            # code search allows 10 requests/minute for authenticated users
MAX_RESULTS_PER_QUERY = 30
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _worst(a: str, b: str) -> str:
    return a if SEV_ORDER.index(a) >= SEV_ORDER.index(b) else b


class GitHubCodeCollector:
    name = "github_code"
    needs = "ASM_GITHUB_TOKEN"
    label = "GitHub public code"
    description = "Public GitHub files that mention the domain next to passwords, keys or tokens. Needs a free GitHub token."
    min_interval_seconds = 6 * 3600

    def configured(self) -> bool:
        return bool(os.environ.get("ASM_GITHUB_TOKEN", "").strip())

    def collect(self, domain: str, http, sleep) -> List[Finding]:
        token = os.environ.get("ASM_GITHUB_TOKEN", "").strip()
        if not token:
            raise CollectorError("not configured")
        require_public_domain(domain)
        headers = {"Accept": "application/vnd.github.text-match+json", "Authorization": f"Bearer {token}",
                   "X-GitHub-Api-Version": "2022-11-28"}
        dom = domain.lower()
        files: Dict[tuple, dict] = {}
        for i, suffix in enumerate(QUERY_SUFFIXES):
            if i:
                sleep(PAUSE_SECONDS)
            r = http.get(API, params={"q": f'"{dom}" {suffix}', "per_page": MAX_RESULTS_PER_QUERY}, headers=headers)
            self._check(r)
            for item in (r.json().get("items") or []):
                repo = item.get("repository") or {}
                full, path = repo.get("full_name"), item.get("path")
                if not full or not path or repo.get("fork"):
                    continue
                entry = files.setdefault((full, path), {"url": item.get("html_url"), "fragments": []})
                for tm in item.get("text_matches") or []:
                    if tm.get("fragment"):
                        entry["fragments"].append(tm["fragment"])
        return [f for f in (self._to_finding(dom, k, v) for k, v in files.items()) if f]

    @staticmethod
    def _check(r) -> None:
        if r.status == 200:
            return
        remaining = r.headers.get("x-ratelimit-remaining")
        retry = r.headers.get("retry-after")
        if r.status == 429 or (r.status == 403 and (remaining == "0" or retry or "rate limit" in r.text.lower())):
            raise RateLimited(int(retry) if retry and retry.isdigit() else None)
        if r.status in (401, 403):
            raise CollectorError("token rejected")
        if r.status == 422:
            raise CollectorError("query rejected")
        raise CollectorError("upstream error")

    @staticmethod
    def _to_finding(domain: str, key: tuple, data: dict):
        repo, path = key
        text = " ".join(data["fragments"])
        # GitHub matches loosely; keep only results that really contain the domain
        if domain not in text.lower() and domain not in path.lower():
            return None
        hits = scan_fragment(text, domain)
        sev = path_severity(path)
        for h in hits:
            sev = _worst(sev, h.severity)
        # Docs, tests and examples are full of fake `password=...` lines. Keep real token formats at full
        # severity, but cap everything else found there at "low".
        if is_doc_path(path) and not any(h.rule in HARD_RULES for h in hits) and SEV_ORDER.index(sev) > SEV_ORDER.index("low"):
            sev = "low"
        rules = sorted({h.rule for h in hits})
        title = f"{repo}: {clean_text(path, 120)}"
        if hits:
            summary = (f"Public file mentions {domain} next to credential-like text "
                       f"({', '.join(rules[:4])}). Values are masked. Check whether this is real and rotate if it is.")
        else:
            summary = f"Public file mentions {domain}. No credential-like text was visible in the matched excerpt."
        return Finding(
            source="github_code", kind="secret" if hits else "mention",
            key=f"{repo}|{path}",
            title=title[:200], summary=summary, severity=sev,
            url=safe_https_url(data.get("url"), ("github.com",)),
            evidence={"repo": clean_text(repo, 100), "path": clean_text(path, 200),
                      "rules": [{"rule": h.rule, "sample": h.sample} for h in hits]},
        )

