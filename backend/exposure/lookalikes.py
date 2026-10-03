"""Lookalike domains: registered names that imitate the target's domain (typosquats, homoglyphs, phishing-style
names such as acme-login.com).

Self-contained: candidate names are generated locally (the same families of tricks as dnstwist) and checked
with ordinary DNS lookups. No third-party service is queried. A name is only reported when it actually resolves,
and one that points at the target's own infrastructure is marked info (defensive registrations).

Limits worth knowing: a domain that is registered but has no DNS records cannot be seen this way, and the
registrable-domain detection is a heuristic (it knows the common country second-level suffixes, not the full
public suffix list).
"""
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple

from backend.exposure.base import CollectorError, Finding, Findings, NotApplicable, clean_text, registrable_parts  # noqa: F401  (re-exported)

MAX_CANDIDATES = 1200
WORKERS = 12
DEADLINE_SECONDS = 150
MAX_ERROR_RATE = 0.5

LABEL_OK = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
ASCII_NAME_OK = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")

COMMON_TLDS = ["com", "net", "org", "co", "io", "app", "xyz", "info", "biz", "online", "site", "shop", "top", "support",
               "cloud", "tech", "live", "me", "cc", "in", "co.in", "us", "uk", "co.uk", "de", "ru", "cn"]
KEYWORDS = ["login", "secure", "support", "portal", "account", "verify", "billing", "mail", "vpn", "sso", "pay", "help", "service"]

QWERTY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
    "a": "qsz", "s": "awdx", "d": "serfc", "f": "drtgv", "g": "ftyhb", "h": "gyujn", "j": "huikm", "k": "jiol", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPH_ASCII = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "1": ["l", "i"], "i": ["1", "l"], "m": ["rn"], "w": ["vv"],
                   "d": ["cl"], "s": ["5"], "a": ["4"], "e": ["3"], "g": ["q"], "q": ["g"], "u": ["v"], "v": ["u"]}
# Characters from other alphabets that look the same; the domain is converted to punycode (xn--...)
HOMOGLYPH_UNICODE = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у",
                     "i": "і", "s": "ѕ", "j": "ј"}
VOWELS = "aeiou"

_ascii_priority = {"homoglyph": 0, "idn": 0, "keyword": 1, "tld": 1, "transposition": 2, "omission": 2, "repetition": 2,
                   "replacement": 3, "insertion": 3, "hyphenation": 3, "vowel-swap": 3, "bitsquat": 4, "addition": 4}


def _label_variants(label: str) -> Dict[str, str]:
    """candidate label -> technique (first technique wins)."""
    out: Dict[str, str] = {}

    def add(v: str, tech: str):
        if v and v != label and LABEL_OK.match(v) and v not in out:
            out[v] = tech

    n = len(label)
    for i in range(n):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] * 2 + label[i + 1:], "repetition")
        if i < n - 1 and label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
        for k in QWERTY.get(label[i], ""):
            add(label[:i] + k + label[i + 1:], "replacement")
            add(label[:i] + k + label[i:], "insertion")
            add(label[:i + 1] + k + label[i + 1:], "insertion")
        if label[i] in VOWELS:
            for v in VOWELS:
                add(label[:i] + v + label[i + 1:], "vowel-swap")
        for g in HOMOGLYPH_ASCII.get(label[i], []):
            add(label[:i] + g + label[i + 1:], "homoglyph")
        if i > 0:
            add(label[:i] + "-" + label[i:], "hyphenation")
        # bit flips that still give a valid hostname character
        for bit in range(8):
            c = chr(ord(label[i]) ^ (1 << bit))
            if re.match(r"[a-z0-9-]", c):
                add(label[:i] + c + label[i + 1:], "bitsquat")
    for i in range(n - 1):
        pair = label[i:i + 2]
        for g in (("m",) if pair == "rn" else ("w",) if pair == "vv" else ("d",) if pair == "cl" else ()):
            add(label[:i] + g + label[i + 2:], "homoglyph")
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        add(label + ch, "addition")
    for kw in KEYWORDS:
        add(f"{label}-{kw}", "keyword")
        add(f"{kw}-{label}", "keyword")
        add(f"{label}{kw}", "keyword")
    return out


def _idn_variants(label: str) -> Dict[str, str]:
    """Punycode names built by swapping letters for look-alike letters from other alphabets (one, then two)."""
    out: Dict[str, str] = {}
    swappable = [i for i, c in enumerate(label) if c in HOMOGLYPH_UNICODE]
    combos: List[Tuple[int, ...]] = [(i,) for i in swappable]
    combos += [(i, j) for a, i in enumerate(swappable) for j in swappable[a + 1:]][:60]
    for combo in combos:
        chars = list(label)
        for i in combo:
            chars[i] = HOMOGLYPH_UNICODE[chars[i]]
        try:
            out["".join(chars).encode("idna").decode("ascii")] = "idn"
        except UnicodeError:
            continue
    return out


def generate_candidates(domain: str, limit: int = MAX_CANDIDATES) -> List[Tuple[str, str]]:
    """[(ascii domain, technique)] ordered most-suspicious technique first, never the original, bounded."""
    parts = registrable_parts(domain)
    if not parts:
        return []
    label, tld = parts
    original = f"{label}.{tld}"
    found: Dict[str, str] = {}

    def add(name: str, tech: str):
        if name != original and name not in found and ASCII_NAME_OK.match(name):
            found[name] = tech

    for v, tech in _label_variants(label).items():
        add(f"{v}.{tld}", tech)
        if tld != "com" and tech in ("homoglyph", "keyword", "transposition", "omission"):
            add(f"{v}.com", tech)
    for v, tech in _idn_variants(label).items():
        add(f"{v}.{tld}", tech)
    for t in COMMON_TLDS:
        add(f"{label}.{t}", "tld")
    if len(label) > 3:
        for i in range(2, len(label) - 1):
            add(f"{label[:i]}.{label[i:]}.{tld}", "subdomain-split")
    order = sorted(found.items(), key=lambda kv: (_ascii_priority.get(kv[1], 5), len(kv[0]), kv[0]))
    return order[:limit]


# ----------------------------------------------------------------------------- DNS

def default_resolver() -> Callable[[str], Optional[Dict[str, List[str]]]]:
    import dns.exception
    import dns.resolver

    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = 2.0, 4.0

    def lookup(name: str) -> Optional[Dict[str, List[str]]]:
        """None = not registered (NXDOMAIN). Raises on resolver trouble so it can be counted."""
        rec: Dict[str, List[str]] = {"a": [], "mx": [], "ns": []}
        exists = False
        for rtype, key in (("A", "a"), ("AAAA", "a"), ("MX", "mx"), ("NS", "ns")):
            try:
                ans = r.resolve(name, rtype)
            except dns.resolver.NXDOMAIN:
                return None
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                if rtype == "NS":
                    continue
                continue
            except dns.exception.Timeout:
                raise TimeoutError(name)
            exists = True
            for x in ans:
                txt = x.exchange.to_text() if rtype == "MX" else x.target.to_text() if rtype == "NS" else x.to_text()
                txt = txt.rstrip(".").lower()
                if txt:                      # an MX of "." is a null MX (RFC 7505): the domain says it takes no mail
                    rec[key].append(txt)
        return rec if exists else None

    return lookup


def _severity(rec: Dict[str, List[str]], technique: str, same_infra: bool) -> str:
    if same_infra:
        return "info"
    if rec["a"] and rec["mx"]:
        sev = "high"
    elif rec["a"] or rec["mx"]:
        sev = "medium"
    else:
        sev = "low"
    if technique in ("homoglyph", "idn", "keyword") and sev in ("low", "medium"):
        sev = {"low": "medium", "medium": "high"}[sev]
    return sev


class LookalikeCollector:
    name = "lookalike_domains"
    label = "Lookalike domains"
    description = "Registered look-alike names for this domain: typos, swapped characters, login-style names. Checked with plain DNS, no third party."
    min_interval_seconds = 24 * 3600

    def __init__(self, resolver: Optional[Callable] = None):
        self._resolver = resolver
        self._now = time.monotonic

    def configured(self) -> bool:
        return True

    def collect(self, domain: str, http, sleep) -> Findings:
        parts = registrable_parts(domain)
        if not parts:
            raise NotApplicable("needs a public domain name, not an IP or internal host")
        label, tld = parts
        original = f"{label}.{tld}"
        lookup = self._resolver or default_resolver()
        candidates = generate_candidates(domain)
        # What the real domain points at, so defensive registrations that share it are not flagged.
        try:
            own = lookup(original) or {"a": [], "mx": [], "ns": []}
        except Exception:  # noqa: BLE001
            own = {"a": [], "mx": [], "ns": []}
        own_a, own_ns = set(own["a"]), set(own["ns"])

        started = self._now()
        results: Dict[str, Tuple[str, Dict[str, List[str]]]] = {}
        errors = checked = 0
        pool = ThreadPoolExecutor(max_workers=WORKERS)
        try:
            futures = {pool.submit(lookup, name): (name, tech) for name, tech in candidates}
            pending = set(futures)
            for fut in as_completed(futures, timeout=None):
                pending.discard(fut)
                name, tech = futures[fut]
                checked += 1
                try:
                    rec = fut.result()
                except Exception:  # noqa: BLE001
                    errors += 1
                    rec = None
                if rec:
                    results[name] = (tech, rec)
                if self._now() - started > DEADLINE_SECONDS:
                    break
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        complete = checked >= len(candidates)
        if checked and errors / checked > MAX_ERROR_RATE:
            raise CollectorError("dns resolver unreliable")

        out = Findings(complete=complete)
        for name, (tech, rec) in sorted(results.items()):
            same = bool(own_a and rec["a"] and set(rec["a"]) <= own_a) or bool(own_ns and rec["ns"] and set(rec["ns"]) <= own_ns)
            sev = _severity(rec, tech, same)
            try:
                shown = name.encode("ascii").decode("idna")
            except UnicodeError:
                shown = name
            idn = shown != name
            has = [x for x, v in (("A/AAAA", rec["a"]), ("MX", rec["mx"])) if v]
            summary = (f"{name}{f' (displays as {clean_text(shown, 80)})' if idn else ''} is registered and imitates {original} "
                       f"(technique: {tech}). Has {' and '.join(has) if has else 'DNS delegation only'}"
                       f"{'; points at your own infrastructure' if same else ''}. "
                       "Check who owns it before acting; look for a login page or mail sending that copies your brand.")
            out.append(Finding(
                source=self.name, kind="lookalike", key=name,
                title=f"Lookalike domain: {name}"[:200], summary=summary[:500], severity=sev, url=None,
                evidence={"domain": name, "displays_as": clean_text(shown, 80) if idn else None, "technique": tech,
                          "a": [clean_text(x, 45) for x in rec["a"][:5]], "mx": [clean_text(x, 80) for x in rec["mx"][:3]],
                          "ns": [clean_text(x, 80) for x in rec["ns"][:3]], "same_infrastructure": same},
            ))
        return out
