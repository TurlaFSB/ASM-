"""Collector interface, shared errors and input hygiene for data from third-party sources."""
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")
INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localhost", ".test", ".example")
CC_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "nic", "mil", "gen", "res"}
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


class CollectorError(Exception):
    """A source failed in a way worth showing. `label` is short and never contains a URL or token."""

    def __init__(self, label: str):
        super().__init__(label)
        self.label = label


class NotApplicable(CollectorError):
    """The source cannot work for this kind of target (for example an IP address). Not a failure."""


class Findings(list):
    """A list of findings plus whether the source looked at EVERYTHING it meant to. An incomplete run must
    not be used to conclude that older findings have disappeared."""

    def __init__(self, items=(), complete: bool = True):
        super().__init__(items)
        self.complete = complete


class RateLimited(CollectorError):
    def __init__(self, retry_after: Optional[int] = None):
        super().__init__("rate limited")
        self.retry_after = retry_after


def registrable_parts(domain: str) -> Optional[Tuple[str, str]]:
    """('acme', 'co.uk') for www.acme.co.uk; None for IPs, internal names and single labels."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d or "/" in d or d.endswith(INTERNAL_SUFFIXES) or "." not in d:
        return None
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    labels = d.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in CC_SECOND_LEVEL:
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def require_public_domain(domain: str) -> None:
    """Every exposure source looks for a domain on the public internet (public code, breach records, listings,
    DNS look-alikes). An IP address or an internal name has nothing to find there, and searching for it would only
    produce unrelated matches, so such targets are skipped with a clear reason."""
    if registrable_parts(domain) is None:
        raise NotApplicable("needs a public domain name, not an IP or internal host")


def applies_to(domain: str) -> bool:
    return registrable_parts(domain) is not None


def clean_text(value, limit: int) -> str:
    """Third-party text is untrusted: drop control/bidi characters, collapse whitespace, bound the length."""
    s = _CTRL.sub("", str(value if value is not None else ""))
    s = " ".join(s.split())
    return s[:limit]


def safe_https_url(value, allowed_hosts: Optional[tuple]) -> Optional[str]:
    """Only keep evidence links that are https, carry no credentials, and (when a list is given) sit on an
    expected host. Pass allowed_hosts=None for third-party reference links (news articles): the UI must show
    the host and open them with rel="noopener noreferrer"."""
    from urllib.parse import urlparse
    try:
        u = urlparse(str(value or "").strip())
        host = (u.hostname or "").lower()
    except ValueError:
        return None
    if u.scheme != "https" or not host or u.username or u.password:
        return None
    if allowed_hosts is not None and host not in allowed_hosts:
        return None
    return u.geturl()[:500]


@dataclass
class Finding:
    source: str
    kind: str                 # secret | breach | mention
    key: str                  # stable identity within the source (repo+path, breach id, onion url ...)
    title: str
    summary: str
    severity: str
    url: Optional[str] = None
    evidence: Dict = field(default_factory=dict)


class Collector(Protocol):
    name: str
    label: str
    description: str
    min_interval_seconds: int

    def configured(self) -> bool: ...

    def collect(self, domain: str, http, sleep) -> List[Finding]: ...


def fingerprint(source: str, key: str) -> str:
    return hashlib.sha256(f"{source}|{key}".encode()).hexdigest()
