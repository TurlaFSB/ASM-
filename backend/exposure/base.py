"""Collector interface, shared errors and input hygiene for data from third-party sources."""
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol

SEVERITIES = ("critical", "high", "medium", "low", "info")
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
