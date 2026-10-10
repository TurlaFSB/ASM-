"""Scan-target validation (single source of truth for API, scheduler and tests).

A target is a fully-qualified domain name, an IPv4 address, or an IPv4 range in CIDR notation
(at most ``ASM_MAX_CIDR_HOSTS`` addresses, default 256).
Private/internal addresses and internal hostnames (``.local`` etc.) are only
accepted when ``ASM_ALLOW_PRIVATE_TARGETS=true`` (lab / internal-network use).
Loopback, link-local (cloud metadata 169.254.x), multicast, unspecified,
reserved and IPv6 literals are always rejected.
"""
import ipaddress
import os
import re

DOMAIN_REGEX = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$"
)
INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home")
INTERNAL_LABEL_REGEX = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$")


def private_targets_allowed() -> bool:
    return os.getenv("ASM_ALLOW_PRIVATE_TARGETS", "false").strip().lower() in ("1", "true", "yes")


# Ranges that must never be part of a scan range, whatever the settings.
_FORBIDDEN_NETS = [ipaddress.ip_network(n) for n in
                   ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]
_HARD_MAX_CIDR_HOSTS = 1024


def max_cidr_hosts() -> int:
    """Largest range a single target may cover (default 256, i.e. a /24; never above 1024)."""
    try:
        n = int(os.getenv("ASM_MAX_CIDR_HOSTS", "256"))
    except ValueError:
        n = 256
    return max(1, min(n, _HARD_MAX_CIDR_HOSTS))


def is_cidr(value: str) -> bool:
    return "/" in (value or "")


def cidr_hosts(value: str) -> list:
    """Usable host addresses of a CIDR target, as strings (network and broadcast excluded for /30 and larger)."""
    net = ipaddress.ip_network(value.strip(), strict=False)
    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    return [str(h) for h in hosts]


def classify_target(value: str) -> str:
    """Return "cidr" for a range, "ip" for an IP literal, otherwise "domain"."""
    v = value.strip()
    if is_cidr(v):
        return "cidr"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        return "domain"


def _validate_cidr(v: str) -> str:
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError("Invalid network range (example: 203.0.113.0/28)")
    if net.version != 4:
        raise ValueError("IPv6 targets are not supported")
    if net.num_addresses > max_cidr_hosts():
        raise ValueError(
            f"This range has {net.num_addresses} addresses; the limit is {max_cidr_hosts()} "
            "(set ASM_MAX_CIDR_HOSTS to change it, at most 1024). Split it into smaller ranges.")
    if any(net.overlaps(bad) for bad in _FORBIDDEN_NETS):
        raise ValueError("This address range is not allowed")
    if not private_targets_allowed():
        if any(net.overlaps(p) for p in _PRIVATE_NETS):
            raise ValueError(
                "Private ranges are disabled. Set ASM_ALLOW_PRIVATE_TARGETS=true for lab use.")
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)           # canonical form, e.g. 10.0.0.5/24 becomes 10.0.0.0/24


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24",
                  "198.18.0.0/15")]


def validate_target(value: str) -> str:
    """Normalise and validate a target. Raises ValueError with a user-safe message."""
    if value is None:
        raise ValueError("Target cannot be empty")
    v = value.strip().lower()
    if not v:
        raise ValueError("Target cannot be empty")
    if len(v) > 253:
        raise ValueError("Target is too long")
    if v.startswith("-"):
        raise ValueError("Invalid characters in target")
    if "/" in v:
        if not re.fullmatch(r"[0-9.]+/[0-9]{1,2}", v):
            raise ValueError("Invalid network range (example: 203.0.113.0/28)")
        return _validate_cidr(v)
    if not re.fullmatch(r"[a-z0-9.:\-]+", v):
        raise ValueError("Invalid characters in target")

    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.version != 4:
            raise ValueError("IPv6 targets are not supported")
        if (ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_unspecified or ip.is_reserved):
            raise ValueError("This address range is not allowed")
        if ip.is_private and not private_targets_allowed():
            raise ValueError(
                "Private IP targets are disabled. Set ASM_ALLOW_PRIVATE_TARGETS=true for lab use."
            )
        return v

    if ":" in v:
        raise ValueError("Invalid target format")
    if v.endswith(INTERNAL_SUFFIXES):
        if not private_targets_allowed():
            raise ValueError(
                "Internal hostnames are disabled. Set ASM_ALLOW_PRIVATE_TARGETS=true for lab use."
            )
        if not INTERNAL_LABEL_REGEX.match(v):
            raise ValueError("Invalid domain format (e.g. example.com or 8.8.8.8)")
        return v
    if not DOMAIN_REGEX.match(v):
        raise ValueError("Invalid domain format (e.g. example.com or 8.8.8.8)")
    return v


def validate_webhook_url(url: str) -> str:
    """Webhook destinations must be https and resolve only to public addresses
    (blocks SSRF to cloud metadata / internal services). Raises ValueError.
    Delivery itself re-resolves and pins the address (backend.safe_http), so a DNS change
    between this check and the connection cannot redirect it to an internal host."""
    from backend.safe_http import resolve_public_ips

    resolve_public_ips(url)
    return url.strip()


MAX_TAGS = 10
_TAG_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:-]{0,31}$")


def normalize_tags(values) -> list:
    """Tags are short lower-case labels (letters, digits and _ . : -), trimmed and de-duplicated, at most 10.
    Raises ValueError with a message the user can act on."""
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise ValueError("tags must be a list")
    out = []
    for raw in values:
        tag = str(raw or "").strip().lower().replace(" ", "-")
        if not tag:
            continue
        if not _TAG_RE.match(tag):
            raise ValueError(f"'{str(raw)[:40]}' is not a valid tag. Use up to 32 letters, digits, dashes, dots or colons.")
        if tag not in out:
            out.append(tag)
    if len(out) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags per target")
    return out
