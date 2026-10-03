"""Scan-target validation (single source of truth for API, scheduler and tests).

A target is either a fully-qualified domain name or an IPv4 address.
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


def classify_target(value: str) -> str:
    """Return "ip" for an IP literal, otherwise "domain"."""
    try:
        ipaddress.ip_address(value.strip())
        return "ip"
    except ValueError:
        return "domain"


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
    Note: DNS can change between check and use; callers should also disable redirects."""
    import socket
    from urllib.parse import urlparse

    u = urlparse((url or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise ValueError("Webhook URL must be https")
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("Webhook host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # is_global also rejects ranges the individual flags miss, e.g. carrier-grade NAT 100.64.0.0/10
        if not ip.is_global or ip.is_multicast:
            raise ValueError("Webhook host resolves to a non-public address")
    return url.strip()
