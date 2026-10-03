"""Outbound HTTPS to user-supplied URLs (webhooks) with DNS pinning.

The hostname is resolved ONCE, every address is checked to be public, and the connection is
made to that exact address. TLS still validates the certificate against the original
hostname (SNI + hostname check), and the Host header is the original hostname. This closes the
DNS-rebinding gap between "validate the URL" and "connect to it".
"""
import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter


def resolve_public_ips(url: str) -> Tuple[str, int, List[str]]:
    """Return (hostname, port, [public ip strings]) or raise ValueError."""
    u = urlparse((url or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise ValueError("Webhook URL must be https")
    port = u.port or 443
    try:
        infos = socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("Webhook host does not resolve")
    ips: List[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # is_global also rejects ranges the individual flags miss, e.g. carrier-grade NAT 100.64.0.0/10
        if not ip.is_global or ip.is_multicast:
            raise ValueError("Webhook host resolves to a non-public address")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise ValueError("Webhook host does not resolve")
    return u.hostname, port, ips


class _PinnedAdapter(HTTPAdapter):
    """Connect to an IP but present/verify the original hostname for TLS."""

    def __init__(self, hostname: str, **kw):
        self._hostname = hostname
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["server_hostname"] = self._hostname
        kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)


def pinned_post(url: str, body: bytes, headers: dict, *, timeout, resolver=resolve_public_ips,
                verify=True):
    """POST to `url`, connecting only to freshly resolved public addresses. No redirects."""
    hostname, port, ips = resolver(url)
    u = urlparse(url.strip())
    host_header = hostname if port == 443 else f"{hostname}:{port}"
    last_exc: Exception = requests.exceptions.ConnectionError("no address reachable")
    for ip in ips:
        netloc = f"[{ip}]" if ":" in ip else ip
        if port != 443:
            netloc += f":{port}"
        target = urlunparse(u._replace(netloc=netloc))
        sess = requests.Session()
        sess.mount("https://", _PinnedAdapter(hostname))
        try:
            return sess.post(target, data=body, headers={**headers, "Host": host_header},
                             timeout=timeout, allow_redirects=False, verify=verify)
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
            if isinstance(e, requests.exceptions.SSLError):
                raise
            last_exc = e
        finally:
            sess.close()
    raise last_exc
