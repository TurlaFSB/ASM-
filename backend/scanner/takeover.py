"""Subdomain takeover detection.

A subdomain takeover is possible when a name still points (CNAME) at a third-party service where the
account or resource it used to point to no longer exists, so anyone can register it and serve content
under the victim's domain. Two signals are used, both passive from the target's point of view:

1. the CNAME chain ends at a name that no longer resolves (NXDOMAIN), or
2. the CNAME points at a known provider and the provider's "nothing here" page answers.

A provider match turns signal 1 into a *candidate* (high); an unknown provider with a dangling CNAME is
reported as a medium "dangling CNAME" because it may or may not be claimable. Nothing is ever registered or
claimed: the check is DNS lookups plus at most two plain GET requests per matched name.

The provider table follows the community-maintained "can-i-take-over-xyz" project and only lists
services whose unclaimed state has a stable, documented fingerprint. Providers change their behaviour over
time, so a hit is a strong lead that should be verified by hand, not proof of exploitability.
"""
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

MAX_NAMES = 500
MAX_CNAME_HOPS = 8
BODY_LIMIT = 64 * 1024


@dataclass(frozen=True)
class Provider:
    slug: str
    name: str
    suffixes: Tuple[str, ...]            # CNAME target suffixes (with leading dot)
    markers: Tuple[str, ...] = ()        # text on the unclaimed page (case-insensitive)
    nxdomain_claimable: bool = False     # a CNAME to a missing name under this suffix can be re-registered


PROVIDERS: Tuple[Provider, ...] = (
    Provider("github-pages", "GitHub Pages", (".github.io",),
             ("there isn't a github pages site here",)),
    Provider("heroku", "Heroku", (".herokuapp.com", ".herokudns.com"), ("no such app",)),
    Provider("aws-s3", "Amazon S3 website", (".s3.amazonaws.com", ".amazonaws.com"),
             ("the specified bucket does not exist", "nosuchbucket")),
    Provider("azure", "Microsoft Azure", (".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
                                          ".trafficmanager.net", ".blob.core.windows.net",
                                          ".azureedge.net", ".azurefd.net"),
             (), nxdomain_claimable=True),
    Provider("shopify", "Shopify", (".myshopify.com",), ("sorry, this shop is currently unavailable",)),
    Provider("fastly", "Fastly", (".fastly.net",), ("fastly error: unknown domain",)),
    Provider("pantheon", "Pantheon", (".pantheonsite.io",),
             ("the gods are wise, but do not know of the site which you seek",)),
    Provider("surge", "Surge.sh", (".surge.sh",), ("project not found",)),
    Provider("bitbucket", "Bitbucket", (".bitbucket.io",), ("repository not found",)),
    Provider("ghost", "Ghost", (".ghost.io",), ("the thing you were looking for is no longer here",)),
    Provider("zendesk", "Zendesk", (".zendesk.com",), ("help center closed",)),
)


def match_provider(cname: str) -> Optional[Provider]:
    c = cname.rstrip(".").lower()
    for p in PROVIDERS:
        if any(c.endswith(s) for s in p.suffixes):
            return p
    return None


# ---------------------------------------------------------------- DNS

def resolve_cname_chain(name: str, resolver=None) -> Dict:
    """Follow CNAMEs from `name`. Returns {"chain": [...], "resolves": bool, "nxdomain": bool, "error": str|None}.

    `resolves` means the final name has an address; `nxdomain` means a hop in the chain does not exist at all
    (as opposed to existing without address records, or a transient failure, which are never findings).
    """
    res = resolver or dns.resolver.Resolver()
    res.lifetime = 5
    chain: List[str] = []
    current = name.rstrip(".").lower()
    for _ in range(MAX_CNAME_HOPS):
        try:
            answer = res.resolve(current, "CNAME")
        except dns.resolver.NoAnswer:
            break                                   # not a CNAME: the chain ends here
        except dns.resolver.NXDOMAIN:
            return {"chain": chain, "resolves": False, "nxdomain": bool(chain), "error": None}
        except (dns.exception.DNSException, OSError) as e:
            return {"chain": chain, "resolves": False, "nxdomain": False, "error": type(e).__name__}
        current = str(answer[0].target).rstrip(".").lower()
        if current in chain or current == name:
            return {"chain": chain, "resolves": False, "nxdomain": False, "error": "cname loop"}
        chain.append(current)
    if not chain:
        return {"chain": [], "resolves": True, "nxdomain": False, "error": None}
    for rtype in ("A", "AAAA"):
        try:
            res.resolve(current, rtype)
            return {"chain": chain, "resolves": True, "nxdomain": False, "error": None}
        except dns.resolver.NXDOMAIN:
            return {"chain": chain, "resolves": False, "nxdomain": True, "error": None}
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.DNSException, OSError) as e:
            return {"chain": chain, "resolves": False, "nxdomain": False, "error": type(e).__name__}
    return {"chain": chain, "resolves": False, "nxdomain": False, "error": None}   # exists, no addresses


# ---------------------------------------------------------------- unclaimed-page fingerprint

def _public_address(name: str) -> bool:
    try:
        answer = dns.resolver.resolve(name, "A", lifetime=5)
        return any(ipaddress.ip_address(str(a)).is_global for a in answer)
    except (dns.exception.DNSException, ValueError, OSError):
        return False


def fetch_body(name: str) -> str:
    """First 64 KB of http(s)://name/ (no redirects), only when the name resolves to a public address."""
    import requests
    if not _public_address(name):
        return ""
    for scheme in ("http", "https"):
        try:
            r = requests.get(f"{scheme}://{name}/", timeout=(4, 8), allow_redirects=False, stream=True,
                             verify=False, headers={"User-Agent": "asm-takeover-check/1"})  # nosec B501
            try:
                body = r.raw.read(BODY_LIMIT, decode_content=True) or b""
            finally:
                r.close()
            text = body.decode("utf-8", "replace").lower()
            if text:
                return text
        except Exception as e:  # noqa: BLE001
            logger.debug("[takeover] %s://%s not fetched: %s", scheme, name, type(e).__name__)
    return ""


# ---------------------------------------------------------------- findings

def _finding(slug: str, title: str, severity: str, description: str, host: str, matched_at: str, tags) -> Dict:
    return {"template_id": slug, "name": title, "severity": severity, "description": description,
            "matched_at": matched_at, "vuln_type": "subdomain-takeover",
            "tags": ["takeover", "posture", "dns", *tags], "host": host, "cve_id": None, "cvss_score": None}


def check_name(name: str, own_domain: str, resolver=None,
               fetch: Callable[[str], str] = fetch_body) -> Optional[Dict]:
    info = resolve_cname_chain(name, resolver)
    if not info["chain"]:
        return None
    target = info["chain"][-1]
    provider = next((p for p in (match_provider(c) for c in info["chain"]) if p), None)
    where = f"{name} -> {' -> '.join(info['chain'])}"
    own = target == own_domain or target.endswith("." + own_domain)

    if info["nxdomain"]:
        if provider:
            return _finding(
                f"takeover-{provider.slug}-nxdomain", f"Subdomain takeover candidate ({provider.name})", "high",
                f"{name} is a CNAME to {target}, which no longer exists on {provider.name}. If the resource can be "
                f"registered again by anyone, they could serve content under {name}. Verify, then remove the DNS "
                f"record or reclaim the resource. Chain: {where}.",
                name, where, [provider.slug])
        return _finding(
            "takeover-dangling-cname", "Dangling CNAME record", "low" if own else "medium",
            f"{name} is a CNAME to {target}, which does not resolve. Stale records like this are takeover risks "
            f"whenever the target name can be registered or claimed. Chain: {where}.",
            name, where, [])

    if info["resolves"] and provider and provider.markers:
        body = fetch(name)
        if body and any(m in body for m in provider.markers):
            return _finding(
                f"takeover-{provider.slug}", f"Subdomain takeover candidate ({provider.name})", "high",
                f"{name} points at {provider.name} and the service answers with its 'not claimed' page, so the "
                f"site or account the name used to serve appears to be gone. Anyone could register it and serve "
                f"content under {name}. Verify, then remove the DNS record or reclaim the resource. Chain: {where}.",
                name, where, [provider.slug])
    return None


def run_takeover_check(names: List[str], own_domain: str, max_workers: int = 16, resolver=None,
                       fetch: Callable[[str], str] = fetch_body) -> Dict:
    """Check every discovered name (live or not: dangling records are usually dead names)."""
    own_domain = own_domain.rstrip(".").lower()
    cleaned = sorted({n.strip().rstrip(".").lower() for n in names or []
                      if n and re.fullmatch(r"[a-z0-9._-]+", n.strip().rstrip(".").lower())})
    result: Dict = {"findings": [], "module_status": "ok", "checked": 0}
    if not cleaned:
        result["module_status"] = "no names provided"
        return result
    truncated = len(cleaned) > MAX_NAMES
    cleaned = cleaned[:MAX_NAMES]
    errors = 0

    def one(n):
        try:
            return check_name(n, own_domain, resolver, fetch)
        except Exception:  # noqa: BLE001
            logger.exception("[takeover] check failed for %s", n)
            return Exception
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for f in ex.map(one, cleaned):
            if f is Exception:
                errors += 1
            elif f:
                result["findings"].append(f)
    result["checked"] = len(cleaned)
    if errors:
        result["module_status"] = f"partial: {errors} of {len(cleaned)} names could not be checked"
    elif truncated:
        result["module_status"] = f"partial: only the first {MAX_NAMES} names were checked"
    return result
