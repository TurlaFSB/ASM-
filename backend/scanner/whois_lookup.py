"""
WHOIS + ASN/RDAP lookup module.
Runs against a target's domain (WHOIS) and resolved IP (ASN/RDAP via ipwhois).
Synchronous — both underlying libs are blocking I/O, called once per scan cycle.
"""
import logging
import socket
from datetime import datetime

import whois as python_whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError

logger = logging.getLogger(__name__)


def _normalize(value):
    """Flatten python-whois's inconsistent list/datetime/str fields into a JSON-safe form."""
    if isinstance(value, list):
        # take the first element if it's a list of dates/strings (common with multi-registrar responses)
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def run_domain_whois(domain: str) -> dict:
    """WHOIS lookup for a domain. Returns {} on failure — never raises, scan pipeline shouldn't die on this."""
    try:
        w = python_whois.whois(domain)
        return {
            "registrar": _normalize(w.registrar),
            "creation_date": _normalize(w.creation_date),
            "expiration_date": _normalize(w.expiration_date),
            "updated_date": _normalize(w.updated_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "org": _normalize(w.org),
            "country": _normalize(w.country),
            "emails": list(w.emails) if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {}


def run_asn_lookup(ip: str) -> dict:
    """RDAP/ASN lookup for a resolved IP. Returns {} on failure or for private/internal IPs."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country_code": result.get("asn_country_code"),
            "network_name": result.get("network", {}).get("name"),
            "network_cidr": result.get("network", {}).get("cidr"),
        }
    except IPDefinedError:
        # private/reserved IP (RFC1918, .local resolution, etc.) — expected for internal lab targets
        logger.info(f"ASN lookup skipped for {ip}: private/reserved address")
        return {}
    except ASNRegistryError as e:
        logger.warning(f"ASN lookup failed for {ip}: {e}")
        return {}
    except Exception as e:
        logger.warning(f"ASN lookup failed for {ip}: {e}")
        return {}


def run_whois_asn(domain: str, resolved_ip: str | None = None, is_internal: bool = False) -> dict:
    """
    Main entry point called from the Celery task.
    is_internal: skip domain WHOIS entirely (no point WHOIS-ing metasploitable.local)
    """
    result = {"domain_whois": {}, "asn": {}}

    if not is_internal:
        result["domain_whois"] = run_domain_whois(domain)

    ip = resolved_ip
    if not ip:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = None

    if ip:
        result["asn"] = run_asn_lookup(ip)

    return result
