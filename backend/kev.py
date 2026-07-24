"""
CISA Known Exploited Vulnerabilities (KEV) cross-reference.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Free, public JSON feed. No API key required.

A CVE appearing in this catalog means CISA has confirmed active
exploitation in the wild -- a much stronger prioritization signal
than CVSS score alone, since CVSS measures theoretical severity,
not real-world attacker interest.
"""
import requests
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cache = {"data": None, "fetched_at": None}
CACHE_TTL = timedelta(hours=12)


def _fetch_kev_catalog() -> set:
    """Fetch and cache the KEV catalog CVE IDs. Returns a set of CVE strings."""
    now = datetime.now(timezone.utc)
    if _cache["data"] is not None and _cache["fetched_at"] and (now - _cache["fetched_at"]) < CACHE_TTL:
        return _cache["data"]

    try:
        resp = requests.get(KEV_URL, timeout=15)
        resp.raise_for_status()
        catalog = resp.json()
        cve_ids = {v["cveID"].upper() for v in catalog.get("vulnerabilities", [])}
        _cache["data"] = cve_ids
        _cache["fetched_at"] = now
        logger.info(f"KEV catalog refreshed: {len(cve_ids)} known exploited CVEs")
        return cve_ids
    except Exception as e:
        logger.error(f"Failed to fetch KEV catalog: {e}")
        # Fall back to stale cache if available, else empty set
        return _cache["data"] or set()


def is_known_exploited(cve_id: str) -> bool:
    """Check if a CVE ID is in CISA's KEV catalog."""
    if not cve_id:
        return False
    kev_set = _fetch_kev_catalog()
    return cve_id.upper() in kev_set
