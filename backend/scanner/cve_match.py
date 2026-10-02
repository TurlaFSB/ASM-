"""Service-version -> CVE correlation (NVD).

nmap -sV gives product/version and CPE identifiers for each open service. We look the CPE up
in the NVD CVE API (free, optional NVD_API_KEY raises the rate limit) and emit findings in the
same shape as nuclei findings so risk scoring, KEV and the UI treat them uniformly.

IMPORTANT: these are *version matches*, not confirmed vulnerabilities. Distros (e.g. Ubuntu)
backport fixes without changing the version string, so findings are tagged "unverified" and
named "[version match]". Treat them as leads to verify, not proof.
"""
import json
import logging
import os
import re
import time
from typing import Callable, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 24 * 3600


def cpe22_to_23(cpe: str) -> Optional[str]:
    """nmap emits CPE 2.2 URIs (cpe:/a:vendor:product:version); NVD wants 2.3 names.
    Returns None when there is no version (a version-less CPE would match every CVE)."""
    if not cpe or not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    part, vendor, product, version = parts[:4]
    if part not in ("a", "o"):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


_BUILD_SUFFIX = re.compile(r"\.v\d{8}$|\.(?:final|release|ga)$", re.IGNORECASE)


def cpe_candidates(cpe23: str) -> List[str]:
    """Exact CPE first, then a normalised variant. nmap reports build-qualified versions
    (Jetty '8.1.7.v20120910') but NVD indexes the base version ('8.1.7')."""
    parts = cpe23.split(":")
    out = [cpe23]
    if len(parts) > 5:
        base = _BUILD_SUFFIX.sub("", parts[5])
        if base != parts[5]:
            out.append(":".join(parts[:5] + [base] + parts[6:]))
    return out


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _best_cvss(metrics: Dict) -> Optional[float]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def parse_nvd(payload: Dict) -> List[Dict]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({
            "cve_id": cid,
            "cvss": _best_cvss(cve.get("metrics", {})),
            "description": desc,
            "kev": bool(cve.get("cisaExploitAdd")),
        })
    return out


def _lookup(cpe23: str, session, cache, api_key: Optional[str], sleep: Callable, last_call: List[float]):
    """Return (cve_list, from_cache). Raises on HTTP failure."""
    ckey = f"nvd:{cpe23}"
    if cache is not None:
        try:
            hit = cache.get(ckey)
            if hit:
                return json.loads(hit), True
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[cve_match] cache read failed: {e}")
    # NVD limits: 5 req/30s without a key, 50 with one.
    gap = 0.7 if api_key else 6.5
    wait = gap - (time.time() - last_call[0])
    if wait > 0:
        sleep(wait)
    headers = {"apiKey": api_key} if api_key else {}
    resp = session.get(NVD_URL, params={"cpeName": cpe23, "noRejected": ""}, headers=headers, timeout=30)
    last_call[0] = time.time()
    resp.raise_for_status()
    cves = parse_nvd(resp.json())
    if cache is not None:
        try:
            cache.setex(ckey, CACHE_TTL_SECONDS, json.dumps(cves))
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[cve_match] cache write failed: {e}")
    return cves, False


def run_cve_match(port_hosts: List[Dict], min_cvss: Optional[float] = None, max_per_service: int = 15,
                  session=None, cache=None, api_key: Optional[str] = None,
                  sleep: Callable = time.sleep, budget_seconds: int = 240) -> Dict:
    min_cvss = float(os.getenv("CVE_MIN_CVSS", "7.0")) if min_cvss is None else min_cvss
    api_key = api_key if api_key is not None else (os.getenv("NVD_API_KEY") or None)
    session = session or requests.Session()
    result = {"findings": [], "module_status": "ok", "services_checked": 0}
    started = time.time()
    last_call = [0.0]
    errors = 0
    skipped_budget = 0
    seen = set()

    for h in port_hosts:
        for p in h.get("ports", []):
            for cpe in (p.get("cpe") or []):
                cpe23 = cpe22_to_23(cpe)
                key = (h["subdomain"], p.get("port"), cpe23)
                if not cpe23 or key in seen:
                    continue
                seen.add(key)
                if time.time() - started > budget_seconds:
                    skipped_budget += 1
                    continue
                try:
                    cves = []
                    for cand in cpe_candidates(cpe23):
                        cves, _ = _lookup(cand, session, cache, api_key, sleep, last_call)
                        if cves:
                            break
                except Exception as e:  # noqa: BLE001
                    errors += 1
                    logger.warning(f"[cve_match] lookup failed for {cpe23}: {e}")
                    continue
                result["services_checked"] += 1
                label = " ".join(x for x in (p.get("product"), p.get("version")) if x) or cpe23
                relevant = [c for c in cves if (c["cvss"] or 0) >= min_cvss]
                relevant.sort(key=lambda c: (c["kev"], c["cvss"] or 0), reverse=True)
                for c in relevant[:max_per_service]:
                    tags = ["version-match", "unverified", "nvd", "cve"] + (["kev"] if c["kev"] else [])
                    result["findings"].append({
                        "host": h["subdomain"],
                        "template_id": f"nvd-{c['cve_id']}",
                        "name": f"[version match] {label}: {c['cve_id']}",
                        "severity": severity_from_cvss(c["cvss"]),
                        "description": (c["description"] or "")[:1500]
                                       + f"\n\nMatched by service version ({cpe23}). Unverified: "
                                         "vendor backports may have fixed this without a version change.",
                        "matched_at": f"{h['subdomain']}:{p.get('port')}",
                        "type": "version-match",
                        "tags": tags,
                        "cvss_score": c["cvss"],
                        "cve_id": c["cve_id"],
                    })

    if errors or skipped_budget:
        result["module_status"] = (f"partial ({errors} lookup errors, {skipped_budget} skipped over time budget)"
                                   if result["services_checked"] else f"failed: {errors} lookup errors")
    elif result["services_checked"] == 0:
        result["module_status"] = "no services with version info"
    logger.info(f"[cve_match] services={result['services_checked']} findings={len(result['findings'])} "
                f"status={result['module_status']} duration={time.time()-started:.1f}s")
    return result
