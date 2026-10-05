"""Cloud storage exposure: are there public buckets/containers named after the target?

Guessing storage names is how most public-bucket exposure is found in practice, and it has one important caveat:
a bucket called `acme-backup` may belong to someone else. Every finding is therefore tagged `ownership-unverified`
(change events show it as *inferred*, never as a confirmed fact about the target) and says so.

What is checked, per candidate name and provider, with one unauthenticated GET to a fixed provider hostname:
  - Amazon S3:      https://<name>.s3.amazonaws.com/           public listing => `<ListBucketResult`
  - Google Cloud:   https://storage.googleapis.com/<name>/     public listing => `<ListBucketResult`
  - Azure Blob:     https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
                    public listing => `<EnumerationResults`

Only the existence of a public *listing* is reported. Object names are never stored and no object is ever
downloaded. Private buckets (403) are counted but are not findings. Hostnames are fixed provider endpoints and
candidate names are validated, so nothing here can be steered at an internal address.
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

SUFFIXES = ("", "-dev", "-staging", "-stage", "-test", "-prod", "-backup", "-backups", "-assets", "-static",
            "-media", "-uploads", "-data", "-logs", "-public", "-files", "-cdn", "-www", "-internal")
# Names that many unrelated organisations use: a public bucket called "example-files" says nothing about example.com.
GENERIC_LABELS = frozenset("""example test demo sample sandbox staging dev prod app apps web site sites blog shop store
    cloud data files file media image images photo photos video videos music news mail email home office team company
    group global world international service services solutions systems tech technology digital online network net
    info online portal admin api cdn static assets backup backups docs support help""".split())
AZURE_CONTAINERS = ("public", "assets", "backup", "backups", "media", "files", "uploads", "data", "$web")
BODY_LIMIT = 8192
_S3_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_REGION = re.compile(r"^[a-z0-9-]{3,30}$")


def base_label(domain: str) -> str:
    """The registrable label: acme.co.uk -> acme. Empty if there is none."""
    labels = [p for p in domain.lower().strip(".").split(".") if p]
    if len(labels) < 2:
        return ""
    # skip a second-level public suffix such as co.uk / com.au
    return labels[-3] if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "ac") \
        and len(labels[-1]) == 2 else labels[-2]


def is_generic_label(domain: str) -> bool:
    """Short or common-word labels collide with other organisations' buckets far too often to rate highly."""
    base = base_label(domain)
    return len(base) <= 4 or base in GENERIC_LABELS


def candidate_names(domain: str) -> List[str]:
    """Bucket-name guesses from the registrable label, e.g. acme.co.uk -> acme, acme-dev, ..."""
    base = base_label(domain)
    if not base:
        return []
    names = []
    for suffix in SUFFIXES:
        n = f"{base}{suffix}"
        if _S3_NAME.match(n) and n not in names:
            names.append(n)
    return names


Response = Tuple[int, Dict[str, str], str]   # status, lower-cased headers, first bytes of body


def http_get(url: str) -> Optional[Response]:
    import requests
    try:
        r = requests.get(url, timeout=(4, 8), allow_redirects=False, stream=True,
                         headers={"User-Agent": "asm-storage-check/1"})
        try:
            body = (r.raw.read(BODY_LIMIT, decode_content=True) or b"").decode("utf-8", "replace")
        finally:
            r.close()
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, body
    except Exception:  # noqa: BLE001
        return None


def _finding(provider: str, name: str, where: str, domain: str) -> Dict:
    # The name is only a guess, so this is never "high": a stranger's bucket is not the organisation's exposure.
    # Generic labels (example, test, short names) collide with other organisations constantly: informational.
    severity = "info" if is_generic_label(domain) else "medium"
    return {
        "template_id": f"cloud-storage-public-{provider.lower().split()[0]}",
        "name": f"Public {provider} listing: {name}", "severity": severity,
        "description": (f"The {provider} storage '{name}' allows anyone to list its contents without credentials. "
                        f"It is named after {domain} but ASM cannot prove it belongs to the organisation, so "
                        "confirm ownership first. If it is yours, restrict public access and review what it holds. "
                        "No object was read or stored."),
        "matched_at": where, "vuln_type": "cloud-storage-exposure",
        "tags": ["cloud-storage", "posture", "ownership-unverified", provider.lower().split()[0]],
        "host": name, "cve_id": None, "cvss_score": None,
    }


def check_s3(name: str, domain: str, get: Callable[[str], Optional[Response]]) -> Tuple[Optional[Dict], str]:
    """Returns (finding or None, state) with state in public/private/absent/unknown."""
    url = f"https://{name}.s3.amazonaws.com/"
    resp = get(url)
    if resp is None:
        return None, "unknown"
    status, headers, body = resp
    region = headers.get("x-amz-bucket-region", "")
    if status in (301, 307, 400) and _REGION.match(region) and region != "us-east-1":
        url = f"https://{name}.s3.{region}.amazonaws.com/"
        resp = get(url)
        if resp is None:
            return None, "unknown"
        status, headers, body = resp
    if status == 200 and "<ListBucketResult" in body:
        return _finding("Amazon S3", name, url, domain), "public"
    if status == 403:
        return None, "private"
    if status == 404:
        return None, "absent"
    return None, "unknown"


def check_gcs(name: str, domain: str, get: Callable[[str], Optional[Response]]) -> Tuple[Optional[Dict], str]:
    url = f"https://storage.googleapis.com/{name}/"
    resp = get(url)
    if resp is None:
        return None, "unknown"
    status, _h, body = resp
    if status == 200 and "<ListBucketResult" in body:
        return _finding("Google Cloud Storage", name, url, domain), "public"
    if status in (401, 403):
        return None, "private"
    if status == 404:
        return None, "absent"
    return None, "unknown"


def _azure_account_exists(account: str) -> bool:
    try:
        dns.resolver.resolve(f"{account}.blob.core.windows.net", "A", lifetime=5)
        return True
    except (dns.exception.DNSException, OSError):
        return False


def check_azure(name: str, domain: str, get: Callable[[str], Optional[Response]],
                exists: Callable[[str], bool] = _azure_account_exists) -> Tuple[Optional[Dict], str]:
    account = re.sub(r"[^a-z0-9]", "", name)[:24]
    if len(account) < 3 or not exists(account):
        return None, "absent"
    for container in AZURE_CONTAINERS:
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
        resp = get(url)
        if resp and resp[0] == 200 and "<EnumerationResults" in resp[2]:
            return _finding("Azure Blob Storage", f"{account}/{container}", url, domain), "public"
    return None, "private"


def run_cloud_bucket_check(domain: str, max_workers: int = 8, pause: float = 0.05,
                           get: Callable[[str], Optional[Response]] = http_get,
                           azure_exists: Callable[[str], bool] = _azure_account_exists) -> Dict:
    result: Dict = {"findings": [], "module_status": "ok", "checked": 0, "private": 0}
    names = candidate_names(domain)
    if not names:
        result["module_status"] = "no candidate names"
        return result
    jobs = [(n, p) for n in names for p in ("s3", "gcs", "azure")]
    errors = 0

    def paced(url):
        time.sleep(pause)
        return get(url)

    def one(job):
        n, p = job
        try:
            if p == "s3":
                return check_s3(n, domain, paced)
            if p == "gcs":
                return check_gcs(n, domain, paced)
            return check_azure(n, domain, paced, azure_exists)
        except Exception:  # noqa: BLE001
            logger.exception("[cloud] check failed for %s/%s", n, p)
            return None, "error"
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for finding, state in ex.map(one, jobs):
            if finding:
                result["findings"].append(finding)
            if state == "private":
                result["private"] += 1
            elif state in ("unknown", "error"):
                errors += 1
    result["checked"] = len(jobs)
    if errors > len(jobs) // 2:
        result["module_status"] = f"partial: {errors} of {len(jobs)} probes got no usable answer"
    return result
