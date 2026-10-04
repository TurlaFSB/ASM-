"""Email security posture of a domain: SPF, DMARC, DKIM and MTA-STS, from public DNS records only.

Spoofable mail is one of the most common real findings against a domain. Nothing is sent to the domain's
mail servers: every check is a TXT/MX lookup.

DKIM selectors cannot be enumerated, so a handful of very common ones are tried. Finding none proves nothing and
is never reported as a problem; a selector that IS found is checked for a weak key.
"""
import base64
import logging
import re
from typing import Dict, List, Optional, Set

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim",
                  "smtp", "mandrill", "mxvault", "zoho", "protonmail", "scph0", "everlytickey1")
SPF_LOOKUP_LIMIT = 10
_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists", "redirect")


def txt_records(name: str, resolver=None) -> Optional[List[str]]:
    """TXT strings of `name` (each record's chunks joined). [] if none, None on a lookup error."""
    res = resolver or dns.resolver.Resolver()
    res.lifetime = 5
    try:
        answer = res.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []          # authoritative "nothing there"; SERVFAIL and timeouts fall through to None
    except (dns.exception.DNSException, OSError):
        return None
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in answer]


def has_mx(domain: str, resolver=None) -> Optional[bool]:
    res = resolver or dns.resolver.Resolver()
    res.lifetime = 5
    try:
        answer = res.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except (dns.exception.DNSException, OSError):
        return None
    # RFC 7505 "null MX" (a single '.') says the domain sends and receives no mail
    return not (len(answer) == 1 and str(answer[0].exchange) == ".")


def _finding(slug: str, name: str, severity: str, description: str, domain: str, matched_at: str) -> Dict:
    return {"template_id": slug, "name": name, "severity": severity, "description": description,
            "matched_at": matched_at, "vuln_type": "email-security",
            "tags": ["email-security", "posture", "dns"], "host": domain, "cve_id": None, "cvss_score": None}


# ---------------------------------------------------------------- SPF

def spf_lookup_count(record: str, resolver=None, _seen: Optional[Set[str]] = None, _depth: int = 0) -> int:
    """DNS-lookup-causing terms in an SPF record, following include/redirect (bounded)."""
    seen = _seen if _seen is not None else set()
    total = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech = re.split(r"[:/=]", t, maxsplit=1)[0]
        if mech not in _LOOKUP_MECHS:          # exact name: "a" must not match "all" or "ip4"
            continue
        total += 1
        if (t.startswith("include:") or t.startswith("redirect=")) and _depth < 5:
            dom = t.split(":", 1)[-1] if t.startswith("include:") else t.split("=", 1)[1]
            if dom and dom not in seen and len(seen) < 20:
                seen.add(dom)
                inner = next((r for r in (txt_records(dom, resolver) or []) if r.lower().startswith("v=spf1")), None)
                if inner:
                    total += spf_lookup_count(inner, resolver, seen, _depth + 1)
    return total


def check_spf(domain: str, mail: bool, resolver=None) -> List[Dict]:
    recs = txt_records(domain, resolver)
    if recs is None:
        return []
    spf = [r for r in recs if r.lower().startswith("v=spf1")]
    out: List[Dict] = []
    where = f"{domain} TXT"
    if not spf:
        out.append(_finding(
            "email-spf-missing", "No SPF record", "medium" if mail else "low",
            f"{domain} publishes no SPF record, so receiving servers cannot tell which hosts may send mail for it. "
            + ("Anyone can spoof mail from this domain more easily." if mail else
               "The domain has no MX records; publish 'v=spf1 -all' to state that it sends no mail."),
            domain, where))
        return out
    if len(spf) > 1:
        out.append(_finding("email-spf-multiple", "Multiple SPF records", "medium",
                            f"{domain} has {len(spf)} SPF records. Receivers treat this as a permanent error and "
                            "ignore SPF, which leaves the domain unprotected. Merge them into one record.",
                            domain, where))
    record = spf[0]
    m = re.search(r"(?:^|\s)([+\-~?]?)all\b", record.lower())
    qualifier = m.group(1) if m else None
    if m is None and "redirect=" not in record.lower():
        out.append(_finding("email-spf-no-all", "SPF record has no 'all' mechanism", "low",
                            "The record does not end with an 'all' term, so unlisted senders get a neutral "
                            "result. End it with '-all' (or '~all' while rolling out).", domain, record))
    elif qualifier in ("+", ""):
        out.append(_finding("email-spf-allow-all", "SPF allows any sender (+all)", "high",
                            "The record ends in '+all' (or a bare 'all'), which authorises every server on the "
                            "internet to send mail as this domain. It provides no protection at all.",
                            domain, record))
    elif qualifier == "?":
        out.append(_finding("email-spf-neutral", "SPF record is neutral (?all)", "medium",
                            "'?all' tells receivers not to judge unlisted senders, so spoofed mail is not "
                            "flagged. Use '-all' or '~all'.", domain, record))
    elif qualifier == "~":
        out.append(_finding("email-spf-softfail", "SPF uses softfail (~all)", "info",
                            "'~all' marks unlisted senders as suspicious rather than rejecting them. It is "
                            "common during rollout; move to '-all' once all legitimate senders are listed.",
                            domain, record))
    if re.search(r"(?:^|\s)[+\-~?]?ptr\b", record.lower()):
        out.append(_finding("email-spf-ptr", "SPF uses the deprecated 'ptr' mechanism", "low",
                            "RFC 7208 discourages 'ptr': it is slow and unreliable. Replace it with ip4/ip6 or "
                            "include terms.", domain, record))
    lookups = spf_lookup_count(record, resolver)
    if lookups > SPF_LOOKUP_LIMIT:
        out.append(_finding("email-spf-too-many-lookups", "SPF exceeds the 10 DNS lookup limit", "medium",
                            f"The record causes about {lookups} DNS lookups (limit {SPF_LOOKUP_LIMIT}). Receivers "
                            "return a permanent error and SPF stops protecting the domain. Flatten or trim "
                            "include terms.", domain, record))
    return out


# ---------------------------------------------------------------- DMARC

def _tags(record: str) -> Dict[str, str]:
    out = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip()
    return out


def check_dmarc(domain: str, mail: bool, resolver=None) -> List[Dict]:
    recs = txt_records(f"_dmarc.{domain}", resolver)
    if recs is None:
        return []
    dm = [r for r in recs if r.lower().replace(" ", "").startswith("v=dmarc1")]
    where = f"_dmarc.{domain} TXT"
    if not dm:
        return [_finding("email-dmarc-missing", "No DMARC record", "medium" if mail else "low",
                         f"{domain} publishes no DMARC policy, so receivers have no instruction on what to do with "
                         "mail that fails SPF and DKIM, and you get no reports about abuse of the domain.",
                         domain, where)]
    out: List[Dict] = []
    t = _tags(dm[0])
    policy = t.get("p", "").lower()
    if policy == "none":
        out.append(_finding("email-dmarc-monitor-only", "DMARC policy is monitor-only (p=none)", "low",
                            "p=none collects reports but does not stop spoofed mail. Once reports show that all "
                            "legitimate senders pass, move to p=quarantine and then p=reject.", domain, dm[0]))
    elif policy not in ("quarantine", "reject"):
        out.append(_finding("email-dmarc-invalid", "DMARC record has no valid policy", "medium",
                            "The record has no usable p= tag, so receivers ignore it.", domain, dm[0]))
    pct = t.get("pct")
    if policy in ("quarantine", "reject") and pct and pct.isdigit() and int(pct) < 100:
        out.append(_finding("email-dmarc-partial", f"DMARC applies to only {pct}% of mail", "low",
                            "pct below 100 leaves part of spoofed mail unaffected. Raise it to 100 once rollout "
                            "is verified.", domain, dm[0]))
    sp = t.get("sp", "").lower()
    if policy in ("quarantine", "reject") and sp == "none":
        out.append(_finding("email-dmarc-subdomain-none", "DMARC subdomain policy is none (sp=none)", "low",
                            "Subdomains are exempt from enforcement, so mail can still be spoofed from "
                            "any subdomain.", domain, dm[0]))
    if "rua" not in t:
        out.append(_finding("email-dmarc-no-reports", "DMARC has no aggregate report address (rua)", "info",
                            "Without rua you receive no reports on who sends mail as your domain, which makes "
                            "tightening the policy a guess.", domain, dm[0]))
    return out


# ---------------------------------------------------------------- DKIM

def _rsa_bits(p_b64: str) -> Optional[int]:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(base64.b64decode(p_b64 + "=" * (-len(p_b64) % 4)))
        return key.key_size if isinstance(key, rsa.RSAPublicKey) else None
    except Exception:  # noqa: BLE001
        return None


def check_dkim(domain: str, resolver=None) -> Dict:
    """Probe common selectors. Returns {"findings": [...], "selectors": [found selector names]}."""
    findings: List[Dict] = []
    found: List[str] = []
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        for rec in txt_records(name, resolver) or []:
            tags = _tags(rec)
            if "p" not in tags and not rec.lower().startswith("v=dkim1"):
                continue
            found.append(sel)
            p = tags.get("p", "").replace(" ", "")
            if not p:
                continue                                    # revoked key: intentional
            bits = _rsa_bits(p)
            if bits is not None and bits < 1024:
                findings.append(_finding(
                    "email-dkim-weak-key", f"DKIM key is only {bits} bits (selector {sel})", "high",
                    f"The DKIM key at {name} is a {bits}-bit RSA key, which can be factored. Rotate to 2048 bits.",
                    domain, name))
            elif bits == 1024:
                findings.append(_finding(
                    "email-dkim-1024-key", f"DKIM key is 1024 bits (selector {sel})", "low",
                    f"The DKIM key at {name} is a 1024-bit RSA key. 2048 bits is the current recommendation.",
                    domain, name))
            break
    return {"findings": findings, "selectors": found}


# ---------------------------------------------------------------- MTA-STS

def check_mta_sts(domain: str, mail: bool, resolver=None) -> List[Dict]:
    if not mail:
        return []
    recs = txt_records(f"_mta-sts.{domain}", resolver)
    if recs is None or any(r.lower().startswith("v=stsv1") for r in recs):
        return []
    return [_finding("email-mta-sts-missing", "No MTA-STS policy", "info",
                     "MTA-STS makes sending servers require TLS when delivering mail to this domain, which "
                     "blocks downgrade attacks. It is optional but recommended for domains that receive mail.",
                     domain, f"_mta-sts.{domain} TXT")]


# ---------------------------------------------------------------- entry point

def run_email_security(domain: str, resolver=None) -> Dict:
    domain = (domain or "").strip().rstrip(".").lower()
    result: Dict = {"findings": [], "module_status": "ok", "dkim_selectors": []}
    if not domain:
        result["module_status"] = "no domain provided"
        return result
    mail = has_mx(domain, resolver)
    if mail is None:
        result["module_status"] = "failed: DNS lookup error"
        return result
    findings: List[Dict] = []
    findings += check_spf(domain, mail, resolver)
    findings += check_dmarc(domain, mail, resolver)
    if mail:
        dk = check_dkim(domain, resolver)
        findings += dk["findings"]
        result["dkim_selectors"] = dk["selectors"]
    findings += check_mta_sts(domain, mail, resolver)
    result["findings"] = findings
    result["has_mx"] = mail
    return result
