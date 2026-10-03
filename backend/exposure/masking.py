"""Find credential-like strings in text fragments and keep ONLY a masked trace of them.

The rule: a full secret or password never leaves this module. What callers get back is the rule that
matched, a masked sample (at most 4 leading characters of long values, plus the length) and a severity.
"""
import re
from dataclasses import dataclass
from typing import List

PLACEHOLDER = re.compile(
    r"(?i)^(your|my|the|example|sample|dummy|test|changeme|change_me|replace|insert|todo|xxx+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|"
    r"%\(.*\)s|process\.env|os\.environ|getenv|null|none|undefined|password|secret|token|api_?key)"
)

# (rule, regex, group holding the secret value or 0 for whole match, severity)
_RULES = [
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), 0, "high"),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0, "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0, "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0, "high"),
    ("stripe_live_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"), 0, "high"),
]
_URI_CREDS = re.compile(r"\b[a-z][a-z0-9+.\-]{2,15}://[^\s:/@'\"<>]{1,64}:([^\s@'\"<>]{3,})@([A-Za-z0-9.\-]+)")
# Matches NAME=value where NAME contains a credential word (SECRET_KEY, db_password, AWS_SECRET_ACCESS_KEY ...)
_ASSIGN = re.compile(
    r"(?i)(?<![A-Za-z0-9])[A-Za-z0-9_.-]*?(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|api[_-]?token)"
    r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?([^\s\"'<>,;]{8,})"
)

SENSITIVE_PATH = re.compile(
    r"(?i)(^|/)(\.env[^/]*|id_rsa|id_dsa|\.pgpass|\.npmrc|\.netrc|\.htpasswd|wp-config\.php|credentials[^/]*|secrets?[^/]*|"
    r"[^/]*\.(pem|key|p12|pfx|keystore|jks))$"
)
CONFIG_PATH = re.compile(r"(?i)\.(env|ya?ml|json|toml|ini|cfg|conf|properties|xml|tf|tfvars)$")


@dataclass
class Hit:
    rule: str
    sample: str          # masked
    severity: str


def mask_value(value: str) -> str:
    """Never more than 4 leading characters, and only for long values; always the length."""
    v = value or ""
    keep = 4 if len(v) >= 20 else 2 if len(v) >= 10 else 0
    return f"{v[:keep]}***({len(v)})"


def scan_fragment(fragment: str, domain: str = "") -> List[Hit]:
    hits: List[Hit] = []
    text = fragment or ""
    for rule, rx, grp, sev in _RULES:
        for m in rx.finditer(text):
            hits.append(Hit(rule, mask_value(m.group(grp)) if rule != "private_key_block" else "(key block)", sev))
    for m in _URI_CREDS.finditer(text):
        pw, host = m.group(1), m.group(2).lower()
        if PLACEHOLDER.match(pw):
            continue
        ours = bool(domain) and (host == domain.lower() or host.endswith("." + domain.lower()))
        hits.append(Hit("uri_credentials", mask_value(pw), "high" if ours else "medium"))
    for m in _ASSIGN.finditer(text):
        val = m.group(2)
        if PLACEHOLDER.match(val):
            continue
        hits.append(Hit(f"assignment:{m.group(1).lower()}", mask_value(val), "medium"))
    # one entry per (rule, sample), bounded
    seen, out = set(), []
    for h in hits:
        k = (h.rule, h.sample)
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out[:10]


def path_severity(path: str) -> str:
    if SENSITIVE_PATH.search(path or ""):
        return "medium"
    if CONFIG_PATH.search(path or ""):
        return "low"
    return "info"
