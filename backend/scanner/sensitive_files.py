"""Exposed sensitive files: .git, .env, backups, credentials and debug endpoints on each live web host.

Directory discovery finds paths by status code and size, which cannot tell a real exposed `.env` from a soft-404
page that answers 200 for everything. This stage requests a short list of well-known paths and only reports
one when the *content itself* proves it (file magic bytes, `ref: refs/heads/...`, `KEY=value` lines, ...), so
catch-all sites do not produce false findings.

Handling of what is found:
  - at most the first 4 KB of a response is read,
  - the content is never stored; findings carry the path and a one-line reason, no values and no filenames
    from inside an archive or repository,
  - redirects are not followed (a login redirect is not an exposure).
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

READ_LIMIT = 4096
MAX_HOSTS = 50
_SECRET_NAME = re.compile(r"(PASS(WORD)?|SECRET|TOKEN|API_?KEY|PRIVATE|DATABASE_URL|DB_URL|CREDENTIAL|AWS_)", re.I)


def _env_check(body: bytes, _headers) -> Optional[str]:
    text = body.decode("utf-8", "ignore")
    if "<html" in text[:500].lower():
        return None
    lines = [ln for ln in text.splitlines() if re.match(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]{2,}\s*=", ln)]
    if len(lines) < 2:
        return None
    names = [re.split(r"=", ln, 1)[0].replace("export", "").strip() for ln in lines]
    secrets = any(_SECRET_NAME.search(n) for n in names)
    return f"environment file with {len(lines)}+ variables" + (", including secret-looking names" if secrets else "")


def _secret_env(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return any(_SECRET_NAME.search(ln.split("=", 1)[0]) for ln in text.splitlines() if "=" in ln)


def _starts(prefix: bytes, why: str):
    return lambda body, _h: why if body.startswith(prefix) else None


def _contains(pattern: str, why: str, html_ok: bool = False):
    rx = re.compile(pattern, re.I | re.M)

    def check(body: bytes, _h) -> Optional[str]:
        text = body.decode("utf-8", "ignore")
        if not html_ok and "<html" in text[:300].lower():
            return None
        return why if rx.search(text) else None
    return check


@dataclass(frozen=True)
class Probe:
    slug: str
    path: str
    title: str
    severity: str
    check: Callable
    advice: str


_ARCHIVE = lambda body, _h: ("ZIP archive" if body.startswith(b"PK\x03\x04") else  # noqa: E731
                             "gzip archive" if body.startswith(b"\x1f\x8b") else None)
_SQL = _contains(r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "SQL database dump")

PROBES: Tuple[Probe, ...] = (
    Probe("exposed-git", "/.git/HEAD", "Exposed .git repository", "high",
          _contains(r"^ref:\s*refs/", "git HEAD file"),
          "The repository's full history, including past secrets, can usually be reconstructed from this. "
          "Block /.git on the web server and rotate any credential that was ever committed."),
    Probe("exposed-env", "/.env", "Exposed .env file", "high", _env_check,
          "Environment files usually hold database passwords and API keys. Remove it from the web root and rotate "
          "every value it contains."),
    Probe("exposed-svn", "/.svn/wc.db", "Exposed Subversion metadata", "high",
          _starts(b"SQLite format 3", "Subversion working copy database"),
          "The checkout metadata reveals source file names and can expose the code. Remove /.svn from the web root."),
    Probe("exposed-ds-store", "/.DS_Store", "Exposed .DS_Store file", "low",
          lambda b, _h: "macOS directory index" if b[4:8] == b"Bud1" else None,
          "It lists file and folder names that were in the directory. Delete it and block dotfiles."),
    Probe("exposed-htpasswd", "/.htpasswd", "Exposed .htpasswd file", "high",
          _contains(r"^[A-Za-z0-9._-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$6\$|\$5\$|[A-Za-z0-9./]{13})", "password hashes"),
          "Password hashes can be cracked offline. Move it out of the web root and rotate the passwords."),
    Probe("exposed-aws-credentials", "/.aws/credentials", "Exposed AWS credentials file", "critical",
          _contains(r"aws_access_key_id\s*=", "AWS access key entries"),
          "Revoke the keys in AWS immediately and remove the file."),
    Probe("exposed-ssh-key", "/.ssh/id_rsa", "Exposed SSH private key", "critical",
          _contains(r"-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----", "private key"),
          "Treat the key as compromised: remove it from every authorized_keys file and replace it."),
    Probe("exposed-wp-config-backup", "/wp-config.php.bak", "Exposed WordPress config backup", "critical",
          _contains(r"DB_PASSWORD", "WordPress database credentials", html_ok=True),
          "Remove the backup and rotate the database password and the salts."),
    Probe("exposed-wp-config-old", "/wp-config.php.old", "Exposed WordPress config backup", "critical",
          _contains(r"DB_PASSWORD", "WordPress database credentials", html_ok=True),
          "Remove the backup and rotate the database password and the salts."),
    Probe("exposed-wp-config-tilde", "/wp-config.php~", "Exposed WordPress config backup", "critical",
          _contains(r"DB_PASSWORD", "WordPress database credentials", html_ok=True),
          "Remove the backup and rotate the database password and the salts."),
    Probe("exposed-config-backup", "/config.php.bak", "Exposed configuration backup", "high",
          _contains(r"(password|passwd|secret|db_pass)\s*[=:'\"]", "credentials in a config file", html_ok=True),
          "Remove the backup and rotate the credentials in it."),
    Probe("exposed-backup-zip", "/backup.zip", "Exposed backup archive", "high", _ARCHIVE,
          "Archives often hold source code or data. Remove it from the web root."),
    Probe("exposed-site-zip", "/site.zip", "Exposed site archive", "high", _ARCHIVE,
          "Archives often hold source code or data. Remove it from the web root."),
    Probe("exposed-www-zip", "/www.zip", "Exposed site archive", "high", _ARCHIVE,
          "Archives often hold source code or data. Remove it from the web root."),
    Probe("exposed-backup-targz", "/backup.tar.gz", "Exposed backup archive", "high", _ARCHIVE,
          "Archives often hold source code or data. Remove it from the web root."),
    Probe("exposed-backup-sql", "/backup.sql", "Exposed database dump", "critical", _SQL,
          "A database dump holds user and business data. Remove it and treat the data as exposed."),
    Probe("exposed-db-sql", "/db.sql", "Exposed database dump", "critical", _SQL,
          "A database dump holds user and business data. Remove it and treat the data as exposed."),
    Probe("exposed-dump-sql", "/dump.sql", "Exposed database dump", "critical", _SQL,
          "A database dump holds user and business data. Remove it and treat the data as exposed."),
    Probe("exposed-phpinfo", "/phpinfo.php", "phpinfo() page exposed", "medium",
          _contains(r"PHP Version\s+\d", "phpinfo output", html_ok=True),
          "It discloses versions, paths and environment values. Remove the file."),
    Probe("exposed-server-status", "/server-status", "Apache server-status exposed", "medium",
          _contains(r"Apache Server Status for", "Apache status page", html_ok=True),
          "It shows live requests and client addresses. Restrict /server-status to localhost."),
    Probe("exposed-actuator-env", "/actuator/env", "Spring Boot actuator /env exposed", "high",
          _contains(r"\"propertySources\"", "Spring environment properties", html_ok=True),
          "The environment endpoint can leak credentials and configuration. Disable it or require authentication."),
)


Response = Tuple[int, Dict[str, str], bytes]


def http_get(url: str) -> Optional[Response]:
    import requests
    try:
        r = requests.get(url, timeout=(4, 8), allow_redirects=False, stream=True, verify=False,   # nosec B501
                         headers={"User-Agent": "asm-exposure-check/1"})
        try:
            body = r.raw.read(READ_LIMIT, decode_content=True) or b""
        finally:
            r.close()
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, body
    except Exception:  # noqa: BLE001
        return None


def base_urls(urls: List[str]) -> List[str]:
    out: List[str] = []
    for u in urls or []:
        p = urlparse(u)
        if p.scheme in ("http", "https") and p.netloc:
            b = f"{p.scheme}://{p.netloc}"
            if b not in out:
                out.append(b)
    return out


def check_host(base: str, get: Callable[[str], Optional[Response]], delay: float) -> Tuple[List[Dict], int]:
    """Returns (findings, probes that got no answer)."""
    findings: List[Dict] = []
    failed = 0
    for pr in PROBES:
        time.sleep(delay)
        resp = get(base + pr.path)
        if resp is None:
            failed += 1
            continue
        status, headers, body = resp
        if status != 200 or not body:
            continue
        why = pr.check(body, headers)
        if not why:
            continue
        sev = pr.severity
        if pr.slug == "exposed-env" and _secret_env(body):
            sev = "critical"
        findings.append({
            "template_id": pr.slug, "name": pr.title, "severity": sev,
            "description": f"{base}{pr.path} is publicly readable and looks like a {why}. {pr.advice} "
                           "ASM read only the first few KB to confirm and stored none of the content.",
            "matched_at": base + pr.path, "vuln_type": "exposed-file",
            "tags": ["exposed-file", "posture"], "host": base, "cve_id": None, "cvss_score": None,
        })
    return findings, failed


def run_sensitive_file_check(urls: List[str], rate_limit: int = 10, max_workers: int = 4,
                             get: Callable[[str], Optional[Response]] = http_get) -> Dict:
    result: Dict = {"findings": [], "module_status": "ok", "checked": 0}
    bases = base_urls(urls)
    if not bases:
        result["module_status"] = "no hosts provided"
        return result
    truncated = len(bases) > MAX_HOSTS
    bases = bases[:MAX_HOSTS]
    delay = 1.0 / max(1, rate_limit)
    failed = total = 0

    def one(b):
        try:
            return check_host(b, get, delay)
        except Exception:  # noqa: BLE001
            logger.exception("[files] check failed for %s", b)
            return [], len(PROBES)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for f, bad in ex.map(one, bases):
            result["findings"] += f
            failed += bad
            total += len(PROBES)
    result["checked"] = len(bases)
    if total and failed > total // 2:
        result["module_status"] = f"partial: {failed} of {total} requests got no answer"
    elif truncated:
        result["module_status"] = f"partial: only the first {MAX_HOSTS} hosts were checked"
    return result
