"""Normalized scan snapshots.

A snapshot is the comparable, point-in-time view of one scan: assets with their ports,
technologies and discovered paths, plus the findings, plus a COVERAGE map saying which sections
the scan can actually vouch for. The diff engine only compares what both scans covered, so a
stage that crashed or was skipped never looks like "everything disappeared".

Pure functions only (no database, no I/O) so every rule is unit-testable.
"""
import hashlib
import json
from typing import Dict, List, Optional

from backend.scan_profiles import get_profile
from backend.tech_utils import clean_technologies

SCHEMA_VERSION = 1

# coverage levels: "full" = additions AND removals are trustworthy; "additive" = only additions
# (e.g. directory discovery that hit its time limit); None = the section says nothing.
FULL, ADDITIVE = "full", "additive"


def _ok(status) -> bool:
    return str(status or "").startswith("ok")


def compute_coverage(profile_name: str, module_results: Dict) -> Dict:
    """What this scan can vouch for, from the profile and the per-stage results."""
    prof = get_profile(profile_name)
    mr = module_results or {}

    dns = str(mr.get("dns", ""))
    sub = str(mr.get("subfinder", ""))
    discovery = dns.startswith("resolved") or (dns == "ok" and sub == "ok")

    dirs = str(mr.get("dirbuster", ""))
    if not prof.run_dirbuster or "dirbuster" not in mr:
        paths = None
    elif _ok(dirs):
        paths = FULL
    elif dirs.startswith("partial"):
        paths = ADDITIVE
    else:
        paths = None

    def lvl(ok):
        return FULL if ok else None

    return {
        "assets": lvl(discovery),
        "ports": lvl(_ok(mr.get("portscan"))),
        "http": lvl(_ok(mr.get("httpprobe"))),
        "technologies": lvl(prof.run_whatweb and _ok(mr.get("whatweb"))),
        "paths": paths,
        "findings_web": lvl(prof.run_nuclei and _ok(mr.get("vuln"))),
        "findings_network": lvl(prof.run_nuclei_network and _ok(mr.get("nuclei_network"))),
        "findings_cve": lvl(prof.run_cve_match and _ok(mr.get("cve_match"))),
    }


def finding_source(tags) -> str:
    t = {str(x).lower() for x in (tags or [])}
    if "version-match" in t:
        return "cve"
    if "network" in t:
        return "network"
    return "web"


def finding_key(f: Dict) -> str:
    return f"{f.get('template_id') or ''}|{f.get('host') or ''}"


def _port_key(p: Dict) -> str:
    return f"{p.get('port')}/{p.get('protocol') or 'tcp'}"


def build_snapshot(profile: str, module_results: Dict, assets: List[Dict],
                   paths: List[Dict], findings: List[Dict]) -> Dict:
    """assets: [{subdomain, ip, open_ports, technologies, http_status, http_title}]
    paths:  [{subdomain, path, status_code}]   findings: [{template_id, host, name, severity, ...}]"""
    snap_assets: Dict[str, Dict] = {}
    for a in assets:
        snap_assets[a["subdomain"]] = {
            "ip": a.get("ip"),
            "ports": {_port_key(p): {"service": p.get("service") or "", "product": p.get("product") or "",
                                     "version": p.get("version") or ""}
                      for p in (a.get("open_ports") or []) if isinstance(p, dict) and "port" in p},
            "technologies": sorted(clean_technologies(a.get("technologies"))),
            "http_status": a.get("http_status"),
            "http_title": (a.get("http_title") or "").strip(),
        }

    snap_paths: Dict[str, Dict] = {}
    for p in paths:
        snap_paths.setdefault(p["subdomain"], {})[p["path"]] = {"status": p.get("status_code")}

    snap_findings: Dict[str, Dict] = {}
    for f in findings:
        tags = [str(t).lower() for t in (f.get("tags") or [])]
        snap_findings[finding_key(f)] = {
            "name": f.get("name"), "severity": (f.get("severity") or "info").lower(),
            "cve": f.get("cve_id"), "host": f.get("host"), "template_id": f.get("template_id"),
            "source": finding_source(tags), "kev": "kev" in tags, "unverified": "version-match" in tags,
            "cvss": f.get("cvss_score"),
        }

    snap = {
        "schema": SCHEMA_VERSION, "profile": get_profile(profile).name,
        "coverage": compute_coverage(profile, module_results),
        "assets": snap_assets, "paths": snap_paths, "findings": snap_findings,
    }
    return snap


def snapshot_hash(snap: Dict) -> str:
    """Stable content hash; equal hashes mean nothing observable changed."""
    return hashlib.sha256(json.dumps(snap, sort_keys=True, default=str).encode()).hexdigest()
