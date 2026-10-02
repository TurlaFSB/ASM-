"""Scan profiles: how deep a scan goes.

A profile is a frozen description of which pipeline stages run and with what limits.
Profiles are the single source of truth for scan depth: the API validates against
PROFILES, the pipeline reads the resolved ScanProfile, and the UI lists them via
GET /scans/profiles so the three never drift apart.

Time estimates are rough (measured on a small lab host) and exist for the UI only.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Optional

DEFAULT_PROFILE = "standard"


@dataclass(frozen=True)
class ScanProfile:
    name: str
    label: str
    description: str
    estimate: str                 # human hint, e.g. "~2-3 min"

    # Port scan: "100" / "1000" (nmap --top-ports) or "all" (-p-)
    nmap_ports: str = "1000"
    nmap_host_timeout: int = 600  # seconds, per host

    # Web analysis stages
    run_whatweb: bool = True
    run_screenshots: bool = True
    run_sslyze: bool = True

    # Directory discovery
    run_dirbuster: bool = True
    wordlist: str = "core"
    dirbuster_cap: int = 300      # max seconds per host

    # Vulnerability stages
    run_nuclei: bool = True
    nuclei_severity: str = "info,low,medium,high,critical"
    nuclei_timeout: int = 1800    # seconds for the whole web nuclei run
    run_nuclei_network: bool = True
    run_cve_match: bool = True

    def public(self) -> Dict:
        """Fields safe/useful to show in the UI."""
        d = asdict(self)
        return {k: d[k] for k in ("name", "label", "description", "estimate")} | {
            "stages": self.stage_names(),
        }

    def stage_names(self):
        names = ["DNS/WHOIS", f"nmap ({self.nmap_ports} ports)", "httpx"]
        if self.run_whatweb:
            names.append("whatweb")
        if self.run_dirbuster:
            names.append(f"dirs ({self.wordlist})")
        if self.run_nuclei:
            names.append("nuclei")
        if self.run_nuclei_network:
            names.append("network nuclei")
        if self.run_cve_match:
            names.append("CVE match")
        if self.run_sslyze:
            names.append("TLS")
        if self.run_screenshots:
            names.append("screenshots")
        return names


PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        label="Quick",
        description="Fast triage: top 100 ports, CVE match, network checks, high/critical web findings only.",
        estimate="~2-3 min",
        nmap_ports="100",
        nmap_host_timeout=300,
        run_whatweb=False,
        run_screenshots=False,
        run_sslyze=False,
        run_dirbuster=False,
        nuclei_severity="high,critical",
        nuclei_timeout=300,
    ),
    "standard": ScanProfile(
        name="standard",
        label="Standard",
        description="Balanced: top 1000 ports, tech fingerprinting, TLS, screenshots, curated high-signal directory discovery.",
        estimate="~8-10 min",
        nmap_ports="1000",
        nmap_host_timeout=600,
        run_dirbuster=True,
        wordlist="core",
        dirbuster_cap=300,
        nuclei_timeout=900,
    ),
    "deep": ScanProfile(
        name="deep",
        label="Deep",
        description="Exhaustive: all 65535 ports, core paths with backup extensions plus common.txt, long nuclei budget.",
        estimate="~20+ min",
        nmap_ports="all",
        nmap_host_timeout=1800,
        run_dirbuster=True,
        wordlist="medium",
        dirbuster_cap=900,
        nuclei_timeout=1800,
    ),
}


def get_profile(name: Optional[str]) -> ScanProfile:
    """Resolve a profile name; unknown/empty names fall back to the default."""
    return PROFILES.get((name or "").lower(), PROFILES[DEFAULT_PROFILE])


def is_valid_profile(name: Optional[str]) -> bool:
    return bool(name) and name.lower() in PROFILES
