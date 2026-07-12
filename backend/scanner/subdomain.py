import subprocess
import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def run_subfinder(domain: str, rate_limit: int = 10) -> List[str]:
    """Run subfinder against domain. Returns list of subdomains."""
    try:
        result = subprocess.run(
            [
                "subfinder",
                "-d", domain,
                "-silent",
                "-rate-limit", str(rate_limit),
                "-json"
            ],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        subdomains = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", ""))
                except json.JSONDecodeError:
                    subdomains.append(line.strip())
        
        return list(set(filter(None, subdomains)))
    
    except subprocess.TimeoutExpired:
        logger.error(f"Subfinder timed out for domain: {domain}")
        return []
    except FileNotFoundError:
        logger.error("Subfinder not found — is it installed?")
        return []
    except Exception as e:
        logger.error(f"Subfinder failed for {domain}: {e}")
        return []


def run_amass(domain: str) -> List[str]:
    """Run amass passive enumeration. Returns list of subdomains."""
    try:
        result = subprocess.run(
            [
                "amass", "enum",
                "-passive",
                "-d", domain,
                "-timeout", "2"
            ],
            capture_output=True,
            text=True,
            timeout=150
        )
        
        subdomains = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line and domain in line:
                subdomains.append(line)
        
        return list(set(filter(None, subdomains)))
    
    except subprocess.TimeoutExpired:
        logger.error(f"Amass timed out for domain: {domain}")
        return []
    except FileNotFoundError:
        logger.error("Amass not found — is it installed?")
        return []
    except Exception as e:
        logger.error(f"Amass failed for {domain}: {e}")
        return []


def enumerate_subdomains(domain: str, rate_limit: int = 10) -> Dict:
    """
    Run all subdomain enumeration tools and merge results.
    Returns dict with subdomains list and per-tool status.
    """
    results = {
        "domain": domain,
        "subdomains": [],
        "module_status": {
            "subfinder": "ok",
            "amass": "ok"
        }
    }

    logger.info(f"Starting subdomain enumeration for {domain}")

    subfinder_results = run_subfinder(domain, rate_limit)
    if not subfinder_results:
        results["module_status"]["subfinder"] = "failed or empty"
    
    amass_results = run_amass(domain)
    if not amass_results:
        results["module_status"]["amass"] = "failed or empty"

    # Merge and deduplicate
    all_subdomains = list(set(subfinder_results + amass_results))
    results["subdomains"] = sorted(all_subdomains)
    
    logger.info(f"Found {len(all_subdomains)} subdomains for {domain}")
    return results