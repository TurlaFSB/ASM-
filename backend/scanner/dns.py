import socket
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def resolve_host(subdomain: str) -> Dict:
    """Resolve a single subdomain to IP. Returns dict with result."""
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip, "alive": True}
    except socket.gaierror:
        return {"subdomain": subdomain, "ip": None, "alive": False}
    except Exception as e:
        logger.error(f"DNS resolution failed for {subdomain}: {e}")
        return {"subdomain": subdomain, "ip": None, "alive": False}


def resolve_subdomains(subdomains: List[str], max_workers: int = 20) -> Dict:
    """
    Resolve all subdomains concurrently.
    Returns dict with live hosts and dead hosts.
    """
    results = {
        "live": [],
        "dead": [],
        "total": len(subdomains),
        "module_status": "ok"
    }

    if not subdomains:
        results["module_status"] = "no subdomains to resolve"
        return results

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(resolve_host, subdomain): subdomain
                for subdomain in subdomains
            }

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=10)
                    if result["alive"]:
                        results["live"].append(result)
                    else:
                        results["dead"].append(result["subdomain"])
                except Exception as e:
                    subdomain = futures[future]
                    logger.error(f"DNS future failed for {subdomain}: {e}")
                    results["dead"].append(subdomain)

    except Exception as e:
        logger.error(f"DNS resolution pool failed: {e}")
        results["module_status"] = f"failed: {e}"

    logger.info(f"DNS resolution: {len(results['live'])} live, {len(results['dead'])} dead")
    return results