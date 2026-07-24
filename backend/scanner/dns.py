import dns.resolver
import dns.exception
import socket
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def resolve_host(subdomain: str) -> Dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(subdomain, "A")
        ip = str(answer[0])
        return {"subdomain": subdomain, "ip": ip, "alive": True}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Real DNS has no record -- fall back to the OS resolver, which
        # checks /etc/hosts (and any local nsswitch sources) before DNS.
        # This lets internal lab targets (added via /etc/hosts) resolve,
        # while public DNS remains the authoritative first path.
        try:
            ip = socket.gethostbyname(subdomain)
            logger.info(f"[dns] {subdomain} resolved via OS/hosts fallback -> {ip}")
            return {"subdomain": subdomain, "ip": ip, "alive": True}
        except socket.gaierror:
            return {"subdomain": subdomain, "ip": None, "alive": False}
    except dns.exception.Timeout:
        logger.warning(f"DNS resolution timed out for {subdomain}")
        return {"subdomain": subdomain, "ip": None, "alive": False}
    except Exception as e:
        logger.error(f"DNS resolution failed for {subdomain}: {e}")
        return {"subdomain": subdomain, "ip": None, "alive": False}


def resolve_subdomains(subdomains: List[str], max_workers: int = 20) -> Dict:
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
