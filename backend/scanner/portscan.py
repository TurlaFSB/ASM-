import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 5  # cap concurrent Nmap processes to avoid overwhelming the host/network


def parse_nmap_xml(xml_output: str) -> List[Dict]:
    """Parse nmap XML output into structured port list."""
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            for port in host.findall("ports/port"):
                state = port.find("state")
                service = port.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "service": service.get("name") if service is not None else "unknown",
                        "version": service.get("version", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else ""
                    })
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
    return ports


def scan_ports(host: str, rate_limit: int = 10) -> Dict:
    """
    Run nmap against a single host.
    Returns structured port data with module status.
    """
    result = {
        "host": host,
        "ports": [],
        "module_status": "ok"
    }

    try:
        nmap_result = subprocess.run(
            [
                "nmap",
                "-sV",                          # service version detection
                "--top-ports", "1000",          # top 1000 ports
                "--max-rate", str(rate_limit),  # rate limiting
                "--open",                       # only show open ports
                "-T4",                          # timing template
                "--host-timeout", "120s",       # per host timeout
                "-oX", "-",                     # XML output to stdout
                host
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if nmap_result.returncode != 0:
            logger.error(f"Nmap failed for {host}: {nmap_result.stderr}")
            result["module_status"] = "failed"
            return result

        result["ports"] = parse_nmap_xml(nmap_result.stdout)
        logger.info(f"Nmap found {len(result['ports'])} open ports on {host}")

    except subprocess.TimeoutExpired:
        logger.error(f"Nmap timed out for {host}")
        result["module_status"] = "timeout"
    except FileNotFoundError:
        logger.error("Nmap not found")
        result["module_status"] = "tool_not_found"
    except Exception as e:
        logger.error(f"Nmap failed for {host}: {e}")
        result["module_status"] = f"failed: {e}"

    return result


def scan_multiple_hosts(hosts: List[Dict], rate_limit: int = 10) -> Dict:
    """
    Scan all live hosts from DNS resolution results, concurrently.

    Nmap subprocess calls are I/O-bound (waiting on network responses),
    so a thread pool gives real wall-clock speedup without needing
    async rewrites. Concurrency is capped at MAX_CONCURRENT_SCANS to
    avoid overwhelming the local network stack or triggering aggressive
    rate-limiting/WAF blocks on the target -- this is a deliberate
    trade-off between speed and stealth/politeness, same consideration
    real engagement tooling has to make.
    """
    results = {
        "hosts": [],
        "module_status": "ok",
        "failed_hosts": []
    }

    if not hosts:
        return results

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS) as executor:
        future_to_host = {
            executor.submit(scan_ports, h["subdomain"], rate_limit): h
            for h in hosts
        }
        for future in as_completed(future_to_host):
            host_data = future_to_host[future]
            host = host_data["subdomain"]
            try:
                scan = future.result()
            except Exception as e:
                logger.error(f"Unexpected error scanning {host}: {e}")
                results["failed_hosts"].append({"subdomain": host, "reason": str(e)})
                continue

            if scan["module_status"] == "ok":
                results["hosts"].append({
                    "subdomain": host,
                    "ip": host_data["ip"],
                    "ports": scan["ports"]
                })
            else:
                results["failed_hosts"].append({
                    "subdomain": host,
                    "reason": scan["module_status"]
                })

    if results["failed_hosts"]:
        results["module_status"] = "partial"

    return results
