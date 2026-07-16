import subprocess
import subprocess
import logging
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from backend.scanner.subdomain import _run_with_process_group_cleanup

logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 10  # cap concurrent Nmap processes


def parse_nmap_xml(xml_output: str) -> List[Dict]:
    """Parse nmap XML output into structured port list."""
    ports = []

    try:
        xml_start = xml_output.find("<?xml")
        if xml_start > 0:
            xml_output = xml_output[xml_start:]

        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            for port in host.findall("ports/port"):

                state = port.find("state")
                service = port.find("service")

                if state is not None and state.get("state") == "open":
                    ports.append(
                        {
                            "port": int(port.get("portid")),
                            "protocol": port.get("protocol"),
                            "service": service.get("name") if service is not None else "unknown",
                            "version": service.get("version", "") if service is not None else "",
                            "product": service.get("product", "") if service is not None else "",
                        }
                    )

    except ET.ParseError as e:
        logger.error(f"Failed to parse Nmap XML: {e}")

    return ports


def scan_ports(host: str, rate_limit: int = 100) -> Dict:
    """
    Run Nmap against a single host.
    """

    result = {
        "host": host,
        "ports": [],
        "module_status": "ok",
    }

    start = time.time()

    try:
        nmap_result = _run_with_process_group_cleanup(
            [
                "nmap",
                "-Pn",
                "-n",
                "-sS",
                "-sV",
                "--version-light",
                "--top-ports",
                "1000",
                "--min-rate",
                str(rate_limit),
                "--open",
                "-T4",
                "--host-timeout",
                "60s",
                "-oX",
                "-",
                host,
            ],
            timeout=180,
        )

        if nmap_result.returncode != 0:
            duration = time.time() - start

            logger.error(
                f"[nmap] host={host} "
                f"status=failed "
                f"returncode={nmap_result.returncode} "
                f"duration={duration:.2f}s"
            )

            if nmap_result.stderr:
                logger.error(nmap_result.stderr.strip())

            result["module_status"] = "failed"
            return result

        result["ports"] = parse_nmap_xml(nmap_result.stdout)

        duration = time.time() - start

        logger.info(
            f"[nmap] host={host} "
            f"status=ok "
            f"ports={len(result['ports'])} "
            f"duration={duration:.2f}s"
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start

        logger.error(
            f"[nmap] host={host} "
            f"status=timeout "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = "timeout"

    except FileNotFoundError:
        logger.error("[nmap] tool_not_found")
        result["module_status"] = "tool_not_found"

    except Exception as e:
        duration = time.time() - start

        logger.error(
            f"[nmap] host={host} "
            f"status=failed "
            f"error={e} "
            f"duration={duration:.2f}s"
        )

        result["module_status"] = f"failed: {e}"

    return result


def scan_multiple_hosts(hosts: List[Dict], rate_limit: int = 100) -> Dict:
    """
    Scan all live hosts concurrently.
    """

    results = {
        "hosts": [],
        "module_status": "ok",
        "failed_hosts": [],
    }

    if not hosts:
        return results

    # Deduplicate hosts
    seen = set()
    hosts = [
        h for h in hosts
        if not (
            h["subdomain"] in seen
            or seen.add(h["subdomain"])
        )
    ]

    overall_start = time.time()

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

                results["failed_hosts"].append(
                    {
                        "subdomain": host,
                        "reason": str(e),
                    }
                )

                continue

            if scan["module_status"] == "ok":

                results["hosts"].append(
                    {
                        "subdomain": host,
                        "ip": host_data["ip"],
                        "ports": scan["ports"],
                    }
                )

            else:

                results["failed_hosts"].append(
                    {
                        "subdomain": host,
                        "reason": scan["module_status"],
                    }
                )

    if results["failed_hosts"]:
        results["module_status"] = "partial"

    logger.info(
        f"[nmap] scanned={len(results['hosts'])} "
        f"failed={len(results['failed_hosts'])} "
        f"duration={time.time() - overall_start:.2f}s"
    )

    return results