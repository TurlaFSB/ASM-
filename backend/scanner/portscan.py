import subprocess
import logging
import time
import defusedxml.ElementTree as ET   # nmap output carries text from scanned hosts: parse it defensively
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
                            "extrainfo": service.get("extrainfo", "") if service is not None else "",
                            "cpe": [c.text for c in service.findall("cpe") if c.text] if service is not None else [],
                        }
                    )

    except ET.ParseError as e:
        logger.error(f"Failed to parse Nmap XML: {e}")

    return ports




# Web, admin, database and dev-server ports that are NOT in nmap's top 1000 but are common on real
# attack surfaces (found by a Deep scan only, otherwise).
EXTRA_PORTS = (3333, 4000, 4848, 5601, 6066, 7001, 7077, 8001, 8008, 8090, 8161, 8300, 8500, 8834,
               8880, 8888, 9000, 9001, 9042, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 10250,
               15672, 27018, 50000)
NMAP_SERVICES_PATHS = ("/usr/share/nmap/nmap-services", "/usr/local/share/nmap/nmap-services")


def top_tcp_ports(n: int, services_paths=NMAP_SERVICES_PATHS) -> List[int]:
    """The n most common TCP ports according to nmap's own frequency table (what --top-ports uses)."""
    for path in services_paths:
        try:
            ranked = []
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].endswith("/tcp"):
                        try:
                            ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
                        except ValueError:
                            continue
            if len(ranked) >= n:
                ranked.sort(key=lambda t: (-t[0], t[1]))
                return [port for _, port in ranked[:n]]
        except OSError:
            continue
    return []


def _port_args(ports: str, services_paths=NMAP_SERVICES_PATHS) -> List[str]:
    """'100'/'1000' -> --top-ports N, '1000+' -> top 1000 plus EXTRA_PORTS, 'all' -> -p-.
    Anything else falls back to 1000."""
    p = str(ports).lower()
    if p == "all":
        return ["-p-"]
    if p == "1000+":
        top = top_tcp_ports(1000, services_paths)
        if top:
            return ["-p", ",".join(str(x) for x in sorted(set(top) | set(EXTRA_PORTS)))]
        logger.warning("[nmap] nmap-services not readable; falling back to --top-ports 1000")
        return ["--top-ports", "1000"]
    return ["--top-ports", p if p in ("100", "1000") else "1000"]


def build_nmap_cmd(host: str, rate_limit: int, ports: str = "1000",
                   host_timeout: int = 600, version_intensity: int = 2) -> List[str]:
    """Build the nmap command.

    rate_limit is the per-target "politeness" knob shared with the HTTP tools
    (default 10). Passing it directly as --min-rate (10 pkt/s) made a 1000-port
    scan take >100s and trip the host timeout, silently yielding 0 ports. We
    cap the rate instead (--max-rate) at a sane multiple, and give the host
    enough time for service-version detection.
    """
    max_rate = max(100, int(rate_limit) * 50)
    return [
        "nmap", "-Pn", "-n", "-sS", "-sV", "--version-intensity", str(max(0, min(9, int(version_intensity)))),
        *_port_args(ports), "--max-rate", str(max_rate),
        "--open", "-T4", "--host-timeout", f"{int(host_timeout)}s",
        "-oX", "-", host,
    ]


def scan_ports(host: str, rate_limit: int = 100, ports: str = "1000",
               host_timeout: int = 600, version_intensity: int = 2) -> Dict:
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
            build_nmap_cmd(host, rate_limit, ports, host_timeout, version_intensity),
            timeout=int(host_timeout) + 120,
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

        if "due to host timeout" in (nmap_result.stderr or ""):
            logger.error(f"[nmap] host={host} status=timeout (nmap host-timeout hit)")
            result["module_status"] = "timeout"
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


def scan_multiple_hosts(hosts: List[Dict], rate_limit: int = 100, ports: str = "1000",
                        host_timeout: int = 600, version_intensity: int = 2) -> Dict:
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
            executor.submit(scan_ports, h["subdomain"], rate_limit, ports, host_timeout, version_intensity): h
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