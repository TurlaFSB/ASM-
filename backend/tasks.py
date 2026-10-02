from celery import Celery
import logging
from backend.config import settings
import redis

logger = logging.getLogger(__name__)

def send_webhook_alerts(db, target_id, alerts):
    """
    POST each newly created alert to the target's configured webhook_url,
    if one is set. Never raises -- a webhook failure should never break
    the scan pipeline that's delivering it.
    """
    import requests
    from backend.models.target import Target

    from backend.validators import validate_webhook_url

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target or not target.webhook_url:
        return
    try:
        validate_webhook_url(target.webhook_url)
    except ValueError as e:
        logger.warning(f"[webhook] blocked for target {target_id}: {e}")
        return

    for alert in alerts:
        payload = {
            "alert_id": alert.id,
            "target_id": target_id,
            "target_domain": target.domain,
            "alert_type": alert.alert_type,
            "asset_subdomain": alert.asset_subdomain,
            "asset_ip": alert.asset_ip,
            "detail": alert.detail,
        }
        try:
            resp = requests.post(target.webhook_url, json=payload, timeout=5, allow_redirects=False)
            if resp.ok:
                alert.webhook_sent = True
        except requests.RequestException as e:
            logger.warning(f"[webhook] delivery failed for alert {alert.id}: {e}")

    db.commit()

celery_app = Celery(
    "asm_platform",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["backend.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "check-scheduled-scans-every-minute": {
            "task": "check_scheduled_scans",
            "schedule": 60.0,
        },
    },
)

@celery_app.task(bind=True, name="run_scan")
def run_scan(self, target_id: int, domain: str, rate_limit: int = 10, scan_id: int = None,
             wordlist: str = None, enable_dirbuster: bool = True, profile: str = None):
    """
    Full ASM pipeline task.
    Runs all scanner modules sequentially.
    Updates scan record in DB at each stage.
    """
    from backend.scanner.subdomain import enumerate_subdomains
    from backend.scanner.dns import resolve_subdomains
    from backend.scanner.portscan import scan_multiple_hosts
    from backend.scanner.whois_lookup import run_whois_asn
    from backend.scanner.httpprobe import run_httpx
    from backend.scanner.whatweb import run_whatweb
    from backend.scanner.dirbuster import run_dirbuster
    from backend.scanner.sslyze_scan import run_sslyze
    from backend.scanner.vuln import run_nuclei
    from backend.scanner.screenshot import run_eyewitness
    from backend.db import SessionLocal
    from backend.models.scan import Scan
    from backend.models.asset import Asset
    from backend.models.alert import Alert
    from backend.models.vulnerability import Vulnerability
    from backend.models.scan_asset import ScanAsset
    from backend.models.discovered_path import DiscoveredPath
    from backend.models.target import Target
    import hashlib
    import time
    import json
    from datetime import datetime, timezone

    from backend.scan_profiles import get_profile
    prof = get_profile(profile)
    wordlist = wordlist or prof.wordlist
    enable_dirbuster = bool(enable_dirbuster and prof.run_dirbuster)
    logger.info(f"[pipeline] scan_id={scan_id} target={domain} profile={prof.name}")

    redis_client = redis.Redis.from_url(settings.redis_url)
    lock_key = f"scan_lock:{target_id}"
    lock = redis_client.lock(lock_key, timeout=1800)
    have_lock = lock.acquire(blocking=False)
    if not have_lock:
        logger.warning(f"[pipeline] Scan already running for target_id={target_id}, retrying in 30s")
        raise self.retry(countdown=30, max_retries=20)

    db = SessionLocal()
    module_results = {}
    stage_timings = {}
    scan = None
    overall_start = time.time()

    try:
        # Update scan status to running
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "running"
                scan.started_at = datetime.now(timezone.utc)
                db.commit()

        stage_start = time.time()

        import ipaddress
        from backend.validators import classify_target, INTERNAL_SUFFIXES

        def _is_internal_target(d):
            return classify_target(d) == "ip" or d.lower().endswith(INTERNAL_SUFFIXES)

        internal_target = _is_internal_target(domain)

        if internal_target:
            # Raw IP or internal/lab hostname -- public subdomain discovery
            # (subfinder/amass query CT logs, passive DNS, etc.) cannot find
            # anything for a target that's never been publicly indexed.
            # Skip straight to treating the target itself as the sole live host.
            self.update_state(state="PROGRESS", meta={"stage": "subdomain_enumeration"})
            if scan:
                scan.current_stage = "subdomain_enumeration"
                db.commit()
            module_results["subfinder"] = "skipped (internal/IP target)"
            module_results["amass"] = "skipped (internal/IP target)"
            subdomains = [domain]
            stage_timings["subdomain"] = round(time.time()-stage_start,2)
            logger.info(f"[pipeline] Subdomain skipped for internal target {domain}")

            self.update_state(state="PROGRESS", meta={"stage": "dns_resolution"})
            if scan:
                scan.current_stage = "dns_resolution"
                db.commit()
            stage_start = time.time()

            try:
                ipaddress.ip_address(domain)
                resolved_ip = domain
            except ValueError:
                import socket
                try:
                    resolved_ip = socket.gethostbyname(domain)
                except socket.gaierror as e:
                    resolved_ip = None
                    logger.warning(f"[pipeline] Could not resolve internal hostname {domain}: {e}")

            if resolved_ip:
                live_hosts = [{"subdomain": domain, "ip": resolved_ip}]
                module_results["dns"] = "resolved directly (internal target)"
            else:
                live_hosts = []
                module_results["dns"] = "resolution failed"

            stage_timings["dns"] = round(time.time()-stage_start,2)
            logger.info(f"[pipeline] DNS completed in {stage_timings['dns']}s ({len(live_hosts)} live hosts)")
        else:
            # Stage 1: Subdomain enumeration
            self.update_state(state="PROGRESS", meta={"stage": "subdomain_enumeration"})
            if scan:
                scan.current_stage = "subdomain_enumeration"
                db.commit()
            subdomain_data = enumerate_subdomains(domain, rate_limit)
            module_results["subfinder"] = subdomain_data["module_status"]["subfinder"]
            module_results["amass"] = subdomain_data["module_status"]["amass"]
            subdomains = subdomain_data["subdomains"]

            stage_timings["subdomain"] = round(time.time()-stage_start,2)
            logger.info(f"[pipeline] Subdomain completed in {stage_timings['subdomain']}s ({len(subdomains)} subdomains)")

            # Stage 2: DNS resolution
            self.update_state(state="PROGRESS", meta={"stage": "dns_resolution"})
            if scan:
                scan.current_stage = "dns_resolution"
                db.commit()
            stage_start = time.time()

            dns_data = resolve_subdomains(subdomains)
            module_results["dns"] = dns_data["module_status"]
            live_hosts = dns_data["live"]

            stage_timings["dns"] = round(time.time()-stage_start,2)
            logger.info(f"[pipeline] DNS completed in {stage_timings['dns']}s ({len(live_hosts)} live hosts)")

        # Stage 2.5: WHOIS + ASN lookup
        self.update_state(state="PROGRESS", meta={"stage": "whois_asn_lookup"})
        if scan:
            scan.current_stage = "whois_asn_lookup"
            db.commit()
        stage_start = time.time()
        first_ip = next((h["ip"] for h in live_hosts if h.get("ip")), None)
        whois_result = run_whois_asn(domain, resolved_ip=first_ip, is_internal=internal_target)
        target_row = db.query(Target).filter(Target.id == target_id).first()
        if target_row:
            target_row.whois_data = whois_result
            db.commit()
        module_results["whois_asn"] = "completed" if (whois_result.get("domain_whois") or whois_result.get("asn")) else "no data"
        stage_timings["whois_asn"] = round(time.time()-stage_start,2)
        logger.info(f"[pipeline] WHOIS/ASN completed in {stage_timings['whois_asn']}s")

        # Stage 3: Port scanning
        self.update_state(state="PROGRESS", meta={"stage": "port_scanning"})
        if scan:
            scan.current_stage = "port_scanning"
            db.commit()
        stage_start = time.time()

        port_data = scan_multiple_hosts(live_hosts, rate_limit, prof.nmap_ports, prof.nmap_host_timeout)
        module_results["portscan"] = port_data["module_status"]

        stage_timings["portscan"] = round(time.time()-stage_start,2)
        logger.info(
            f"[pipeline] PortScan completed in {stage_timings['portscan']}s "
            f"({len(port_data['hosts'])} hosts scanned)"
        )

        # Stage 4: HTTP probing
        self.update_state(state="PROGRESS", meta={"stage": "http_probing"})
        if scan:
            scan.current_stage = "http_probing"
            db.commit()
        # Feed HTTPX bare hostnames -- it determines http/https itself via
        # -follow-redirects, so we don't need to force a scheme upfront.
        stage_start = time.time()

        from backend.pipeline_utils import (
            build_web_targets, tls_targets_from_urls, merge_http_info,
            pipeline_trusted_for_removals,
        )
        bare_hosts = [h["subdomain"] for h in live_hosts]
        # Probe every web-looking port nmap found (not just 80/443)
        web_targets = build_web_targets(port_data["hosts"], bare_hosts)
        http_data = run_httpx(web_targets, rate_limit)
        module_results["httpprobe"] = http_data["module_status"]

        # Use CONFIRMED live URLs (with correct scheme) from HTTPX output for
        # downstream tools, instead of the original guessed http:// list.
        # Falls back to bare hostnames only if HTTPX found nothing, so
        # nuclei/eyewitness don't get an empty target list on partial failure.
        confirmed_urls = list(dict.fromkeys(h["url"] for h in http_data["hosts"] if h.get("url")))
        # No confirmed web service -> web stages get nothing (bare hosts have no scheme
        # and would make feroxbuster/nuclei/eyewitness error out).
        host_urls = confirmed_urls

        stage_timings["httpx"] = round(time.time()-stage_start,2)
        logger.info(
            f"[pipeline] HTTPX completed in {stage_timings['httpx']}s "
            f"({len(http_data['hosts'])} live web services)"
        )

        # Stages 4.5-6: independent web-facing modules run CONCURRENTLY
        # (whatweb, directory discovery, nuclei, sslyze, screenshots). Total time becomes
        # the slowest module instead of the sum. They only read host_urls/TLS targets and
        # never touch the DB, so this is thread-safe. ASM_PARALLEL_STAGES=false disables it.
        import os as _os
        from backend.pipeline_utils import run_stages_parallel, effective_rate
        # nuclei and feroxbuster run at the same time against the same hosts: split the budget
        # so combined load stays within the configured ceiling (overloading a host makes
        # nuclei abandon it as 'unresponsive').
        n_heavy = int(enable_dirbuster) + int(prof.run_nuclei) + int(prof.run_nuclei_network)
        heavy_rate = max(1, effective_rate(rate_limit) // max(1, n_heavy))
        self.update_state(state="PROGRESS", meta={"stage": "web_analysis"})
        if scan:
            scan.current_stage = "web_analysis"
            db.commit()
        stage_start = time.time()
        from backend.scanner.cve_match import run_cve_match

        def _cve_cache():
            try:
                return redis.Redis.from_url(settings.redis_url, socket_timeout=2)
            except Exception:  # noqa: BLE001
                return None
        from backend.scanner.vuln import network_tags_from_services
        net_tags = network_tags_from_services(port_data["hosts"])
        tls_targets = tls_targets_from_urls(confirmed_urls)
        stage_results, stage_dts = run_stages_parallel(
            jobs={
                "whatweb": (lambda: run_whatweb(host_urls)) if prof.run_whatweb else None,
                "dirbuster": (lambda: run_dirbuster(host_urls, heavy_rate, wordlist, scan_id=scan_id,
                                                    max_seconds=prof.dirbuster_cap))
                             if enable_dirbuster else None,
                "nuclei": (lambda: run_nuclei(host_urls, heavy_rate, severity=prof.nuclei_severity,
                                              timeout=prof.nuclei_timeout))
                          if prof.run_nuclei else None,
                "sslyze": (lambda: run_sslyze(tls_targets)) if prof.run_sslyze else None,
                "screenshot": (lambda: run_eyewitness(host_urls)) if prof.run_screenshots else None,
                "cve_match": (lambda: run_cve_match(port_data["hosts"], cache=_cve_cache()))
                             if prof.run_cve_match else None,
                "nuclei_network": (lambda: run_nuclei(
                    sorted({h["subdomain"] for h in port_data["hosts"]}), heavy_rate, tags=net_tags,
                    # tag-targeted and fast (~40s): keep every severity so low/info exposures
                    # (anonymous FTP, open IRC, SMB signing) are not lost to the web severity filter
                    timeout=prof.nuclei_timeout))
                    if (net_tags and prof.run_nuclei_network) else None,
            },
            defaults={
                "whatweb": {"hosts": {}}, "dirbuster": {"hosts": {}},
                "nuclei": {"findings": []}, "sslyze": {"findings": []},
                "screenshot": {"screenshots": []}, "cve_match": {"findings": []},
                "nuclei_network": {"findings": []},
            },
            parallel=_os.getenv("ASM_PARALLEL_STAGES", "true").lower() != "false",
        )
        stage_timings.update(stage_dts)
        stage_timings["web_analysis_wall"] = round(time.time() - stage_start, 2)

        skipped = f"skipped (profile: {prof.name})"
        module_results["profile"] = prof.name
        whatweb_data = stage_results.get("whatweb") or {"hosts": {}, "module_status": skipped}
        module_results["whatweb"] = whatweb_data["module_status"]
        for entry in http_data["hosts"]:
            ww_result = whatweb_data["hosts"].get(entry.get("url", ""))
            if ww_result:
                merged = set(entry.get("technologies", [])) | set(ww_result.get("technologies", []))
                entry["technologies"] = sorted(merged)

        if enable_dirbuster:
            dirbuster_data = stage_results["dirbuster"]
            module_results["dirbuster"] = dirbuster_data["module_status"]
        else:
            dirbuster_data = {"hosts": {}, "module_status": "skipped"}
            module_results["dirbuster"] = skipped if not prof.run_dirbuster else "skipped"

        vuln_data = stage_results.get("nuclei") or {"findings": [], "module_status": skipped}
        module_results["vuln"] = vuln_data["module_status"]
        net_data = stage_results.get("nuclei_network")
        if net_data is not None:
            module_results["nuclei_network"] = net_data["module_status"]
            vuln_data["findings"] = list(vuln_data.get("findings", [])) + net_data.get("findings", [])
        else:
            module_results["nuclei_network"] = (
                skipped if not prof.run_nuclei_network else "skipped (no recognised network services)")
        cve_data = stage_results.get("cve_match") or {"findings": [], "module_status": skipped}
        module_results["cve_match"] = cve_data["module_status"]
        # version-matched CVEs flow through the same save/score/KEV path as nuclei findings
        vuln_data.setdefault("findings", [])
        vuln_data["findings"] = list(vuln_data["findings"]) + cve_data.get("findings", [])
        module_results["nuclei_templates"] = vuln_data.get("template_count")
        sslyze_data = stage_results.get("sslyze") or {"findings": [], "module_status": skipped}
        module_results["sslyze"] = sslyze_data["module_status"]
        screenshot_data = stage_results.get("screenshot") or {"screenshots": [], "module_status": skipped}
        module_results["screenshot"] = screenshot_data["module_status"]
        logger.info(
            f"[pipeline] web analysis done in {stage_timings['web_analysis_wall']}s wall "
            f"(per-module: {stage_dts}); nuclei findings={len(vuln_data.get('findings', []))}, "
            f"sslyze findings={len(sslyze_data.get('findings', []))}"
        )

        # Save Nuclei findings to DB
        for finding in vuln_data.get("findings", []):
            tags = finding.get("tags", [])
            template_id = finding.get("template_id", "")

            # Prefer real CVE from Nuclei's classification block; fall back to
            # tag/template-id pattern matching only if classification is absent.
            cve_id = finding.get("cve_id")
            if not cve_id and isinstance(tags, list):
                for tag in tags:
                    if str(tag).upper().startswith("CVE-"):
                        cve_id = str(tag).upper()
                        break
            if not cve_id and template_id.upper().startswith("CVE-"):
                cve_id = template_id.upper()

            vuln = Vulnerability(
                target_id=target_id,
                scan_id=scan_id,
                template_id=template_id,
                name=finding.get("name", ""),
                severity=finding.get("severity", "info"),
                description=finding.get("description", ""),
                matched_at=finding.get("matched_at", ""),
                vuln_type=finding.get("type", ""),
                tags=tags,
                host=finding.get("host", ""),
                cve_id=cve_id,
                cvss_score=finding.get("cvss_score")
            )
            db.add(vuln)

        db.commit()

        # Save sslyze findings
        for finding in sslyze_data.get("findings", []):
            vuln = Vulnerability(
                target_id=target_id,
                scan_id=scan_id,
                template_id=finding.get("template_id", ""),
                name=finding.get("name", ""),
                severity=finding.get("severity", "info"),
                description=finding.get("description", ""),
                matched_at=finding.get("matched_at", ""),
                vuln_type=finding.get("vuln_type", ""),
                tags=finding.get("tags", []),
                host=finding.get("host", ""),
                cve_id=finding.get("cve_id"),
                cvss_score=finding.get("cvss_score")
            )
            db.add(vuln)
        db.commit()
        # Stage 7: Save assets to DB with upsert + change detection
        self.update_state(state="PROGRESS", meta={"stage": "saving_results"})
        if scan:
            scan.current_stage = "saving_results"
            db.commit()

        # One merged record per host across ALL its web ports (union of technologies)
        http_merged = merge_http_info(http_data["hosts"])
        port_lookup = {h["subdomain"]: h["ports"] for h in port_data["hosts"]}

        new_count = 0
        changed_count = 0
        disappeared_count = 0

        found_subdomains = set(h["subdomain"] for h in live_hosts)
        scanned_assets_this_run = []

        existing_assets = db.query(Asset).filter(
            Asset.target_id == target_id,
            Asset.status != "disappeared"
        ).all()

        created_alerts = []

        removals_trusted = pipeline_trusted_for_removals(module_results, internal_target)
        if not removals_trusted:
            logger.warning("[pipeline] discovery not fully successful -- skipping 'disappeared' detection")

        for existing_asset in existing_assets:
            if removals_trusted and existing_asset.subdomain not in found_subdomains:
                existing_asset.status = "disappeared"
                disappeared_count += 1
                alert = Alert(
                    target_id=target_id,
                    scan_id=scan_id,
                    alert_type="disappeared_asset",
                    asset_subdomain=existing_asset.subdomain,
                    asset_ip=existing_asset.ip,
                    detail={"reason": "Asset not found in latest scan"}
                )
                db.add(alert)
                created_alerts.append(alert)

        for host in live_hosts:
            subdomain = host["subdomain"]
            ip = host["ip"]
            if subdomain in port_lookup:
                ports = port_lookup[subdomain]
            else:
                # nmap failed/timed out for this host: keep last known ports instead of
                # recording "no open ports" (which would raise a false changed_asset).
                prev = db.query(Asset).filter(Asset.target_id == target_id,
                                              Asset.subdomain == subdomain).first()
                ports = (prev.open_ports or []) if prev else []
            http_info = http_merged.get(subdomain) or http_merged.get(ip) or {}
            technologies = http_info.get("technologies", [])
            # A narrower profile only ADDS to what we know; it never removes ports/techs a
            # wider earlier scan found (that would raise false 'changed asset' alerts).
            if prof.nmap_ports == "100" or not prof.run_whatweb:
                from backend.pipeline_utils import merge_known_ports, merge_known_technologies
                prev_a = db.query(Asset).filter(Asset.target_id == target_id,
                                                Asset.subdomain == subdomain).first()
                if prev_a:
                    if prof.nmap_ports == "100" and subdomain in port_lookup:
                        ports = merge_known_ports(prev_a.open_ports, ports)
                    if not prof.run_whatweb:
                        technologies = merge_known_technologies(prev_a.technologies, technologies)
            http_status = http_info.get("status_code")
            http_title = http_info.get("title", "")

            hash_input = json.dumps({
                "ports": sorted([p["port"] for p in ports]),
                "technologies": sorted(technologies),
                "http_status": http_status,
                "http_title": http_title
            }, sort_keys=True)
            content_hash = hashlib.sha256(hash_input.encode()).hexdigest()

            existing = db.query(Asset).filter(
                Asset.target_id == target_id,
                Asset.subdomain == subdomain
            ).first()

            if existing:
                if existing.content_hash != content_hash:
                    old_detail = {
                        "old_ports": [p["port"] for p in (existing.open_ports or [])],
                        "new_ports": [p["port"] for p in ports],
                        "old_technologies": existing.technologies or [],
                        "new_technologies": technologies,
                        "old_http_status": existing.http_status,
                        "new_http_status": http_status,
                    }
                    existing.content_hash = content_hash
                    existing.ip = ip
                    existing.open_ports = ports
                    existing.technologies = technologies
                    existing.http_status = http_status
                    existing.http_title = http_title
                    existing.status = "changed"
                    existing.last_seen = datetime.now(timezone.utc)
                    scanned_assets_this_run.append(existing)
                    changed_count += 1
                    alert = Alert(
                        target_id=target_id,
                        scan_id=scan_id,
                        alert_type="changed_asset",
                        asset_subdomain=subdomain,
                        asset_ip=ip,
                        detail=old_detail
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                else:
                    if existing.status == "disappeared":
                        alert = Alert(
                            target_id=target_id, scan_id=scan_id, alert_type="reappeared_asset",
                            asset_subdomain=subdomain, asset_ip=ip,
                            detail={"reason": "Asset seen again after being marked disappeared"},
                        )
                        db.add(alert)
                        created_alerts.append(alert)
                    # unchanged since last scan: no longer "new"/"changed"/"disappeared"
                    existing.status = "active"
                    existing.last_seen = datetime.now(timezone.utc)
                    scanned_assets_this_run.append(existing)
            else:
                new_asset = Asset(
                    target_id=target_id,
                    subdomain=subdomain,
                    ip=ip,
                    open_ports=ports,
                    technologies=technologies,
                    http_status=http_status,
                    http_title=http_title,
                    content_hash=content_hash,
                    status="new",
                    last_seen=datetime.now(timezone.utc)
                )
                db.add(new_asset)
                scanned_assets_this_run.append(new_asset)
                new_count += 1
                alert = Alert(
                    target_id=target_id,
                    scan_id=scan_id,
                    alert_type="new_asset",
                    asset_subdomain=subdomain,
                    asset_ip=ip,
                    detail={"technologies": technologies, "http_status": http_status}
                )
                db.add(alert)
                created_alerts.append(alert)

        db.commit()

        # Persist discovered paths from the dirbuster stage, linked to the
        # correct asset by subdomain -- look up fresh from the DB now that
        # all assets (new and existing) have real ids after the commit above.
        if dirbuster_data["hosts"]:
            asset_lookup = {
                a.subdomain: a.id
                for a in db.query(Asset).filter(Asset.target_id == target_id).all()
            }
            paths_saved = 0
            for url, host_result in dirbuster_data["hosts"].items():
                subdomain = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                asset_id = asset_lookup.get(subdomain)
                if not asset_id:
                    continue
                for p in host_result.get("paths", []):
                    db.add(DiscoveredPath(
                        asset_id=asset_id,
                        scan_id=scan_id,
                        path=p.get("path") or "/",
                        status_code=p.get("status_code"),
                        content_length=p.get("content_length"),
                        redirect_location=p.get("redirect_location"),
                    ))
                    paths_saved += 1
            if paths_saved:
                db.commit()
            logger.info(f"[pipeline] Saved {paths_saved} discovered paths to DB")

        # Deliver webhook notifications for all alerts generated this run
        if created_alerts:
            send_webhook_alerts(db, target_id, created_alerts)

        # Record which assets were actually observed in this scan, for
        # point-in-time report scoping (independent of Asset's mutable state)
        for a in scanned_assets_this_run:
            db.add(ScanAsset(scan_id=scan_id, asset_id=a.id))
        db.commit()

        # Stage 8: Risk scoring
        self.update_state(state="PROGRESS", meta={"stage": "risk_scoring"})
        if scan:
            scan.current_stage = "risk_scoring"
            db.commit()
        from backend.risk_scoring import score_all_assets

        stage_start = time.time()
        score_all_assets(db, target_id, scan_id)
        stage_timings["risk_scoring"] = round(time.time() - stage_start, 2)

        logger.info(
            f"[pipeline] Risk scoring completed in "
            f"{stage_timings['risk_scoring']}s"
        )

        if scan:
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_assets = len(live_hosts)
            scan.new_assets = new_count
            scan.changed_assets = changed_count
            scan.disappeared_assets = disappeared_count
            module_results["stage_timings"] = stage_timings
            scan.module_results = module_results
            db.commit()
            from backend.audit import log_action
            log_action(db, "system", "scan_completed", target_id=target_id, scan_id=scan_id,
                       detail={"new_assets": new_count, "changed_assets": changed_count,
                               "disappeared_assets": disappeared_count})

        logger.info(
            f"[pipeline] Total scan completed in "
            f"{round(time.time()-overall_start,2)}s"
        )

        return {
            "status": "completed",
            "target_id": target_id,
            "domain": domain,
            "total_assets": len(live_hosts),
            "new_assets": new_count,
            "changed_assets": changed_count,
            "disappeared_assets": disappeared_count,
            "module_results": module_results
        }

    except Exception as e:
        if scan:
            module_results["stage_timings"] = stage_timings
            scan.module_results = module_results
            scan.status = "failed"
            scan.error_log = str(e)
            db.commit()
            from backend.audit import log_action
            log_action(db, "system", "scan_failed", target_id=target_id, scan_id=scan_id,
                       detail={"error": str(e)})
        raise

    finally:
        db.close()
        if have_lock:
            try:
                lock.release()
            except Exception:
                pass

@celery_app.task(name="check_scheduled_scans")
def check_scheduled_scans():
    """
    Runs periodically (via Celery Beat). Checks for due ScheduledScan rows,
    triggers a scan for each, and advances next_run_at.
    """
    from backend.db import SessionLocal
    from backend.models.schedule import ScheduledScan
    from backend.models.scan import Scan
    from backend.models.target import Target
    from croniter import croniter
    from datetime import datetime, timezone

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.query(ScheduledScan).filter(
            ScheduledScan.enabled == True,
            ScheduledScan.next_run_at <= now
        ).all()

        for sched in due:
            target = db.query(Target).filter(Target.id == sched.target_id).first()
            skip = (not target or not target.authorized or not target.is_active)
            if not skip:
                from backend.validators import validate_target
                try:
                    validate_target(target.domain)
                except ValueError as e:
                    logger.warning(f"[scheduler] target {target.id} failed validation: {e}")
                    skip = True
            if not skip and db.query(Scan).filter(
                    Scan.target_id == target.id, Scan.status.in_(["pending", "running"])).first():
                logger.info(f"[scheduler] scan already active for target {target.id}, skipping this tick")
                skip = True
            if skip:
                # Push next_run forward so we don't spin on a dead/unauthorized/busy target
                itr = croniter(sched.cron_expression, now)
                sched.next_run_at = itr.get_next(datetime)
                continue

            from backend.scan_profiles import get_profile
            db_scan = Scan(
                target_id=target.id,
                status="pending",
                profile=get_profile(target.default_profile).name,
                created_at=now
            )
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)

            task = run_scan.delay(
                target_id=target.id,
                domain=target.domain,
                rate_limit=target.rate_limit,
                scan_id=db_scan.id,
                enable_dirbuster=bool(target.dirbuster_enabled),
                profile=db_scan.profile,
            )
            db_scan.celery_task_id = task.id
            db.commit()

            sched.last_run_at = now
            itr = croniter(sched.cron_expression, now)
            sched.next_run_at = itr.get_next(datetime)

        db.commit()
    finally:
        db.close()
