from celery import Celery
import logging
from backend.config import settings

logger = logging.getLogger(__name__)

def send_webhook_alerts(db, target_id, alerts):
    """
    POST each newly created alert to the target's configured webhook_url,
    if one is set. Never raises -- a webhook failure should never break
    the scan pipeline that's delivering it.
    """
    import requests
    from backend.models.target import Target

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target or not target.webhook_url:
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
            resp = requests.post(target.webhook_url, json=payload, timeout=5)
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
def run_scan(self, target_id: int, domain: str, rate_limit: int = 10, scan_id: int = None):
    """
    Full ASM pipeline task.
    Runs all scanner modules sequentially.
    Updates scan record in DB at each stage.
    """
    from backend.scanner.subdomain import enumerate_subdomains
    from backend.scanner.dns import resolve_subdomains
    from backend.scanner.portscan import scan_multiple_hosts
    from backend.scanner.httpprobe import run_httpx
    from backend.scanner.vuln import run_nuclei
    from backend.scanner.screenshot import run_eyewitness
    from backend.db import SessionLocal
    from backend.models.scan import Scan
    from backend.models.asset import Asset
    from backend.models.alert import Alert
    from backend.models.vulnerability import Vulnerability
    from backend.models.scan_asset import ScanAsset
    from backend.models.target import Target
    import hashlib
    import time
    import json
    from datetime import datetime, timezone

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

        # Stage 3: Port scanning
        self.update_state(state="PROGRESS", meta={"stage": "port_scanning"})
        if scan:
            scan.current_stage = "port_scanning"
            db.commit()
        stage_start = time.time()

        port_data = scan_multiple_hosts(live_hosts, rate_limit)
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

        bare_hosts = [h["subdomain"] for h in live_hosts]
        http_data = run_httpx(bare_hosts, rate_limit)
        module_results["httpprobe"] = http_data["module_status"]

        # Use CONFIRMED live URLs (with correct scheme) from HTTPX output for
        # downstream tools, instead of the original guessed http:// list.
        # Falls back to bare hostnames only if HTTPX found nothing, so
        # nuclei/eyewitness don't get an empty target list on partial failure.
        confirmed_urls = [h["url"] for h in http_data["hosts"] if h.get("url")]
        host_urls = confirmed_urls if confirmed_urls else bare_hosts

        stage_timings["httpx"] = round(time.time()-stage_start,2)
        logger.info(
            f"[pipeline] HTTPX completed in {stage_timings['httpx']}s "
            f"({len(http_data['hosts'])} live web services)"
        )

        # Stage 5: Vulnerability scanning
        self.update_state(state="PROGRESS", meta={"stage": "vuln_scanning"})
        if scan:
            scan.current_stage = "vuln_scanning"
            db.commit()
        stage_start = time.time()

        vuln_data = run_nuclei(host_urls, rate_limit)
        module_results["vuln"] = vuln_data["module_status"]

        stage_timings["nuclei"] = round(time.time()-stage_start,2)
        logger.info(
            f"[pipeline] Nuclei completed in {stage_timings['nuclei']}s "
            f"({len(vuln_data.get('findings', []))} findings)"
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

        # Stage 6: Screenshots
        self.update_state(state="PROGRESS", meta={"stage": "screenshots"})
        if scan:
            scan.current_stage = "screenshots"
            db.commit()
        stage_start = time.time()

        screenshot_data = run_eyewitness(host_urls)
        module_results["screenshot"] = screenshot_data["module_status"]

        stage_timings["eyewitness"] = round(time.time()-stage_start,2)
        logger.info(
            f"[pipeline] EyeWitness completed in {stage_timings['eyewitness']}s "
            f"({len(screenshot_data.get('screenshots', []))} screenshots)"
        )

        # Stage 7: Save assets to DB with upsert + change detection
        self.update_state(state="PROGRESS", meta={"stage": "saving_results"})
        if scan:
            scan.current_stage = "saving_results"
            db.commit()

        http_lookup = {h["host"]: h for h in http_data["hosts"]}
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

        for existing_asset in existing_assets:
            if existing_asset.subdomain not in found_subdomains:
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
            ports = port_lookup.get(subdomain, [])
            http_info = http_lookup.get(subdomain, {})
            technologies = http_info.get("technologies", [])
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
            if not target or not target.authorized or not target.is_active:
                # Skip and push next_run forward so we don't spin on a dead/unauthorized target
                itr = croniter(sched.cron_expression, now)
                sched.next_run_at = itr.get_next(datetime)
                continue

            db_scan = Scan(
                target_id=target.id,
                status="pending",
                created_at=now
            )
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)

            run_scan.delay(
                target_id=target.id,
                domain=target.domain,
                rate_limit=target.rate_limit,
                scan_id=db_scan.id
            )

            sched.last_run_at = now
            itr = croniter(sched.cron_expression, now)
            sched.next_run_at = itr.get_next(datetime)

        db.commit()
    finally:
        db.close()
