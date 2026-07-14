from celery import Celery
from backend.config import settings

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
    import hashlib
    import json
    from datetime import datetime, timezone

    db = SessionLocal()
    module_results = {}
    scan = None

    try:
        # Update scan status to running
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "running"
                scan.started_at = datetime.now(timezone.utc)
                db.commit()

        # Stage 1: Subdomain enumeration
        self.update_state(state="PROGRESS", meta={"stage": "subdomain_enumeration"})
        subdomain_data = enumerate_subdomains(domain, rate_limit)
        module_results["subdomain"] = subdomain_data["module_status"]["subfinder"]
        subdomains = subdomain_data["subdomains"]

        # Stage 2: DNS resolution
        self.update_state(state="PROGRESS", meta={"stage": "dns_resolution"})
        dns_data = resolve_subdomains(subdomains)
        module_results["dns"] = dns_data["module_status"]
        live_hosts = dns_data["live"]

        # Stage 3: Port scanning
        self.update_state(state="PROGRESS", meta={"stage": "port_scanning"})
        port_data = scan_multiple_hosts(live_hosts, rate_limit)
        module_results["portscan"] = port_data["module_status"]

        # Stage 4: HTTP probing
        self.update_state(state="PROGRESS", meta={"stage": "http_probing"})
        host_urls = [f"http://{h['subdomain']}" for h in live_hosts]
        http_data = run_httpx(host_urls, rate_limit)
        module_results["httpprobe"] = http_data["module_status"]

        # Stage 5: Vulnerability scanning
        self.update_state(state="PROGRESS", meta={"stage": "vuln_scanning"})
        vuln_data = run_nuclei(host_urls, rate_limit)
        module_results["vuln"] = vuln_data["module_status"]

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
        screenshot_data = run_eyewitness(host_urls)
        module_results["screenshot"] = screenshot_data["module_status"]

        # Stage 7: Save assets to DB with upsert + change detection
        self.update_state(state="PROGRESS", meta={"stage": "saving_results"})

        http_lookup = {h["host"]: h for h in http_data["hosts"]}
        port_lookup = {h["subdomain"]: h["ports"] for h in port_data["hosts"]}

        new_count = 0
        changed_count = 0
        disappeared_count = 0

        found_subdomains = set(h["subdomain"] for h in live_hosts)

        existing_assets = db.query(Asset).filter(
            Asset.target_id == target_id,
            Asset.status != "disappeared"
        ).all()

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
                else:
                    existing.last_seen = datetime.now(timezone.utc)
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

        db.commit()

        # Stage 8: Risk scoring
        self.update_state(state="PROGRESS", meta={"stage": "risk_scoring"})
        from backend.risk_scoring import score_all_assets
        score_all_assets(db, target_id, scan_id)

        if scan:
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_assets = len(live_hosts)
            scan.new_assets = new_count
            scan.changed_assets = changed_count
            scan.disappeared_assets = disappeared_count
            scan.module_results = module_results
            db.commit()

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
            scan.status = "failed"
            scan.error_log = str(e)
            db.commit()
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
