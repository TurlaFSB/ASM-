from celery import Celery
import logging
from backend.config import settings
import redis
from backend.watchdog import SCAN_MAX_SECONDS

logger = logging.getLogger(__name__)

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
    # With acks_late on Redis an unacked task is redelivered after the visibility timeout (default 1h),
    # which would re-run a long deep scan that is still going. Keep it well above the longest scan.
    broker_transport_options={"visibility_timeout": 6 * 3600},
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "reap-stuck-scans": {"task": "reap_stuck_scans", "schedule": 600.0},
        # Hourly is only the polling rhythm: each source enforces its own minimum interval per target.
        "exposure-sweep": {"task": "exposure_sweep", "schedule": 3600.0},
        "data-retention": {"task": "data_retention", "schedule": 86400.0},
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
    Runs all scanner modules and updates the scan record in the DB at each stage.
    The decisions and data transforms live in backend.pipeline_stages; this function owns the lock,
    the guard thread and the commit/failure bookkeeping.
    """
    from backend.scanner.subdomain import enumerate_subdomains
    from backend.scanner.dns import resolve_subdomains
    from backend.scanner.portscan import scan_multiple_hosts
    from backend.scanner.whois_lookup import run_whois_asn
    from backend.scanner.httpprobe import run_httpx
    from backend.scanner.whatweb import run_whatweb
    from backend.scanner.dirbuster import run_dirbuster
    from backend.scanner.sslyze_scan import run_sslyze
    from backend.scanner.vuln import run_nuclei, network_tags_from_services
    from backend.scanner.screenshot import run_eyewitness
    from backend.scanner.cve_match import run_cve_match
    from backend.scan_persist import upsert_assets, save_discovered_paths
    from backend.db import SessionLocal
    from backend.models.scan import Scan
    from backend.models.scan_asset import ScanAsset
    from backend.models.target import Target
    from backend import pipeline_stages as ps
    from backend.pipeline_utils import (
        build_web_targets, tls_targets_from_urls, urls_in_scope, run_stages_parallel, effective_rate,
    )
    import os as _os
    import time
    from datetime import datetime, timezone

    from backend.scan_profiles import get_profile
    prof = get_profile(profile)
    wordlist = wordlist or prof.wordlist
    enable_dirbuster = bool(enable_dirbuster and prof.run_dirbuster)
    logger.info(f"[pipeline] scan_id={scan_id} target={domain} profile={prof.name}")

    from backend import cancellation as cx

    redis_client = redis.Redis.from_url(settings.redis_url)

    # A scan cancelled while still queued must never start (and never flip back to 'running').
    if scan_id:
        _db = SessionLocal()
        try:
            _s = _db.query(Scan).filter(Scan.id == scan_id).first()
            if cx.is_flagged(redis_client, scan_id) or (_s is not None and _s.status == "cancelled"):
                if _s is not None and _s.status != "cancelled":
                    _s.status = "cancelled"
                    _db.commit()
                logger.info(f"[pipeline] scan_id={scan_id} was cancelled before it started")
                return {"status": "cancelled", "scan_id": scan_id}
        finally:
            _db.close()

    # thread_local=False: the ScanGuard thread renews this lock, and redis-py
    # keeps the lock token in thread-local storage by default.
    lock = redis_client.lock(cx.lock_key(target_id), timeout=cx.LOCK_TTL, thread_local=False)
    have_lock = lock.acquire(blocking=False)
    if not have_lock:
        _db = SessionLocal()
        try:
            stale, owner_id = ps.lock_is_stale(redis_client, _db, target_id, scan_id, cx)
        finally:
            _db.close()
        if stale:
            logger.warning(f"[pipeline] clearing stale scan lock for target_id={target_id} (owner scan {owner_id} is not active)")
            redis_client.delete(cx.lock_key(target_id), cx.owner_key(target_id))
            have_lock = lock.acquire(blocking=False)
    if not have_lock:
        logger.warning(f"[pipeline] Scan already running for target_id={target_id}, retrying in 30s")
        raise self.retry(countdown=30, max_retries=20)
    if scan_id:
        redis_client.setex(cx.owner_key(target_id), 3600, str(scan_id))
    guard = cx.ScanGuard(redis_client, scan_id, lock=lock, max_seconds=SCAN_MAX_SECONDS)
    guard.start()
    checkpoint = guard.checkpoint

    db = SessionLocal()
    module_results = {}
    stage_timings = {}
    scan = None
    overall_start = time.time()

    def stage(name):
        checkpoint()
        ps.enter_stage(self, db, scan, name)

    try:
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                if scan.status == "cancelled":
                    raise cx.ScanCancelled()
                if scan.status == "completed":      # redelivered after a worker restart: do not run twice
                    logger.warning(f"[pipeline] scan {scan_id} already completed; ignoring duplicate delivery")
                    return {"scan_id": scan_id, "status": "completed", "duplicate": True}
                scan.status = "running"
                scan.started_at = datetime.now(timezone.utc)
                db.commit()

        stage_start = time.time()
        internal_target = ps.is_internal_target(domain)

        if internal_target:
            # Raw IP or internal/lab hostname: subfinder/amass query public sources that cannot know it.
            # Treat the target itself as the sole live host.
            stage("subdomain_enumeration")
            module_results["subfinder"] = "skipped (internal/IP target)"
            module_results["amass"] = "skipped (internal/IP target)"
            stage_timings["subdomain"] = round(time.time() - stage_start, 2)
            logger.info(f"[pipeline] Subdomain skipped for internal target {domain}")

            stage("dns_resolution")
            stage_start = time.time()
            live_hosts, module_results["dns"] = ps.internal_live_hosts(domain)
        else:
            stage("subdomain_enumeration")
            subdomain_data = enumerate_subdomains(domain, rate_limit)
            module_results["subfinder"] = subdomain_data["module_status"]["subfinder"]
            module_results["amass"] = subdomain_data["module_status"]["amass"]
            subdomains = subdomain_data["subdomains"]
            stage_timings["subdomain"] = round(time.time() - stage_start, 2)
            logger.info(f"[pipeline] Subdomain completed in {stage_timings['subdomain']}s ({len(subdomains)} subdomains)")

            stage("dns_resolution")
            stage_start = time.time()
            dns_data = resolve_subdomains(subdomains)
            module_results["dns"] = dns_data["module_status"]
            live_hosts = dns_data["live"]
        stage_timings["dns"] = round(time.time() - stage_start, 2)
        logger.info(f"[pipeline] DNS completed in {stage_timings['dns']}s ({len(live_hosts)} live hosts)")

        # WHOIS + ASN
        stage("whois_asn_lookup")
        stage_start = time.time()
        first_ip = next((h["ip"] for h in live_hosts if h.get("ip")), None)
        whois_result = run_whois_asn(domain, resolved_ip=first_ip, is_internal=internal_target)
        target_row = db.query(Target).filter(Target.id == target_id).first()
        if target_row:
            target_row.whois_data = whois_result
            db.commit()
        module_results["whois_asn"] = "completed" if (whois_result.get("domain_whois") or whois_result.get("asn")) else "no data"
        stage_timings["whois_asn"] = round(time.time() - stage_start, 2)
        logger.info(f"[pipeline] WHOIS/ASN completed in {stage_timings['whois_asn']}s")

        # Port scanning
        stage("port_scanning")
        stage_start = time.time()
        port_data = scan_multiple_hosts(live_hosts, rate_limit, prof.nmap_ports, prof.nmap_host_timeout,
                                        prof.nmap_version_intensity)
        module_results["portscan"] = port_data["module_status"]
        stage_timings["portscan"] = round(time.time() - stage_start, 2)
        logger.info(f"[pipeline] PortScan completed in {stage_timings['portscan']}s ({len(port_data['hosts'])} hosts scanned)")

        # HTTP probing: every web-looking port nmap found, bare host names (httpx picks the scheme itself)
        stage("http_probing")
        stage_start = time.time()
        bare_hosts = [h["subdomain"] for h in live_hosts]
        web_targets = build_web_targets(port_data["hosts"], bare_hosts)
        http_data = run_httpx(web_targets, rate_limit)
        module_results["httpprobe"] = http_data["module_status"]

        # Downstream tools get the CONFIRMED URLs (correct scheme) that stay inside the target's scope.
        # With no confirmed web service the web stages get nothing: bare hosts have no scheme and would
        # make feroxbuster/nuclei/eyewitness error out.
        confirmed_urls = list(dict.fromkeys(h["url"] for h in http_data["hosts"] if h.get("url")))
        scope_names = [h["subdomain"] for h in live_hosts] + [h.get("ip") for h in live_hosts]
        confirmed_urls, out_of_scope = urls_in_scope(confirmed_urls, scope_names, domain)
        if out_of_scope:
            logger.warning(f"[pipeline] dropped {len(out_of_scope)} URL(s) outside the target scope "
                           f"(redirected away): {out_of_scope[:5]}")
            module_results["scope_filter"] = f"dropped {len(out_of_scope)} out-of-scope redirect URL(s)"
        host_urls = confirmed_urls
        stage_timings["httpx"] = round(time.time() - stage_start, 2)
        logger.info(f"[pipeline] HTTPX completed in {stage_timings['httpx']}s ({len(http_data['hosts'])} live web services)")

        # Independent web-facing modules run CONCURRENTLY; total time becomes the slowest module instead of
        # the sum. They only read host_urls/TLS targets and never touch the DB. ASM_PARALLEL_STAGES=false
        # runs them one after another. nuclei and feroxbuster hit the same hosts at the same time, so split
        # the rate budget between them (overloading a host makes nuclei abandon it as 'unresponsive').
        n_heavy = int(enable_dirbuster) + int(prof.run_nuclei) + int(prof.run_nuclei_network)
        heavy_rate = max(1, effective_rate(rate_limit) // max(1, n_heavy))
        stage("web_analysis")
        stage_start = time.time()

        def _cve_cache():
            try:
                return redis.Redis.from_url(settings.redis_url, socket_timeout=2)
            except Exception:  # noqa: BLE001
                return None
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
        checkpoint()                 # cancelled during web analysis: persist nothing from this scan

        web = ps.collect_web_results(stage_results, prof, enable_dirbuster, http_data, module_results)
        dirbuster_data, vuln_data, sslyze_data = web["dirbuster"], web["vuln"], web["sslyze"]
        logger.info(
            f"[pipeline] web analysis done in {stage_timings['web_analysis_wall']}s wall "
            f"(per-module: {stage_dts}); nuclei findings={len(vuln_data.get('findings', []))}, "
            f"sslyze findings={len(sslyze_data.get('findings', []))}"
        )

        db.add_all(ps.build_vulnerabilities(vuln_data.get("findings", []), target_id, scan_id))
        db.commit()
        db.add_all(ps.build_vulnerabilities(sslyze_data.get("findings", []), target_id, scan_id,
                                            type_key="vuln_type", derive_cve=False))
        db.commit()

        # Save assets with upsert + change detection
        stage("saving_results")
        new_count, changed_count, disappeared_count, scanned_assets_this_run = upsert_assets(
            db, target_id, live_hosts, port_data, http_data, prof, module_results, internal_target)

        # Link dirbuster hits to assets (looked up fresh now that every asset has a real id).
        save_discovered_paths(db, target_id, scan_id, dirbuster_data)

        # Record which assets were observed in this scan, for point-in-time report scoping
        for a in scanned_assets_this_run:
            db.add(ScanAsset(scan_id=scan_id, asset_id=a.id))
        db.commit()

        if scan:
            ps.record_changes_and_alerts(db, scan, module_results)
            ps.seal_record(db, scan, module_results)

        # Risk scoring
        stage("risk_scoring")
        from backend.risk_scoring import score_all_assets
        stage_start = time.time()
        score_all_assets(db, target_id, scan_id)
        stage_timings["risk_scoring"] = round(time.time() - stage_start, 2)
        logger.info(f"[pipeline] Risk scoring completed in {stage_timings['risk_scoring']}s")

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
            try:
                prebuild_report.delay(scan_id)      # so the first click on "Report" is instant
            except Exception:  # noqa: BLE001
                logger.warning("[pipeline] could not queue report pre-build", exc_info=True)

        logger.info(f"[pipeline] Total scan completed in {round(time.time()-overall_start,2)}s")

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

    except cx.ScanCancelled as _sc:
        _timeout = isinstance(_sc, cx.ScanTimedOut)
        logger.warning(f"[pipeline] scan_id={scan_id} {'timed out' if _timeout else 'cancelled'}")
        try:
            db.rollback()
            if scan_id:
                _c = db.query(Scan).filter(Scan.id == scan_id).first()
                if _c is not None:
                    _c.status = "failed" if _timeout else "cancelled"
                    if _timeout:
                        _c.error_log = f"Scan exceeded the maximum runtime of {SCAN_MAX_SECONDS // 60} minutes and was stopped"
                    _c.current_stage = None
                    _c.completed_at = datetime.now(timezone.utc)
                    db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("[pipeline] could not record cancellation")
        return {"status": "cancelled", "scan_id": scan_id}

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
        guard.stop()
        db.close()
        if have_lock:
            try:
                lock.release()
            except Exception:
                pass
            try:
                redis_client.delete(cx.owner_key(target_id))
            except Exception:  # noqa: BLE001
                pass

@celery_app.task(name="prebuild_report")
def prebuild_report(scan_id: int):
    """Render and cache a finished scan's PDF in the background (best effort)."""
    from backend.db import SessionLocal
    from backend.report_cache import get_or_build_pdf
    import time
    db = SessionLocal()
    try:
        t = time.time()
        get_or_build_pdf(db, scan_id)
        logger.info(f"[report] pre-built report for scan {scan_id} in {time.time() - t:.1f}s")
    except Exception:  # noqa: BLE001
        logger.warning(f"[report] pre-build failed for scan {scan_id}", exc_info=True)
    finally:
        db.close()


@celery_app.task(name="data_retention")
def data_retention():
    """Daily: prune old scan artifacts and delivery logs (see backend/retention.py)."""
    from backend.db import SessionLocal
    from backend.retention import run_retention
    db = SessionLocal()
    try:
        return run_retention(db)
    finally:
        db.close()


@celery_app.task(name="reap_stuck_scans")
def reap_stuck_scans_task():
    from backend.db import SessionLocal
    from backend.watchdog import reap_stuck_scans
    _db = SessionLocal()
    try:
        return reap_stuck_scans(_db, redis.Redis.from_url(settings.redis_url))
    finally:
        _db.close()


@celery_app.task(name="run_exposure_checks")
def run_exposure_checks(target_id: int, sources: list = None, force: bool = False):
    """Run the target's enabled leak/breach collectors. Collector errors are recorded, never raised."""
    from backend.db import SessionLocal
    from backend.models.target import Target
    from backend.exposure.runner import run_collectors
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if target is None:
            return {}
        res = run_collectors(db, target, sources=sources, force=force)
        logger.info(f"[exposure] target {target_id}: {res}")
        return res
    finally:
        db.close()


@celery_app.task(name="exposure_sweep")
def exposure_sweep():
    """Queue a check for every active target that has at least one collector switched on, spread out over time."""
    from backend.db import SessionLocal
    from backend.models.target import Target
    from backend.exposure.runner import enabled_sources
    db = SessionLocal()
    try:
        queued = 0
        for t in db.query(Target).filter(Target.is_active == True, Target.exposure_sources.isnot(None)).order_by(Target.id).all():  # noqa: E712
            if enabled_sources(t):
                run_exposure_checks.apply_async(args=[t.id], countdown=queued * 30)
                queued += 1
        return {"queued": queued}
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
            try:
                db.commit()
            except Exception:  # noqa: BLE001 - unique index: a scan became active since the check above
                db.rollback()
                logger.info(f"[scheduler] scan already active for target {target.id} (race), skipping this tick")
                sched.next_run_at = croniter(sched.cron_expression, now).get_next(datetime)
                continue
            db.refresh(db_scan)

            try:
                task = run_scan.delay(
                    target_id=target.id,
                    domain=target.domain,
                    rate_limit=target.rate_limit,
                    scan_id=db_scan.id,
                    enable_dirbuster=bool(target.dirbuster_enabled),
                    profile=db_scan.profile,
                )
            except Exception:  # noqa: BLE001 - broker down: do not leave a pending row that blocks the target
                db_scan.status = "failed"
                db_scan.error_log = "Could not queue the scheduled scan (task queue unavailable)."
                db_scan.completed_at = now
                db.commit()
                logger.exception(f"[scheduler] could not queue scan for target {target.id}")
                continue
            db_scan.celery_task_id = task.id
            db.commit()

            sched.last_run_at = now
            itr = croniter(sched.cron_expression, now)
            sched.next_run_at = itr.get_next(datetime)

        db.commit()
    finally:
        db.close()
