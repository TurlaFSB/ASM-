"""Persistence stages of the scan pipeline, kept free of Celery and scanner tools so they can be
unit-tested against an ordinary database session."""
import hashlib
import json
import logging
from datetime import datetime, timezone

from backend.models.asset import Asset
from backend.models.discovered_path import DiscoveredPath
from backend.pipeline_utils import merge_http_info, pipeline_trusted_for_removals

logger = logging.getLogger(__name__)


def upsert_assets(db, target_id, live_hosts, port_data, http_data, prof, module_results, internal_target):
    """Create/update Asset rows from this scan's results with change detection.

    Returns (new_count, changed_count, disappeared_count, scanned_assets_this_run).
    """
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

    removals_trusted = pipeline_trusted_for_removals(module_results, internal_target)
    if not removals_trusted:
        logger.warning("[pipeline] discovery not fully successful -- skipping 'disappeared' detection")

    for existing_asset in existing_assets:
        if removals_trusted and existing_asset.subdomain not in found_subdomains:
            existing_asset.status = "disappeared"
            disappeared_count += 1

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
            else:
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

    db.commit()
    return new_count, changed_count, disappeared_count, scanned_assets_this_run


def save_discovered_paths(db, target_id, scan_id, dirbuster_data):
    """Store directory-bruteforce hits against their assets. Returns the number saved."""
    paths_saved = 0
    # Persist discovered paths from the dirbuster stage, linked to the
    # correct asset by subdomain -- look up fresh from the DB now that
    # all assets (new and existing) have real ids after the commit above.
    if dirbuster_data["hosts"]:
        from backend.pipeline_utils import host_port_from_url
        asset_lookup = {
            a.subdomain: a.id
            for a in db.query(Asset).filter(Asset.target_id == target_id).all()
        }
        for url, host_result in dirbuster_data["hosts"].items():
            subdomain, web_port = host_port_from_url(url)
            asset_id = asset_lookup.get(subdomain)
            if not asset_id:
                continue
            for p in host_result.get("paths", []):
                db.add(DiscoveredPath(
                    asset_id=asset_id,
                    scan_id=scan_id,
                    path=p.get("path") or "/",
                    port=web_port,
                    status_code=p.get("status_code"),
                    content_length=p.get("content_length"),
                    redirect_location=p.get("redirect_location"),
                ))
                paths_saved += 1
        if paths_saved:
            db.commit()
        logger.info(f"[pipeline] Saved {paths_saved} discovered paths to DB")

    return paths_saved
