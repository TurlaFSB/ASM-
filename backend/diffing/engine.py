"""Snapshot diff engine -> structured change events.

Trust model (what keeps this from crying wolf):
  * Like-with-like: callers diff against the previous completed scan with the SAME profile.
  * Coverage gating: a section is compared only when both scans covered it. Additions need the
    baseline to have been complete; removals need BOTH scans complete (a partial directory scan
    can add paths but can never prove a path is gone).
  * Removal debounce: the first time something is missing it is recorded as "pending", not
    reported. If the next comparable scan still lacks it the removal is confirmed; if it is back
    (a flapping service, a slow host) the pending event is dismissed silently.
  * Detection flakiness: service/technology versions are compared only when both scans actually
    reported one; a missing banner is not a change.

Pure functions, no database.
"""
import copy
import hashlib
from typing import Dict, List, Optional

from backend.diffing.snapshot import FULL, SCHEMA_VERSION, split_path_key
from backend.path_flags import is_sensitive_path, REACHABLE

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
RISKY_PORTS = {21, 23, 69, 110, 111, 135, 139, 445, 512, 513, 514, 1433, 1521, 2049, 2375, 3306, 3389,
               5432, 5900, 5985, 6379, 6667, 9200, 11211, 27017}
from backend.rollup import COMPONENT_RE as _COMPONENT_RE  # noqa: E402


def _fp(category: str, change_type: str, asset: str, subject: str) -> str:
    return hashlib.sha1(f"{category}|{change_type}|{asset}|{subject}".encode(), usedforsecurity=False).hexdigest()[:20]


def _event(category, change_type, section, asset, subject, severity, summary,
           before=None, after=None, group=None, confidence="confirmed") -> Dict:
    return {
        "category": category, "change_type": change_type, "section": section,
        "asset": asset, "subject": subject, "severity": severity, "summary": summary,
        "before": before, "after": after, "group": group, "confidence": confidence,
        "status": "confirmed", "fingerprint": _fp(category, change_type, asset, subject),
    }


def _port_no(key: str) -> int:
    try:
        return int(key.split("/")[0])
    except ValueError:
        return -1


def _svc(p: Dict) -> str:
    return " ".join(x for x in (p.get("product"), p.get("version")) if x) or p.get("service") or "unknown service"


def _split_tech(t: str):
    name, _, ver = t.partition(":")
    return name, ver


# ---------------------------------------------------------------- comparability

def _levels(old: Dict, new: Dict, section: str):
    return (old.get("coverage") or {}).get(section), (new.get("coverage") or {}).get(section)


def _can_add(old: Dict, new: Dict, section: str) -> bool:
    o, n = _levels(old, new, section)
    return o == FULL and n is not None


def _can_remove(old: Dict, new: Dict, section: str) -> bool:
    o, n = _levels(old, new, section)
    return o == FULL and n == FULL


# ---------------------------------------------------------------- pending handling

def _with_pending(old: Dict, pending: List[Dict]) -> Dict:
    """Baseline as if pending removals had not happened yet, so the new scan decides whether
    they are real (still missing) or a flap (back again)."""
    eff = copy.deepcopy(old)
    for ev in pending:
        a, subj, before, cat = ev.get("asset"), ev.get("subject"), ev.get("before"), ev.get("category")
        if cat == "asset":
            eff["assets"].setdefault(a, (before or {}).get("record") or {})
            if (before or {}).get("paths"):
                eff["paths"].setdefault(a, before["paths"])
            continue
        if cat == "finding":
            eff["findings"].setdefault(subj, before or {})
            continue
        if a not in eff["assets"]:
            continue
        rec = eff["assets"][a]
        if cat == "port":
            rec.setdefault("ports", {}).setdefault(subj, before or {})
        elif cat == "technology":
            val = (before or {}).get("value")
            if val and subj not in {_split_tech(t)[0] for t in rec.get("technologies", [])}:
                rec.setdefault("technologies", []).append(val)
        elif cat == "path":
            eff["paths"].setdefault(a, {}).setdefault(subj, before or {})
    return eff


# ---------------------------------------------------------------- section diffs

def _diff_assets(old, new, ev, skipped):
    oa, na = old["assets"], new["assets"]
    add_ok, rm_ok = _can_add(old, new, "assets"), _can_remove(old, new, "assets")
    added = set(na) - set(oa) if add_ok else set()
    removed = set(oa) - set(na) if rm_ok else set()
    for a in sorted(added):
        ports = sorted(na[a].get("ports", {}), key=_port_no)
        ev.append(_event("asset", "added", "assets", a, a, "medium",
                         f"New asset {a}" + (f" with open ports {', '.join(ports)}" if ports else ""),
                         after=na[a]))
    for a in sorted(removed):
        ev.append(_event("asset", "removed", "assets", a, a, "medium", f"Asset {a} is no longer reachable",
                         before={"record": oa[a], "paths": old["paths"].get(a, {})}))
    if not add_ok or not rm_ok:
        skipped.append({"section": "assets", "reason": "asset discovery was not fully successful in one of the scans"})
    return added, removed


def _diff_ports(old, new, common, ev, skipped):
    add_ok, rm_ok = _can_add(old, new, "ports"), _can_remove(old, new, "ports")
    for a in sorted(common):
        op, np_ = old["assets"][a].get("ports", {}), new["assets"][a].get("ports", {})
        if add_ok:
            for k in sorted(set(np_) - set(op), key=_port_no):
                sev = "high" if _port_no(k) in RISKY_PORTS else "medium"
                ev.append(_event("port", "added", "ports", a, k, sev,
                                 f"Port {k} opened on {a} ({_svc(np_[k])})", after=np_[k]))
        if rm_ok:
            for k in sorted(set(op) - set(np_), key=_port_no):
                ev.append(_event("port", "removed", "ports", a, k, "low",
                                 f"Port {k} closed on {a} (was {_svc(op[k])})", before=op[k]))
        if add_ok:
            for k in sorted(set(op) & set(np_), key=_port_no):
                o, n = op[k], np_[k]
                if (o.get("product") or o.get("version")) and (n.get("product") or n.get("version")) \
                        and (o.get("product"), o.get("version")) != (n.get("product"), n.get("version")):
                    ev.append(_event("port", "modified", "ports", a, k, "medium",
                                     f"Service on {a} {k} changed: {_svc(o)} -> {_svc(n)}", before=o, after=n))
    if not (add_ok and rm_ok):
        skipped.append({"section": "ports", "reason": "port scan did not complete in one of the scans"})


def _diff_tech(old, new, common, ev, skipped):
    add_ok, rm_ok = _can_add(old, new, "technologies"), _can_remove(old, new, "technologies")
    for a in sorted(common):
        ot = dict(_split_tech(t) for t in old["assets"][a].get("technologies", []))
        nt = dict(_split_tech(t) for t in new["assets"][a].get("technologies", []))
        full = lambda name, d: f"{name}:{d[name]}" if d.get(name) else name  # noqa: E731
        if add_ok:
            for name in sorted(set(nt) - set(ot)):
                ev.append(_event("technology", "added", "technologies", a, name, "low",
                                 f"Technology {full(name, nt)} detected on {a}", after={"value": full(name, nt)}))
            for name in sorted(set(nt) & set(ot)):
                if ot[name] and nt[name] and ot[name] != nt[name]:
                    ev.append(_event("technology", "modified", "technologies", a, name, "low",
                                     f"{name} on {a} changed: {ot[name]} -> {nt[name]}",
                                     before={"value": full(name, ot)}, after={"value": full(name, nt)}))
        if rm_ok:
            for name in sorted(set(ot) - set(nt)):
                ev.append(_event("technology", "removed", "technologies", a, name, "info",
                                 f"Technology {full(name, ot)} no longer detected on {a}",
                                 before={"value": full(name, ot)}))
    if not (add_ok and rm_ok):
        skipped.append({"section": "technologies", "reason": "technology fingerprinting did not run in one of the scans"})


def _diff_http(old, new, common, ev):
    if not _can_add(old, new, "http"):
        return
    for a in sorted(common):
        o, n = old["assets"][a], new["assets"][a]
        if o.get("http_status") and n.get("http_status") and o["http_status"] != n["http_status"]:
            ev.append(_event("http", "modified", "http", a, "status", "low",
                             f"HTTP status on {a} changed: {o['http_status']} -> {n['http_status']}",
                             before={"value": o["http_status"]}, after={"value": n["http_status"]}))
        if o.get("http_title") and n.get("http_title") and o["http_title"] != n["http_title"]:
            ev.append(_event("http", "modified", "http", a, "title", "low",
                             f"Page title on {a} changed: '{o['http_title']}' -> '{n['http_title']}'",
                             before={"value": o["http_title"]}, after={"value": n["http_title"]}))


def _path_where(host: str, key: str, rec: Dict) -> str:
    port = rec.get("port") or split_path_key(key)[0]
    return f"{host}:{port}" if port else host


def _diff_paths(old, new, common, ev, skipped):
    add_ok, rm_ok = _can_add(old, new, "paths"), _can_remove(old, new, "paths")
    for a in sorted(common):
        op, np_ = old["paths"].get(a, {}), new["paths"].get(a, {})
        if add_ok:
            for k in sorted(set(np_) - set(op)):
                st, p = np_[k].get("status"), split_path_key(k)[1]
                sev = "high" if is_sensitive_path(p, st) else ("low" if st in REACHABLE else "info")
                ev.append(_event("path", "added", "paths", a, k, sev,
                                 f"New path {p} on {_path_where(a, k, np_[k])} (HTTP {st})", after=np_[k]))
            for k in sorted(set(np_) & set(op)):
                os_, ns, p = op[k].get("status"), np_[k].get("status"), split_path_key(k)[1]
                opened = ns in REACHABLE and os_ not in REACHABLE
                unlocked = ns == 200 and os_ in (401, 403)          # access control removed
                if os_ != ns and (opened or unlocked):
                    sev = "high" if is_sensitive_path(p, ns) else "low"
                    ev.append(_event("path", "modified", "paths", a, k, sev,
                                     f"Path {p} on {_path_where(a, k, np_[k])} became accessible: HTTP {os_} -> {ns}",
                                     before=op[k], after=np_[k]))
        if rm_ok:
            for k in sorted(set(op) - set(np_)):
                p = split_path_key(k)[1]
                ev.append(_event("path", "removed", "paths", a, k, "info",
                                 f"Path {p} on {_path_where(a, k, op[k])} no longer found", before=op[k]))
    if not rm_ok:
        skipped.append({"section": "paths", "reason": "directory discovery was partial or skipped; removals not evaluated"})


def _group(f: Dict) -> Optional[str]:
    if f.get("source") != "cve":
        return None
    m = _COMPONENT_RE.match(f.get("name") or "")
    return m.group(1).strip() if m else None


def _is_degraded(snap: Dict, finding: Dict) -> bool:
    """True for a network finding on a host:port whose checks did not fully run in this snapshot."""
    if finding.get("source") != "network":
        return False
    host = finding.get("host") or ""
    bare = host.rsplit(":", 1)[0] if ":" in host else host
    degraded = set(snap.get("degraded") or [])
    return host in degraded or bare in degraded        # a bare-host entry covers every port on that host


def _diff_findings(old, new, ev, skipped):
    of, nf = old["findings"], new["findings"]
    for source in ("web", "network", "cve", "tls", "takeover", "email", "cloud", "files"):
        sec = f"findings_{source}"
        add_ok, rm_ok = _can_add(old, new, sec), _can_remove(old, new, sec)
        held = 0
        okeys = {k for k, v in of.items() if v.get("source") == source}
        nkeys = {k for k, v in nf.items() if v.get("source") == source}
        if add_ok:
            for k in sorted(nkeys - okeys):
                f = nf[k]
                label = f.get("cve") or f.get("name")
                conf = "inferred" if f.get("unverified") else "confirmed"
                note = ""
                if _is_degraded(old, f):          # the old scan could not fully test this service
                    conf, note = "inferred", " (previous scan had incomplete coverage here)"
                ev.append(_event("finding", "added", sec, f.get("host") or "", k, f.get("severity", "info"),
                                 f"New {f.get('severity', 'info')} finding on {f.get('host')}: {label}"
                                 + (" (KEV)" if f.get("kev") else "") + note,
                                 after=f, group=_group(f), confidence=conf))
            for k in sorted(nkeys & okeys):
                o, n = of[k], nf[k]
                if o.get("severity") != n.get("severity"):
                    ev.append(_event("finding", "modified", sec, n.get("host") or "", k, n.get("severity", "info"),
                                     f"Severity of {n.get('cve') or n.get('name')} on {n.get('host')} changed: "
                                     f"{o.get('severity')} -> {n.get('severity')}", before=o, after=n,
                                     group=_group(n), confidence="inferred" if n.get("unverified") else "confirmed"))
        if rm_ok:
            for k in sorted(okeys - nkeys):
                f = of[k]
                e = _event("finding", "removed", sec, f.get("host") or "", k, "info",
                           f"Finding resolved on {f.get('host')}: {f.get('cve') or f.get('name')}",
                           before=f, group=_group(f), confidence="inferred" if f.get("unverified") else "confirmed")
                if _is_degraded(new, f):          # not tested properly this time: absence proves nothing
                    e["held"] = True              # kept pending, never confirmed from this scan
                    held += 1
                ev.append(e)
        if held:
            skipped.append({"section": sec, "reason": f"low coverage: {held} removal(s) held on host:ports that were "
                                                      f"not fully tested ({', '.join(new.get('degraded') or [])})"})
        if not (add_ok and rm_ok):
            skipped.append({"section": sec, "reason": f"the {source} stage had nothing to report or did not finish cleanly in one of the two scans, so absence is not treated as fixed"})


# ---------------------------------------------------------------- public API

def diff_snapshots(old: Optional[Dict], new: Dict, pending: Optional[List[Dict]] = None) -> Dict:
    """Compare two snapshots.

    pending: removal events recorded as 'pending' by the previous diff for this target.
    Returns {baseline, events, pending, dismissed, skipped}:
      events    confirmed changes to report (additions, modifications, CONFIRMED removals)
      pending   removals seen for the first time (not reported yet) + carried-over ones
      dismissed fingerprints of pending removals that turned out to be flaps
    """
    pending = pending or []
    if not old or old.get("schema") != SCHEMA_VERSION or new.get("schema") != SCHEMA_VERSION:
        return {"baseline": True, "events": [], "pending": [], "dismissed": [], "skipped": []}

    eff = _with_pending(old, pending)
    raw: List[Dict] = []
    skipped: List[Dict] = []

    added, removed = _diff_assets(eff, new, raw, skipped)
    common = (set(eff["assets"]) & set(new["assets"])) - added - removed
    _diff_ports(eff, new, common, raw, skipped)
    _diff_tech(eff, new, common, raw, skipped)
    _diff_http(eff, new, common, raw)
    _diff_paths(eff, new, common, raw, skipped)
    _diff_findings(eff, new, raw, skipped)

    pending_fps = {p["fingerprint"] for p in pending}
    raw_removal_fps = {e["fingerprint"] for e in raw if e["change_type"] == "removed" and not e.get("held")}

    events: List[Dict] = []
    new_pending: List[Dict] = []
    for e in raw:
        if e["change_type"] != "removed":
            events.append(e)
        elif e.get("held"):
            if e["fingerprint"] not in pending_fps:    # first sighting under low coverage: record, wait
                e["status"] = "pending"
                new_pending.append(e)                  # (an existing pending row is carried below)
        elif e["fingerprint"] in pending_fps:
            e["status"] = "confirmed"
            events.append(e)                       # still missing on the second comparable scan
        else:
            e["status"] = "pending"
            new_pending.append(e)                  # first sighting: hold, do not report

    dismissed, carried = [], []
    for p in pending:
        if p["fingerprint"] in raw_removal_fps:
            continue                               # confirmed above
        sec = p.get("section")
        if p.get("category") == "finding" and _is_degraded(new, p.get("before") or {}):
            carried.append(p)                      # service not fully tested this scan: keep waiting
        elif _can_remove(eff, new, sec):
            dismissed.append(p["fingerprint"])     # item is back: it was a flap
        else:
            carried.append(p)                      # cannot judge this scan; keep waiting

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    events.sort(key=lambda e: (rank.get(e["severity"], 9), e["category"], e["asset"], e["subject"]))
    return {"baseline": False, "events": events, "pending": new_pending + carried,
            "dismissed": dismissed, "skipped": skipped}
