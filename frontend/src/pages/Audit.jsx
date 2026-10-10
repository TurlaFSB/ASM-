import { useCallback, useEffect, useState } from "react";
import { getAudit } from "../api";
import Segmented from "../components/Segmented";
import Skeleton from "../components/Skeleton";
import { label, summarize } from "../lib/audit";
import { timeAgo } from "../lib/time";

const PAGE = 100;

const GROUPS = {
  all: null,
  signin: ["login_success", "login_failed", "login_locked", "login_mfa_required", "mfa_failed", "mfa_reauth_failed", "logout", "setup_completed", "setup_failed"],
  access: ["user_created", "user_updated", "user_password_reset", "user_mfa_reset", "password_changed", "password_change_failed",
    "mfa_enabled", "mfa_disabled", "mfa_recovery_regenerated", "cli_password_reset", "api_token_created", "api_token_revoked"],
  scans: ["target_created", "target_deleted", "target_profile_updated", "target_tags_updated", "dirbuster_toggle_updated", "scan_triggered",
    "scan_cancelled", "scan_completed", "scan_failed", "schedule_created", "schedule_updated", "schedule_toggled", "schedule_deleted",
    "finding_triaged", "notification_settings_updated"],
};
const GROUP_OPTIONS = [["all", "Everything"], ["signin", "Sign-in"], ["access", "Accounts and access"], ["scans", "Targets and scans"]];

// Failures and lock-outs stand out; routine events stay quiet.
const WARN = new Set(["login_failed", "login_locked", "mfa_failed", "mfa_reauth_failed", "password_change_failed", "setup_failed", "scan_failed"]);

export default function Audit() {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [group, setGroup] = useState("all");
  const [user, setUser] = useState("");
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [failed, setFailed] = useState(false);

  const params = useCallback((offset) => {
    const p = { limit: PAGE, offset };
    if (GROUPS[group]) p.action = GROUPS[group].join(",");
    if (user.trim()) p.username = user.trim();
    return p;
  }, [group, user]);

  // Re-query when a filter changes (typing is debounced so each key press is not a request).
  useEffect(() => {
    let live = true;
    const t = setTimeout(() => {
      setLoading(true);
      getAudit(params(0))
        .then(r => { if (!live) return; setRows(r.data); setTotal(Number(r.headers["x-total-count"] ?? r.data.length)); setFailed(false); })
        .catch(() => live && setFailed(true))
        .finally(() => live && setLoading(false));
    }, user ? 350 : 0);
    return () => { live = false; clearTimeout(t); };
  }, [params, user]);

  const loadMore = () => {
    setMore(true);
    getAudit(params(rows.length))
      .then(r => setRows(prev => [...prev, ...r.data]))
      .catch(() => setFailed(true))
      .finally(() => setMore(false));
  };

  return (
    <div className="page">
      <div className="page-header"><h1>Audit log</h1></div>
      <p className="muted-note">Who did what, and from where. Entries are kept for good and cannot be edited here.</p>

      <div className="toolbar" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", margin: "12px 0" }}>
        <Segmented value={group} onChange={setGroup} options={GROUP_OPTIONS} label="Kind of event" />
        <label className="sr-only" htmlFor="audit-user">Username</label>
        <input id="audit-user" type="search" placeholder="Filter by username" value={user} maxLength={64} autoComplete="off"
          onChange={e => setUser(e.target.value)} style={{ maxWidth: 220 }} />
      </div>

      {loading ? <Skeleton rows={6} /> : failed ? (
        <div className="empty">Could not load the audit log. Check that the API is running.</div>
      ) : rows.length === 0 ? (
        <div className="empty">No entries match. Try another kind of event or a different username.</div>
      ) : (
        <>
          <div className="dl" style={{ "--cols": "130px minmax(120px,1fr) minmax(180px,1.2fr) minmax(200px,2fr) 130px" }}>
            <div className="dl-head" aria-hidden="true"><div>When</div><div>Who</div><div>Event</div><div>Details</div><div>From</div></div>
            {rows.map(r => (
              <div className="dl-item" key={r.id}>
                <div className="dl-row">
                  <div className="dl-main" title={r.created_at ? new Date(r.created_at).toLocaleString() : ""}>{timeAgo(r.created_at)}</div>
                  <div className="dl-main"><div className="dl-title">{r.username}</div></div>
                  <div className="dl-main"><span className={"badge " + (WARN.has(r.action) ? "badge-sev-high" : "badge-sev-info")}>{label(r.action)}</span></div>
                  <div className="dl-main">{summarize(r.detail)}</div>
                  <div className="dl-main mono">{r.ip_address || ""}</div>
                </div>
              </div>
            ))}
          </div>
          <p className="muted-note" aria-live="polite">Showing {rows.length} of {total}.</p>
          {rows.length < total && (
            <button type="button" className="btn btn-secondary" onClick={loadMore} disabled={more}>{more ? "Loading..." : "Load more"}</button>
          )}
        </>
      )}
    </div>
  );
}
