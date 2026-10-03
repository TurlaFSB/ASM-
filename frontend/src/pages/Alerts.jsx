import { useState, useEffect } from "react";
import { CheckCheck, ChevronRight } from "lucide-react";
import { getAlerts, getDeliveries, markAlertRead, markAllAlertsRead } from "../api";
import Collapse from "../components/Collapse";

const FILTERS = ["all", "critical", "high", "medium", "low"];
const LEGACY_LABELS = {
  new_asset: "New asset", reappeared_asset: "Reappeared", changed_asset: "Changed",
  disappeared_asset: "Disappeared", exploitable_finding: "Exploitable",
};

function timeAgo(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86400) return `${Math.floor(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

// Alerts created before change-event alerting have no summary; describe them from their old detail.
function legacyText(a) {
  const d = a.detail || {};
  if (a.alert_type === "changed_asset") {
    const oldP = d.old_ports || [], newP = d.new_ports || [];
    const added = newP.filter(p => !oldP.includes(p)), removed = oldP.filter(p => !newP.includes(p));
    const parts = [];
    if (added.length) parts.push(`ports opened: ${added.join(", ")}`);
    if (removed.length) parts.push(`ports closed: ${removed.join(", ")}`);
    const oldT = d.old_technologies || [], newT = d.new_technologies || [];
    const tAdd = newT.filter(t => !oldT.includes(t)), tDel = oldT.filter(t => !newT.includes(t));
    if (tAdd.length) parts.push(`technologies added: ${tAdd.join(", ")}`);
    if (tDel.length) parts.push(`technologies removed: ${tDel.join(", ")}`);
    if (d.old_http_status !== d.new_http_status && d.new_http_status != null) parts.push(`HTTP ${d.old_http_status ?? "none"} to ${d.new_http_status}`);
    return parts.join("; ") || "Asset record changed";
  }
  if (a.alert_type === "new_asset") return `Technologies: ${d.technologies?.join(", ") || "none detected"}`;
  if (a.alert_type === "disappeared_asset") return d.reason || "Not found in the latest scan";
  if (a.alert_type === "exploitable_finding") return [d.name, d.cve_id].filter(Boolean).join(" ");
  return a.alert_type;
}

function Deliveries({ rows }) {
  if (!rows.length) return <div className="muted-note">No webhook deliveries yet. Configure one from Targets, under Notifications.</div>;
  return (
    <table className="delivery-table">
      <thead><tr><th>When</th><th>Sent to</th><th>Type</th><th>Result</th><th>Changes</th></tr></thead>
      <tbody>
        {rows.map(d => (
          <tr key={d.id}>
            <td className="cell-nowrap">{timeAgo(d.created_at)}</td>
            <td>{d.host || "unknown"}</td>
            <td>{d.kind === "test" ? "Test" : `Scan #${d.scan_id}`}</td>
            <td>
              <span className={"badge " + (d.status === "sent" ? "badge-completed" : d.status === "blocked" ? "badge-pending" : "badge-failed")}>
                {d.status}
              </span>
              {d.status !== "sent" && d.error && <span className="muted-note" style={{ marginLeft: 8 }}>{d.error}</span>}
            </td>
            <td>{d.kind === "test" ? "—" : d.event_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [deliveries, setDeliveries] = useState([]);
  const [filter, setFilter] = useState("all");
  const [showDeliveries, setShowDeliveries] = useState(false);
  const [showOlder, setShowOlder] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = (sev) => {
    getAlerts(sev === "all" ? { limit: 200 } : { limit: 200, severity: sev })
      .then(r => { setAlerts(r.data); setError(false); })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
    getDeliveries({ limit: 20 }).then(r => setDeliveries(r.data)).catch(() => {});
  };

  useEffect(() => { load("all"); }, []);

  const pick = (sev) => { setFilter(sev); load(sev); };
  const notifyNav = () => window.dispatchEvent(new Event("asm:alerts-changed"));
  const markAll = async () => { await markAllAlertsRead(); load(filter); notifyNav(); };
  const markOne = async (a) => {
    if (a.is_read) return;
    setAlerts(list => list.map(x => (x.id === a.id ? { ...x, is_read: true } : x)));
    try { await markAlertRead(a.id); notifyNav(); } catch { load(filter); }
  };

  const current = alerts.filter(a => a.summary);
  const older = alerts.filter(a => !a.summary);
  const unread = alerts.filter(a => !a.is_read).length;

  const renderAlert = (a) => {
    const legacy = !a.summary;
    return (
      <button type="button" key={a.id} className={"alert-card" + (a.is_read ? "" : " unread")} onClick={() => markOne(a)}>
        <div className="alert-main">
          <div className="alert-title">
            {a.severity
              ? <span className={"badge badge-sev-" + a.severity}>{a.severity}</span>
              : <span className="badge badge-active">{LEGACY_LABELS[a.alert_type] || a.alert_type}</span>}
            <span>{legacy ? (a.asset_subdomain || "Asset") : a.summary}</span>
          </div>
          <div className="alert-sub">
            {legacy ? legacyText(a) : [a.asset_subdomain, a.category && `${a.category} change`].filter(Boolean).join(" · ")}
          </div>
        </div>
        <time className="alert-time" dateTime={a.created_at} title={new Date(a.created_at).toLocaleString()}>
          {timeAgo(a.created_at)}
        </time>
      </button>
    );
  };
  const failedRecently = deliveries.slice(0, 5).some(d => d.status !== "sent");

  if (loading) return <div className="page"><div className="loading">Loading...</div></div>;

  return (
    <div className="page">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
          <h1>Alerts</h1>
          {unread > 0 && <span className="muted-note">{unread} unread</span>}
        </div>
        <button className="btn btn-secondary" onClick={markAll} disabled={unread === 0}>
          <CheckCheck size={16} /> Mark all read
        </button>
      </div>

      <div className="seg" role="group" aria-label="Filter by severity">
        {FILTERS.map(f => (
          <button key={f} type="button" className={"seg-item" + (filter === f ? " active" : "")}
            aria-pressed={filter === f} onClick={() => pick(f)}>
            {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {error && <div className="empty">Could not load alerts. Check that the API is running.</div>}
      {!error && current.length === 0 && (
        <div className="empty">
          {filter === "all"
            ? "No new alerts. When a scan confirms a change at or above your target's severity setting, it shows up here."
            : `No ${filter} alerts.`}
        </div>
      )}

      <div className="alerts-list">{current.map(renderAlert)}</div>

      {older.length > 0 && (
        <div className="deliveries">
          <button type="button" className="stage-toggle" onClick={() => setShowOlder(v => !v)} aria-expanded={showOlder}>
            <ChevronRight size={12} className={"stage-chevron" + (showOlder ? " open" : "")} />
            Earlier alerts, before change tracking ({older.length})
          </button>
          <Collapse open={showOlder}>
            <p className="muted-note" style={{ margin: "10px 0 0" }}>
              These came from the previous alert logic, which compared each scan to the last asset record
              and could report scan noise as changes. New alerts only come from confirmed changes.
            </p>
            <div className="alerts-list">{older.map(renderAlert)}</div>
          </Collapse>
        </div>
      )}

      <div className="deliveries">
        <button type="button" className="stage-toggle" onClick={() => setShowDeliveries(v => !v)} aria-expanded={showDeliveries}>
          <ChevronRight size={12} className={"stage-chevron" + (showDeliveries ? " open" : "")} />
          Webhook deliveries{failedRecently && <span className="stage-chip" style={{ marginLeft: 8 }}>Recent failure</span>}
        </button>
        <Collapse open={showDeliveries}><Deliveries rows={deliveries} /></Collapse>
      </div>
    </div>
  );
}
