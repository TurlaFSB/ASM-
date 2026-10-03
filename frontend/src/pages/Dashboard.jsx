import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getTargets, getScans, getAssets, getVulnSummary, getUnreadAlerts, getScanChanges } from "../api";
import { ProfileBadge } from "../components/ProfilePicker";
import Skeleton from "../components/Skeleton";
import { timeAgo } from "../lib/time";

const Stat = ({ value, label, tone }) => (
  <div className={"tile static" + (tone ? " tone-" + tone : "")}>
    <span className="tile-num">{value}</span>
    <span className="tile-label">{label}</span>
  </div>
);


export default function Dashboard() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [vulnSummary, setVulnSummary] = useState({});
  const [unread, setUnread] = useState(0);
  const [latestChanges, setLatestChanges] = useState(null);   // { scanId, counts, total, pending, baseline }
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getTargets(), getScans(), getAssets(), getVulnSummary().catch(() => ({ data: {} }))])
      .then(([t, s, a, v]) => {
        setTargets(t.data);
        setScans(s.data);
        setAssets(a.data);
        setVulnSummary(v.data || {});
      })
      .catch(console.error)
      .finally(() => setLoading(false));
    getUnreadAlerts({ limit: 100 }).then(r => setUnread(r.data.length)).catch(() => {});
  }, []);

  // What changed in the most recent finished scan (secondary data: the page works without it)
  const latestDoneId = scans.filter(x => x.status === "completed").sort((a, b) => b.id - a.id)[0]?.id;
  useEffect(() => {
    if (!latestDoneId) return;
    let live = true;
    getScanChanges(latestDoneId, { collapse_cves: true })
      .then(r => {
        if (!live) return;
        const counts = r.data.counts || {};
        setLatestChanges({ scanId: latestDoneId, counts, total: Object.values(counts).reduce((a, b) => a + b, 0),
          pending: r.data.pending_removals || 0, baseline: !!r.data.is_baseline });
      })
      .catch(() => {});
    return () => { live = false; };
  }, [latestDoneId]);

  const targetMap = {};
  targets.forEach(t => { targetMap[t.id] = t.domain; });

  const completedScans = scans.filter(s => s.status === "completed").length;
  // Live inventory: summing total_assets across scans double-counted every re-scan
  const totalAssets = assets.filter(a => a.status !== "disappeared").length;
  const critHighVulns = (vulnSummary.critical || 0) + (vulnSummary.high || 0);

  const highRiskCount = assets.filter(a =>
    a.risk_level === "Critical" || a.risk_level === "High"
  ).length;

  const topRiskAssets = [...assets]
    .filter(a => a.risk_score != null && a.risk_score > 0 && a.status !== "disappeared")
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 5);

  if (loading) return <div className="dashboard"><h1>Overview</h1><Skeleton rows={5} height={56} /></div>;

  return (
    <div className="dashboard">
      <h1>Overview</h1>

      <div className="tiles">
        <Stat value={targets.length} label="Targets" />
        <Stat value={totalAssets} label="Live assets" />
        <Stat value={completedScans} label="Completed scans" />
        <Stat value={critHighVulns} label="Critical and high findings" tone={critHighVulns > 0 ? "bad" : ""} />
        <Stat value={highRiskCount} label="High-risk assets" tone={highRiskCount > 0 ? "bad" : ""} />
      </div>

      <div className="attention">
        <Link to="/changes" className="attention-item">
          <div className="attention-title">Latest changes</div>
          {!latestChanges ? <div className="muted-note">No completed scan yet.</div>
            : latestChanges.baseline ? <div className="muted-note">Scan #{latestChanges.scanId} set the baseline. Changes appear from the next scan.</div>
            : latestChanges.total === 0 ? <div className="muted-note">Nothing changed in scan #{latestChanges.scanId}.</div>
            : (
              <div className="attention-counts">
                {["critical", "high", "medium", "low", "info"].filter(k => latestChanges.counts[k]).map(k => (
                  <span key={k} className={"badge badge-sev-" + k}>{latestChanges.counts[k]} {k}</span>
                ))}
                {latestChanges.pending > 0 && <span className="muted-note">{latestChanges.pending} awaiting confirmation</span>}
              </div>
            )}
        </Link>
        <Link to="/alerts" className="attention-item">
          <div className="attention-title">Alerts</div>
          {unread > 0
            ? <div className="attention-counts"><span className="badge badge-pending">{unread >= 100 ? "100+" : unread} unread</span></div>
            : <div className="muted-note">You are all caught up.</div>}
        </Link>
      </div>

      {topRiskAssets.length > 0 && (
        <section className="dash-section">
          <h2>Highest-risk assets</h2>
          <div className="dl" style={{ "--cols": "minmax(0,2fr) minmax(0,1.2fr) 110px 60px" }}>
            {topRiskAssets.map(a => (
              <div className="dl-item" key={a.id}>
                <div className="dl-row">
                  <div className="dl-main"><div className="dl-title mono">{a.subdomain}</div></div>
                  <div className="dl-main">{targetMap[a.target_id] || `Target #${a.target_id}`}</div>
                  <div><span className={`badge badge-risk-${(a.risk_level || "low").toLowerCase()}`}>{a.risk_level}</span></div>
                  <div className="dl-num">{a.risk_score}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="dash-section">
        <h2>Recent scans {scans.length > 8 && <Link to="/scans" className="see-all">View all {scans.length}</Link>}</h2>
        <div className="dl" style={{ "--cols": "minmax(0,1.6fr) minmax(0,1.4fr) minmax(90px,1fr) minmax(90px,1fr)" }}>
          {scans.slice(0, 8).map(scan => {
            const noResults = scan.status === "completed" && !(scan.total_assets > 0);
            const duration = (scan.started_at && scan.completed_at)
              ? Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000) : null;
            const durationLabel = duration == null ? "—" : duration < 60 ? `${duration}s` : `${Math.floor(duration / 60)}m ${duration % 60}s`;
            return (
              <div className="dl-item" key={scan.id} style={noResults ? { opacity: 0.55 } : undefined}>
                <div className="dl-row">
                  <div className="dl-main">
                    <div className="dl-title">{scan.target_domain || targetMap[scan.target_id] || "Target #" + scan.target_id}</div>
                    <div className="dl-sub">Scan #{scan.id} · {durationLabel}</div>
                  </div>
                  <div className="dl-flags" style={{ alignItems: "center" }}>
                    <span className={"badge badge-" + scan.status}>{scan.status}</span>
                    <ProfileBadge name={scan.profile} />
                  </div>
                  <div className="dl-main">
                    <div className="dl-title" style={{ fontWeight: 400 }}>{scan.total_assets || 0} assets</div>
                    <div className="dl-sub">+{scan.new_assets || 0} new · {scan.changed_assets || 0} changed</div>
                  </div>
                  <div className="dl-main" title={scan.started_at ? new Date(scan.started_at).toLocaleString() : ""}>
                    {scan.started_at ? timeAgo(scan.started_at) : "—"}
                  </div>
                </div>
              </div>
            );
          })}
          {scans.length === 0 && <div className="empty">No scans yet. Add a target on the Targets page and run the first scan.</div>}
        </div>
      </section>
    </div>
  );
}
