import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getTargets, getScans, getAssets, getVulnSummary, getUnreadAlerts, getScanChanges } from "../api";
import { ProfileBadge } from "../components/ProfilePicker";
import { Shield, Activity, AlertTriangle, CheckCircle, Flame } from "lucide-react";

export default function Dashboard() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [vulnSummary, setVulnSummary] = useState({});
  const [unread, setUnread] = useState(0);
  const [latestChanges, setLatestChanges] = useState(null);   // { scanId, counts, total, pending, baseline }
  const [loading, setLoading] = useState(true);
  const [now] = useState(() => Date.now());  // relative times are computed against page-load time

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

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="dashboard">
      <h1>Attack Surface Overview</h1>

      <div className="stats-grid">
        <div className="stat-card">
          <Shield size={24} />
          <div>
            <h3>{targets.length}</h3>
            <p>Targets</p>
          </div>
        </div>
        <div className="stat-card">
          <Activity size={24} />
          <div>
            <h3>{totalAssets}</h3>
            <p>Live Assets</p>
          </div>
        </div>
        <div className="stat-card">
          <CheckCircle size={24} />
          <div>
            <h3>{completedScans}</h3>
            <p>Completed Scans</p>
          </div>
        </div>
        <div className="stat-card">
          <AlertTriangle size={24} style={{ color: critHighVulns > 0 ? "var(--red)" : undefined }} />
          <div>
            <h3 style={{ color: critHighVulns > 0 ? "var(--red)" : undefined }}>{critHighVulns}</h3>
            <p>Critical/High Vulns</p>
          </div>
        </div>
        <div className="stat-card">
          <Flame size={24} style={{ color: highRiskCount > 0 ? "var(--red)" : undefined }} />
          <div>
            <h3 style={{ color: highRiskCount > 0 ? "var(--red)" : undefined }}>{highRiskCount}</h3>
            <p>High/Critical Risk Assets</p>
          </div>
        </div>
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
        <div className="recent-scans" style={{ marginBottom: 32 }}>
          <h2>Top Risk-Scored Assets</h2>
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Target</th>
                <th>Risk Level</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {topRiskAssets.map(a => (
                <tr key={a.id}>
                  <td className="mono">{a.subdomain}</td>
                  <td>{targetMap[a.target_id] || `Target #${a.target_id}`}</td>
                  <td>
                    <span className={`badge badge-risk-${(a.risk_level || "low").toLowerCase()}`}>
                      {a.risk_level}
                    </span>
                  </td>
                  <td style={{ fontFamily: "monospace" }}>{a.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="recent-scans">
        <h2>Recent Scans {scans.length > 8 && <Link to="/scans" className="see-all">View all {scans.length}</Link>}</h2>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Profile</th>
              <th>Assets</th>
              <th>New</th>
              <th>Changed</th>
              <th>Duration</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 8).map(scan => {
              const noResults = scan.status === "completed" && !(scan.total_assets > 0);
              const duration = (scan.started_at && scan.completed_at)
                ? Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000)
                : null;
              const durationLabel = duration == null ? "—"
                : duration < 60 ? `${duration}s`
                : `${Math.floor(duration / 60)}m ${duration % 60}s`;
              const started = scan.started_at ? new Date(scan.started_at) : null;
              const minsAgo = started ? Math.round((now - started) / 60000) : null;
              const relTime = minsAgo == null ? "—"
                : minsAgo < 1 ? "just now"
                : minsAgo < 60 ? `${minsAgo}m ago`
                : minsAgo < 1440 ? `${Math.floor(minsAgo / 60)}h ago`
                : started.toLocaleDateString();
              return (
                <tr key={scan.id} style={noResults ? { opacity: 0.45 } : undefined}>
                  <td style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                    {scan.target_domain || targetMap[scan.target_id] || "Target #" + scan.target_id}
                  </td>
                  <td>
                    <span className={"badge badge-" + scan.status}>
                      {scan.status}
                    </span>
                  </td>
                  <td><ProfileBadge name={scan.profile} /></td>
                  <td>{scan.total_assets || 0}</td>
                  <td>{scan.new_assets || 0}</td>
                  <td>{scan.changed_assets || 0}</td>
                  <td style={{ fontFamily: "monospace", fontSize: 12 }}>{durationLabel}</td>
                  <td title={started ? started.toLocaleString() : ""}>{relTime}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
