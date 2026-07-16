import { useState, useEffect } from "react";
import api, { getTargets, getScans, getAssets } from "../api";
import { Shield, Activity, AlertTriangle, CheckCircle, Flame } from "lucide-react";

export default function Dashboard() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getTargets(), getScans(), getAssets()])
      .then(([t, s, a]) => {
        setTargets(t.data);
        setScans(s.data);
        setAssets(a.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const targetMap = {};
  targets.forEach(t => { targetMap[t.id] = t.domain; });

  const completedScans = scans.filter(s => s.status === "completed").length;
  const runningScans = scans.filter(s => s.status === "running").length;
  const totalAssets = scans.reduce((acc, s) => acc + (s.total_assets || 0), 0);

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
            <p>Total Assets</p>
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
          <Flame size={24} style={{ color: highRiskCount > 0 ? "var(--red)" : undefined }} />
          <div>
            <h3 style={{ color: highRiskCount > 0 ? "var(--red)" : undefined }}>{highRiskCount}</h3>
            <p>High/Critical Risk Assets</p>
          </div>
        </div>
      </div>

      {topRiskAssets.length > 0 && (
        <div className="recent-scans" style={{ marginBottom: 32 }}>
          <h2>Highest Risk Assets</h2>
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
                    <span className={`badge badge-risk-${a.risk_level.toLowerCase()}`}>
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
        <h2>Recent Scans</h2>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Assets</th>
              <th>New</th>
              <th>Changed</th>
              <th>Duration</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => {
              const noResults = scan.status === "completed" && !(scan.total_assets > 0);
              const duration = (scan.started_at && scan.completed_at)
                ? Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000)
                : null;
              const durationLabel = duration == null ? "—"
                : duration < 60 ? `${duration}s`
                : `${Math.floor(duration / 60)}m ${duration % 60}s`;
              const started = scan.started_at ? new Date(scan.started_at) : null;
              const minsAgo = started ? Math.round((Date.now() - started) / 60000) : null;
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
