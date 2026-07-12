import { useState, useEffect } from "react";
import { getTargets, getScans } from "../api";
import { Shield, Activity, AlertTriangle, CheckCircle } from "lucide-react";

export default function Dashboard() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getTargets(), getScans()])
      .then(([t, s]) => {
        setTargets(t.data);
        setScans(s.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const completedScans = scans.filter(s => s.status === "completed").length;
  const runningScans = scans.filter(s => s.status === "running").length;
  const totalAssets = scans.reduce((acc, s) => acc + (s.total_assets || 0), 0);

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
          <AlertTriangle size={24} />
          <div>
            <h3>{runningScans}</h3>
            <p>Running Scans</p>
          </div>
        </div>
      </div>

      <div className="recent-scans">
        <h2>Recent Scans</h2>
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Status</th>
              <th>Assets</th>
              <th>New</th>
              <th>Changed</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.id}>
                <td>Target #{scan.target_id}</td>
                <td>
                  <span className={`badge badge-${scan.status}`}>
                    {scan.status}
                  </span>
                </td>
                <td>{scan.total_assets || 0}</td>
                <td>{scan.new_assets || 0}</td>
                <td>{scan.changed_assets || 0}</td>
                <td>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
