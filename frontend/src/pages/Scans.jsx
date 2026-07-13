import { useState, useEffect, useRef } from "react";
import { getScans, getScanAssets, getTargets } from "../api";
import { Activity, ChevronDown, ChevronUp, Loader } from "lucide-react";
import axios from "axios";

const API = "http://192.168.16.130:8000";

const STAGES = {
  subdomain_enumeration: "Running subdomain enumeration...",
  dns_resolution: "Resolving DNS for live hosts...",
  port_scanning: "Scanning open ports...",
  http_probing: "Probing HTTP services...",
  vuln_scanning: "Running vulnerability scan...",
  screenshots: "Capturing screenshots...",
  saving_results: "Saving results to database...",
  unknown: "Processing..."
};

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [assets, setAssets] = useState({});
  const [progress, setProgress] = useState({});
  const pollRef = useRef({});

  const fetchScans = () => {
    Promise.all([getScans(), getTargets()])
      .then(([s, t]) => {
        setScans(s.data);
        setTargets(t.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Poll progress for running scans
  useEffect(() => {
    scans.forEach(scan => {
      if (scan.status === "running" || scan.status === "pending") {
        if (!pollRef.current[scan.id]) {
          pollRef.current[scan.id] = setInterval(async () => {
            try {
              const r = await axios.get(API + "/scans/" + scan.id + "/progress");
              setProgress(prev => ({ ...prev, [scan.id]: r.data }));
              if (r.data.status === "completed" || r.data.status === "failed" || r.data.status === "cancelled") {
                clearInterval(pollRef.current[scan.id]);
                delete pollRef.current[scan.id];
                fetchScans();
              }
            } catch (e) {
              console.error(e);
            }
          }, 5000);
        }
      }
    });

    return () => {
      Object.values(pollRef.current).forEach(clearInterval);
    };
  }, [scans]);

  const targetMap = {};
  targets.forEach(t => { targetMap[t.id] = t.domain; });

  const toggleExpand = async (scanId) => {
    if (expanded === scanId) {
      setExpanded(null);
      return;
    }
    setExpanded(scanId);
    if (!assets[scanId]) {
      try {
        const r = await getScanAssets(scanId);
        setAssets(prev => ({ ...prev, [scanId]: r.data }));
      } catch (e) {
        console.error(e);
      }
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Scan History</h1>
        <Activity size={24} />
      </div>

      <div className="scans-list">
        {scans.map(scan => (
          <div key={scan.id} className="scan-card">
            <div className="scan-header" onClick={() => toggleExpand(scan.id)}>
              <div className="scan-info">
                <span className={"badge badge-" + scan.status}>{scan.status}</span>
                <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>
                  {targetMap[scan.target_id] || "Target #" + scan.target_id}
                </span>
                <span>{scan.total_assets || 0} assets</span>
                <span style={{ color: "var(--green)" }}>{scan.new_assets || 0} new</span>
                <span style={{ color: "var(--orange)" }}>{scan.changed_assets || 0} changed</span>
              </div>
              <div className="scan-meta">
                {(scan.status === "running" || scan.status === "pending") && progress[scan.id] && (
                  <span className="progress-stage">
                    <Loader size={12} className="spin" />
                    {STAGES[progress[scan.id].stage] || STAGES.unknown}
                  </span>
                )}
                <span>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "Pending"}</span>
                {(scan.status === "running" || scan.status === "pending") && (
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      fetch(API + "/scans/" + scan.id + "/cancel", { method: "PATCH" })
                        .then(() => fetchScans());
                    }}
                  >
                    Cancel
                  </button>
                )}
                {expanded === scan.id ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
              </div>
            </div>

            {expanded === scan.id && (
              <div className="scan-assets">
                {scan.module_results && (
                  <div className="module-results">
                    <h4>Module Results</h4>
                    <div className="module-grid">
                      {Object.entries(scan.module_results).map(([mod, status]) => (
                        <span key={mod} className={"module-badge " + (status === "ok" ? "ok" : "fail")}>
                          {mod}: {status}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <h4>Assets Discovered</h4>
                {assets[scan.id] ? (
                  <table>
                    <thead>
                      <tr>
                        <th>Subdomain</th>
                        <th>IP</th>
                        <th>Status</th>
                        <th>HTTP</th>
                        <th>Title</th>
                        <th>Technologies</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assets[scan.id].map(asset => (
                        <tr key={asset.id}>
                          <td>{asset.subdomain}</td>
                          <td>{asset.ip}</td>
                          <td><span className={"badge badge-" + asset.status}>{asset.status}</span></td>
                          <td>{asset.http_status || "—"}</td>
                          <td>{asset.http_title || "—"}</td>
                          <td>{asset.technologies ? asset.technologies.join(", ") : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="loading">Loading assets...</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}