import { useState, useEffect } from "react";
import { getScans, getScanAssets } from "../api";
import { Activity, ChevronDown, ChevronUp } from "lucide-react";

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [assets, setAssets] = useState({});

  useEffect(() => {
    getScans()
      .then(r => setScans(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

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
                <span className={`badge badge-${scan.status}`}>{scan.status}</span>
                <span>Scan #{scan.id}</span>
                <span>Target ID: {scan.target_id}</span>
                <span>{scan.total_assets || 0} assets</span>
                <span className="new-badge">{scan.new_assets || 0} new</span>
                <span className="changed-badge">{scan.changed_assets || 0} changed</span>
              </div>
              <div className="scan-meta">
                <span>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "Pending"}</span>
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
                        <span key={mod} className={`module-badge ${status === 'ok' ? 'ok' : 'fail'}`}>
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
                          <td><span className={`badge badge-${asset.status}`}>{asset.status}</span></td>
                          <td>{asset.http_status || "—"}</td>
                          <td>{asset.http_title || "—"}</td>
                          <td>{asset.technologies?.join(", ") || "—"}</td>
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