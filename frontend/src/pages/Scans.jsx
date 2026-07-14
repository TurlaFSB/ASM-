import { useState, useEffect } from "react";
import { Activity, Play, X, Download } from "lucide-react";
import { getScans, getScanProgress, cancelScan, downloadScanReport } from "../api";

const STAGE_LABELS = {
  subdomain_enumeration: "Subfinder + Amass",
  dns_resolution: "DNS Resolution",
  port_scanning: "Nmap Port Scan",
  http_probing: "HTTPX Probing",
  vuln_scanning: "Nuclei Scan",
  screenshots: "EyeWitness",
  saving_results: "Saving Results",
  risk_scoring: "Risk Scoring",
};

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [stages, setStages] = useState({}); // { scanId: current_stage }

  const fetchScans = () => {
    getScans()
      .then(r => {
        const data = r.data || [];
        setScans(data);
        // For any running scan, poll its progress for current_stage
        data.filter(s => s.status === "running").forEach(s => {
          getScanProgress(s.id)
            .then(res => {
              setStages(prev => ({ ...prev, [s.id]: res.data.current_stage }));
            })
            .catch(() => {});
        });
      })
      .catch(err => {
        console.error("Error fetching scans:", err);
        setScans([]);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleCancel = async (id) => {
    if (window.confirm("Cancel this scan?")) {
      await cancelScan(id);
      fetchScans();
    }
  };

  const handleDownloadReport = async (id) => {
    setDownloadingId(id);
    try {
      const response = await downloadScanReport(id);
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `asm_report_scan_${id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download report:", err);
      alert("Failed to generate report. Check console for details.");
    } finally {
      setDownloadingId(null);
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Scans</h1>
        <Activity size={24} />
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Target</th>
              <th>Status</th>
              <th>Assets Found</th>
              <th>New</th>
              <th>Changed</th>
              <th>Started</th>
              <th>Completed</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.id}>
                <td style={{ fontFamily: "monospace", fontSize: 12 }}>
                  #{scan.id}
                </td>
                <td style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                  {scan.target?.domain || "Target #" + scan.target_id}
                </td>
                <td>
                  <span className={"badge badge-" + scan.status}>
                    {scan.status}
                  </span>
                  {scan.status === "running" && stages[scan.id] && (
                    <div className="progress-stage" style={{ marginTop: 6 }}>
                      {STAGE_LABELS[stages[scan.id]] || stages[scan.id]}
                    </div>
                  )}
                </td>
                <td>{scan.total_assets || 0}</td>
                <td style={{ color: "var(--green)" }}>{scan.new_assets || 0}</td>
                <td style={{ color: "var(--orange)" }}>{scan.changed_assets || 0}</td>
                <td style={{ fontSize: 12 }}>
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                </td>
                <td style={{ fontSize: 12 }}>
                  {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
                </td>
                <td className="actions">
                  {scan.status === "running" && (
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleCancel(scan.id)}
                    >
                      <X size={14} /> Cancel
                    </button>
                  )}
                  {scan.status === "completed" && (
                    <button
                      className="btn btn-sm btn-primary"
                      onClick={() => handleDownloadReport(scan.id)}
                      disabled={downloadingId === scan.id}
                    >
                      <Download size={14} />
                      {downloadingId === scan.id ? "Generating..." : "Report"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {scans.length === 0 && (
          <div className="empty">No scans yet. Add a target and trigger a scan.</div>
        )}
      </div>
    </div>
  );
}
