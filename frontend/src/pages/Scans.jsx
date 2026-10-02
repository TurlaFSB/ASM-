import { useState, useEffect } from "react";
import { Activity, X, Download } from "lucide-react";
import { getScans, getScanProgress, cancelScan, downloadScanReport } from "../api";
import { ProfileBadge } from "../components/ProfilePicker";

const STAGE_LABELS = {
  subdomain_enumeration: "Subfinder + Amass",
  dns_resolution: "DNS Resolution",
  whois_asn_lookup: "WHOIS / ASN",
  port_scanning: "Nmap Port Scan",
  http_probing: "HTTPX Probing",
  web_analysis: "Web analysis (WhatWeb, dirs, Nuclei, TLS, screenshots in parallel)",
  tech_fingerprinting: "WhatWeb",
  dir_discovery: "Directory Discovery",
  vuln_scanning: "Nuclei Scan",
  tls_analysis: "TLS Analysis (sslyze)",
  screenshots: "EyeWitness",
  saving_results: "Saving Results",
  risk_scoring: "Risk Scoring",
};

// Pipeline order, used for the progress bar while a scan runs
const STAGE_ORDER = [
  "subdomain_enumeration", "dns_resolution", "whois_asn_lookup", "port_scanning",
  "http_probing", "web_analysis", "saving_results", "risk_scoring",
];

const MODULE_LABELS = {
  subfinder: "subfinder", amass: "amass", dns: "dns", whois_asn: "whois",
  portscan: "nmap", httpprobe: "httpx", whatweb: "whatweb", dirbuster: "dirs",
  vuln: "nuclei", nuclei_network: "net-nuclei", cve_match: "cve", sslyze: "tls", screenshot: "shots",
};

function formatDuration(seconds) {
  if (seconds == null || seconds < 0) return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  return m < 60 ? `${m}m ${seconds % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

function scanDuration(scan) {
  if (!scan.started_at) return null;
  const end = scan.completed_at ? new Date(scan.completed_at) : (scan.status === "running" ? new Date() : null);
  return end ? Math.round((end - new Date(scan.started_at)) / 1000) : null;
}

function moduleColor(status) {
  const v = String(status || "").toLowerCase();
  if (v.startsWith("ok") || v.startsWith("completed") || v.startsWith("resolved")) return "var(--green)";
  if (v.startsWith("skipped") || v.startsWith("no ") || v === "empty") return "var(--text-secondary)";
  if (v.startsWith("partial") || v.startsWith("timeout")) return "var(--orange)";
  return "var(--red, #ef4444)";
}

function ModuleChips({ results }) {
  if (!results || typeof results !== "object") return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
      {Object.entries(MODULE_LABELS).map(([key, label]) =>
        results[key] === undefined ? null : (
          <span key={key} title={`${label}: ${String(results[key])}`}
            style={{ fontSize: 10, padding: "1px 6px", borderRadius: 8,
                     border: `1px solid ${moduleColor(results[key])}`, color: moduleColor(results[key]) }}>
            {label}
          </span>
        )
      )}
    </div>
  );
}

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
      try {
        await cancelScan(id);
      } catch (err) {
        alert(err?.response?.data?.detail || "Could not cancel the scan.");
      }
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
              <th>Duration</th>
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
                  {scan.target_domain || "Target #" + scan.target_id}
                </td>
                <td>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className={"badge badge-" + scan.status}>
                      {scan.status}
                    </span>
                    <ProfileBadge name={scan.profile} />
                  </div>
                  {scan.status !== "running" && <ModuleChips results={scan.module_results} />}
                  {scan.status === "running" && stages[scan.id] && (
                    <>
                      <div className="progress-stage" style={{ marginTop: 6 }}>
                        {STAGE_LABELS[stages[scan.id]] || stages[scan.id]}
                      </div>
                      <div className="scan-progress" title={`Stage ${Math.max(1, STAGE_ORDER.indexOf(stages[scan.id]) + 1)} of ${STAGE_ORDER.length}`}>
                        <div style={{ width: `${Math.round(((STAGE_ORDER.indexOf(stages[scan.id]) + 1) / STAGE_ORDER.length) * 100)}%` }} />
                      </div>
                    </>
                  )}
                </td>
                <td>{scan.total_assets || 0}</td>
                <td style={{ color: "var(--green)" }}>{scan.new_assets || 0}</td>
                <td style={{ color: "var(--orange)" }}>{scan.changed_assets || 0}</td>
                <td style={{ fontSize: 12 }} title={scan.completed_at ? `Completed ${new Date(scan.completed_at).toLocaleString()}` : ""}>
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                </td>
                <td className="mono-dim">{formatDuration(scanDuration(scan))}</td>
                <td>
                  <div className="actions">
                  {(scan.status === "running" || scan.status === "pending") && (
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
                  </div>
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
