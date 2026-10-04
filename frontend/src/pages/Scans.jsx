import React, { useState, useEffect } from "react";
import { X, Download, ChevronRight, FileSpreadsheet, FileJson, ShieldCheck, Image } from "lucide-react";
import Skeleton from "../components/Skeleton";
import { timeAgo } from "../lib/time";
import { getScans, getScanProgress, cancelScan, downloadScanReport, downloadScanExport } from "../api";
import RowMenu from "../components/RowMenu";
import ScreenshotGallery from "../components/ScreenshotGallery";
import { ProfileBadge } from "../components/ProfilePicker";
import Collapse from "../components/Collapse";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/toastContext";

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

// ok | skipped | attention. Skipped is neutral: a profile that does not run a stage is not a problem.
function stageTone(status) {
  const v = String(status || "").toLowerCase();
  if (v.startsWith("ok") || v.startsWith("completed") || v.startsWith("resolved")) return v.includes("low coverage") ? "attention" : "ok";
  if (v.startsWith("skipped") || v.startsWith("no ") || v === "empty") return "skipped";
  return "attention";
}

// One quiet line instead of a chip per stage: only stages that need a look get a chip of their own.
// "Details" opens the full list.
function StageSummary({ results, open, onToggle }) {
  if (!results || typeof results !== "object") return null;
  const stages = Object.entries(MODULE_LABELS)
    .filter(([key]) => results[key] !== undefined)
    .map(([key, label]) => ({ key, label, status: String(results[key]), tone: stageTone(results[key]) }));
  if (!stages.length) return null;
  const ok = stages.filter(s => s.tone === "ok").length;
  const skipped = stages.filter(s => s.tone === "skipped").length;
  const attention = stages.filter(s => s.tone === "attention");
  return (
    <div className="stage-summary">
      <div className="stage-line">
        <span className={attention.length ? "" : "stage-ok"}>
          {attention.length
            ? `${ok} of ${stages.length - skipped} stages ok`
            : `All ${ok} stages ok`}
          {skipped > 0 && <span className="stage-dim">, {skipped} skipped</span>}
        </span>
        {attention.map(s => (
          <span key={s.key} className="stage-chip" title={`${s.label}: ${s.status}`}>{s.label}</span>
        ))}
        <button type="button" className="stage-toggle" onClick={onToggle} aria-expanded={open}>
          <ChevronRight size={12} className={"stage-chevron" + (open ? " open" : "")} /> Details
        </button>
      </div>
      <Collapse open={open}>
        <dl className="stage-detail">
          {stages.map(s => (
            <React.Fragment key={s.key}>
              <dt>{s.label}</dt>
              <dd className={"tone-" + s.tone}>{s.status}</dd>
            </React.Fragment>
          ))}
        </dl>
      </Collapse>
    </div>
  );
}

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [stages, setStages] = useState({}); // { scanId: current_stage }
  const [openDetails, setOpenDetails] = useState({}); // { scanId: true } stage lists that are expanded
  const [cancelId, setCancelId] = useState(null);      // scan awaiting cancel confirmation
  const [galleryScan, setGalleryScan] = useState(null);   // scan whose screenshots are open
  const [cancelling, setCancelling] = useState(false);
  const { toast } = useToast();

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

  const confirmCancel = async () => {
    setCancelling(true);
    try {
      await cancelScan(cancelId);
      toast(`Scan #${cancelId} is being cancelled.`);
    } catch (err) {
      toast(err?.response?.data?.detail || "Could not cancel the scan.", "bad");
    } finally {
      setCancelling(false);
      setCancelId(null);
      fetchScans();
    }
  };

  const saveBlob = (data, type, filename) => {
    const url = window.URL.createObjectURL(new Blob([data], { type }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const exportItems = (id) => {
    const item = (label, icon, name, type) => ({
      label, icon,
      onClick: async () => {
        try {
          const r = await downloadScanExport(id, name);
          saveBlob(r.data, type, `scan_${id}_${name}`);
        } catch { toast("Could not export that file. Try again in a moment.", "bad"); }
      },
    });
    const shots = scans.find(x => x.id === id)?.module_results?.screenshot_run
      ? [{ label: "View screenshots", icon: Image, onClick: () => setGalleryScan(id) }, { type: "divider" }] : [];
    return [
      ...shots,
      item("Assets (CSV)", FileSpreadsheet, "assets.csv", "text/csv"),
      item("Findings (CSV)", FileSpreadsheet, "vulnerabilities.csv", "text/csv"),
      item("Findings (JSON)", FileJson, "vulnerabilities.json", "application/json"),
      item("Findings (SARIF)", ShieldCheck, "vulnerabilities.sarif", "application/sarif+json"),
    ];
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
      toast("Could not generate the report. Try again in a moment.", "bad");
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Scans</h1>
      </div>

      <ConfirmDialog open={cancelId !== null} tone="danger" title={`Cancel scan #${cancelId}?`} confirmLabel="Cancel scan"
        cancelLabel="Keep running" busy={cancelling} onConfirm={confirmCancel} onCancel={() => setCancelId(null)}>
        The scan stops at the next safe point. Results found so far are kept, but the scan will not complete.
      </ConfirmDialog>

      <ScreenshotGallery scanId={galleryScan} onClose={() => setGalleryScan(null)} />

      {loading ? <Skeleton rows={6} height={64} /> : (
        <div className="dl" style={{ "--cols": "minmax(150px,1.3fr) minmax(220px,2.4fr) minmax(120px,1fr) minmax(110px,1fr) 110px" }}>
          <div className="dl-head" aria-hidden="true">
            <div>Target</div><div>Status</div><div>Results</div><div>Started</div><div />
          </div>
          {scans.map(scan => {
            const running = scan.status === "running";
            const stage = stages[scan.id];
            const dur = scanDuration(scan);
            return (
              <div className="dl-item" key={scan.id}>
                <div className="dl-row">
                  <div className="dl-main">
                    <div className="dl-title">{scan.target_domain || "Target #" + scan.target_id}</div>
                    <div className="dl-sub">Scan #{scan.id}</div>
                  </div>
                  <div className="dl-main dl-col-wide">
                    <div className="dl-flags" style={{ alignItems: "center" }}>
                      <span className={"badge badge-" + scan.status}>{scan.status}</span>
                      <ProfileBadge name={scan.profile} />
                    </div>
                    {!running && (
                      <StageSummary results={scan.module_results} open={!!openDetails[scan.id]}
                        onToggle={() => setOpenDetails(o => ({ ...o, [scan.id]: !o[scan.id] }))} />
                    )}
                    {running && stage && (
                      <>
                        <div className="progress-stage" style={{ marginTop: 6 }}>{STAGE_LABELS[stage] || stage}</div>
                        <div className="scan-progress" title={`Stage ${Math.max(1, STAGE_ORDER.indexOf(stage) + 1)} of ${STAGE_ORDER.length}`}>
                          <div style={{ width: `${Math.round(((STAGE_ORDER.indexOf(stage) + 1) / STAGE_ORDER.length) * 100)}%` }} />
                        </div>
                      </>
                    )}
                  </div>
                  <div className="dl-main">
                    <div className="dl-title">{scan.total_assets || 0} assets</div>
                    <div className="dl-sub">
                      {scan.new_assets ? <span style={{ color: "var(--green)" }}>+{scan.new_assets} new</span> : "No new"}
                      {" · "}
                      {scan.changed_assets ? <span style={{ color: "var(--orange)" }}>{scan.changed_assets} changed</span> : "none changed"}
                    </div>
                  </div>
                  <div className="dl-main" title={scan.started_at ? new Date(scan.started_at).toLocaleString() : ""}>
                    <div className="dl-title" style={{ fontWeight: 400 }}>{scan.started_at ? timeAgo(scan.started_at) : "Not started"}</div>
                    <div className="dl-sub">{dur != null ? formatDuration(dur) : "—"}</div>
                  </div>
                  <div className="dl-actions">
                    {(running || scan.status === "pending") && (
                      <button className="btn btn-sm btn-danger" onClick={() => setCancelId(scan.id)}><X size={14} /> Cancel</button>
                    )}
                    {scan.status === "completed" && (
                      <>
                        <button className="btn btn-sm btn-secondary" onClick={() => handleDownloadReport(scan.id)} disabled={downloadingId === scan.id}>
                          <Download size={14} />{downloadingId === scan.id ? "Generating…" : "Report"}
                        </button>
                        <RowMenu label={`More actions for scan ${scan.id}`} items={exportItems(scan.id)} />
                      </>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          {scans.length === 0 && <div className="empty">No scans yet. Add a target and choose Scan to run the first one.</div>}
        </div>
      )}
    </div>
  );
}
