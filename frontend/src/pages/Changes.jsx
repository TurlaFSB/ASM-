import React, { useState, useEffect, useMemo } from "react";
import { GitCompare, ChevronDown, ChevronRight } from "lucide-react";
import { getScans, getScanChanges, getChanges } from "../api";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CATEGORIES = ["asset", "port", "technology", "http", "path", "finding"];
const CATEGORY_LABELS = { asset: "Assets", port: "Ports", technology: "Technologies", http: "HTTP", path: "Paths", finding: "Findings" };
const CHANGE_COLOR = { added: "var(--orange)", removed: "var(--green)", modified: "var(--blue)" };

const sevRank = (s) => (SEVERITIES.includes(s) ? SEVERITIES.indexOf(s) : SEVERITIES.length);
const fmtTime = (t) => (t ? new Date(t).toLocaleString() : "—");

export default function Changes() {
  const [scans, setScans] = useState([]);
  const [targetId, setTargetId] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [data, setData] = useState(null);          // /changes/scans/{id}
  const [pending, setPending] = useState([]);      // pending removals recorded by this scan
  const [tab, setTab] = useState("confirmed");     // confirmed | pending
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [open, setOpen] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    getScans()
      .then(r => {
        const done = r.data.filter(s => s.status === "completed").sort((a, b) => b.id - a.id);
        setScans(done);
        if (done.length) { setTargetId(done[0].target_id); setScanId(done[0].id); }
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let live = true;
    Promise.all([
      getScanChanges(scanId, { collapse_cves: true }),
      getChanges({ scan_id: scanId, status: "pending", limit: 500 }),
    ])
      .then(([c, p]) => { if (live) { setData(c.data); setPending(p.data); setError(false); } })
      .catch(() => { if (live) setError(true); });
    return () => { live = false; };
  }, [scanId]);

  const targets = useMemo(() => {
    const m = new Map();
    scans.forEach(s => { if (!m.has(s.target_id)) m.set(s.target_id, s.target_domain || `Target #${s.target_id}`); });
    return [...m.entries()];
  }, [scans]);
  const targetScans = scans.filter(s => s.target_id === targetId);

  const selectScan = (id) => {            // reset the per-scan view state together with the selection
    setScanId(id); setTab("confirmed"); setOpen({}); setSeverity("all"); setCategory("all");
  };
  const changeTarget = (id) => {
    const first = scans.find(s => s.target_id === id);
    setTargetId(id);
    selectScan(first ? first.id : null);
  };

  const chip = (active) => ({
    padding: "4px 12px", borderRadius: 14, fontSize: 12, cursor: "pointer",
    border: "1px solid var(--border)", background: active ? "var(--surface-3)" : "transparent",
    color: active ? "var(--text-primary)" : "var(--text-secondary)",
  });

  const current = data && data.scan_id === scanId ? data : null;   // ignore a stale result while another loads
  const events = current ? current.events : [];
  const rollups = current ? current.rollups : [];
  const shown = (tab === "pending" ? pending : events)
    .filter(e => (severity === "all" || e.severity === severity) && (category === "all" || e.category === category))
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.category.localeCompare(b.category) || a.asset.localeCompare(b.asset));
  const shownRollups = tab === "pending" ? [] : rollups.filter(r =>
    (severity === "all" || r.severity === severity) && (category === "all" || category === "finding"));

  const total = events.length + rollups.reduce((n, r) => n + r.shown, 0);
  const lowCoverage = current ? current.not_compared.filter(n => /low coverage/i.test(n.reason)) : [];
  const otherSkips = current ? current.not_compared.filter(n => !/low coverage/i.test(n.reason)) : [];
  const key = (r) => `${r.asset}|${r.component}|${r.change_type}`;

  if (loading) return <div className="page"><div className="loading">Loading...</div></div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Changes</h1>
        <GitCompare size={24} color="var(--accent)" />
      </div>

      {scans.length === 0 ? (
        <div className="empty">No completed scans yet. Run a scan, then run another to see what changed.</div>
      ) : (
        <>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: 12, color: "var(--text-tertiary)" }}>Target</span>
            <select className="wordlist-select" value={targetId ?? ""} onChange={e => changeTarget(Number(e.target.value))}>
              {targets.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
            <span style={{ fontSize: 12, color: "var(--text-tertiary)" }}>Scan</span>
            <select className="wordlist-select" value={scanId ?? ""} onChange={e => selectScan(Number(e.target.value))}>
              {targetScans.map(s => (
                <option key={s.id} value={s.id}>
                  #{s.id} · {s.profile || "standard"} · {fmtTime(s.completed_at || s.started_at)}
                </option>
              ))}
            </select>
          </div>

          {error && <div className="empty" style={{ marginTop: 16 }}>Could not load the changes for this scan.</div>}
          {!error && !current && <div className="loading">Loading changes...</div>}

          {current && (
            <>
              <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 14 }}>
                {current.is_baseline
                  ? <>Scan #{current.scan_id} is the <strong>baseline</strong> for the {current.profile} profile: nothing to compare against yet. Changes appear from the next scan.</>
                  : <>Scan #{current.scan_id} compared with scan #{current.baseline_scan_id} ({current.profile} profile): <strong>{total}</strong> change{total === 1 ? "" : "s"}
                    {current.pending_removals > 0 && <>, <strong>{current.pending_removals}</strong> removal{current.pending_removals === 1 ? "" : "s"} awaiting confirmation</>}.</>}
              </div>

              {!current.is_baseline && (
                <div className="vuln-summary" style={{ marginTop: 14 }}>
                  {["critical", "high", "medium", "low"].map(sev => {
                    const n = (current.counts[sev] || 0);
                    return (
                      <div key={sev} className={"vuln-stat sev-" + sev + (severity === sev ? " active" : "")}
                        onClick={() => setSeverity(severity === sev ? "all" : sev)}>
                        <span className="vuln-count">{n}</span>
                        <span className="vuln-label">{sev.toUpperCase()}</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {lowCoverage.length > 0 && (
                <div style={{ marginTop: 14, padding: "10px 14px", border: "1px solid var(--orange)", borderRadius: "var(--radius)", fontSize: 12 }}>
                  <strong style={{ color: "var(--orange)" }}>Low coverage.</strong> Some services were not fully tested in this scan, so their removals are held
                  as pending instead of being reported as fixed:
                  <ul style={{ margin: "6px 0 0 18px" }}>{lowCoverage.map((n, i) => <li key={i}>{n.reason}</li>)}</ul>
                </div>
              )}
              {otherSkips.length > 0 && (
                <details style={{ marginTop: 10, fontSize: 12, color: "var(--text-secondary)" }}>
                  <summary style={{ cursor: "pointer" }}>Not compared ({otherSkips.length})</summary>
                  <ul style={{ margin: "6px 0 0 18px" }}>
                    {otherSkips.map((n, i) => <li key={i}><span className="mono">{n.section}</span>: {n.reason}</li>)}
                  </ul>
                </details>
              )}

              {!current.is_baseline && (
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16, alignItems: "center" }}>
                  <button style={chip(tab === "confirmed")} onClick={() => setTab("confirmed")}>Changes ({total})</button>
                  <button style={chip(tab === "pending")} onClick={() => setTab("pending")}>Awaiting confirmation ({pending.length})</button>
                  <span style={{ fontSize: 12, color: "var(--text-tertiary)", marginLeft: 12 }}>Category</span>
                  <button style={chip(category === "all")} onClick={() => setCategory("all")}>All</button>
                  {CATEGORIES.map(c => (
                    <button key={c} style={chip(category === c)} onClick={() => setCategory(category === c ? "all" : c)}>{CATEGORY_LABELS[c]}</button>
                  ))}
                  {severity !== "all" && <button style={chip(false)} onClick={() => setSeverity("all")}>Clear severity: {severity} ✕</button>}
                </div>
              )}
              {tab === "pending" && !current.is_baseline && (
                <div style={{ fontSize: 12, color: "var(--text-tertiary)", marginTop: 8 }}>
                  Something present in the previous scan was missing in this one. It is only reported as removed if the next comparable scan
                  also misses it; if it comes back, it was a flap and is dropped.
                </div>
              )}

              {!current.is_baseline && (
                <div className="table-container" style={{ marginTop: 16 }}>
                  {(shown.length > 0 || shownRollups.length > 0) ? (
                    <table>
                      <thead>
                        <tr><th>Severity</th><th>Change</th><th>Category</th><th>Where</th><th>What</th></tr>
                      </thead>
                      <tbody>
                        {shownRollups.map(r => (
                          <React.Fragment key={key(r)}>
                            <tr style={{ cursor: "pointer" }} onClick={() => setOpen(o => ({ ...o, [key(r)]: !o[key(r)] }))}>
                              <td><span className={"badge badge-sev-" + r.severity}>{r.severity}</span></td>
                              <td style={{ color: CHANGE_COLOR[r.change_type] }}>{r.change_type}</td>
                              <td>Findings</td>
                              <td style={{ fontFamily: "monospace", fontSize: 12 }}>{r.asset}</td>
                              <td className="wrap">
                                {open[key(r)] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}{" "}
                                {r.shown} CVE{r.shown === 1 ? "" : "s"} {r.change_type === "removed" ? "no longer match" : "now match"} <strong>{r.component}</strong>
                                {r.kev_count > 0 && <span className="badge badge-sev-critical" style={{ marginLeft: 6 }}>KEV {r.kev_count}</span>}
                                <span className="badge badge-sev-info" style={{ marginLeft: 6 }} title="Inferred from a service version">Unverified</span>
                              </td>
                            </tr>
                            {open[key(r)] && r.cves.map(c => (
                              <tr key={`${key(r)}-${c.event_id}`}>
                                <td style={{ paddingLeft: 24 }}><span className={"badge badge-sev-" + c.severity}>{c.severity}</span></td>
                                <td colSpan={3} style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                                  {c.cvss != null ? `CVSS ${Number(c.cvss).toFixed(1)}` : ""} {c.kev && <span className="badge badge-sev-critical">KEV</span>}
                                </td>
                                <td>
                                  {c.cve_id ? <a className="cve-link" target="_blank" rel="noreferrer" href={"https://nvd.nist.gov/vuln/detail/" + c.cve_id}>{c.cve_id}</a> : "—"}
                                </td>
                              </tr>
                            ))}
                          </React.Fragment>
                        ))}
                        {shown.map(e => (
                          <tr key={e.id}>
                            <td><span className={"badge badge-sev-" + e.severity}
                              title={e.rule_severity && e.rule_severity !== e.severity ? `Rules said ${e.rule_severity}; AI triage adjusted it` : undefined}>{e.severity}</span></td>
                            <td style={{ color: CHANGE_COLOR[e.change_type] }}>{e.change_type}</td>
                            <td>{CATEGORY_LABELS[e.category] || e.category}</td>
                            <td style={{ fontFamily: "monospace", fontSize: 12 }}>{e.asset || "—"}</td>
                            <td className="wrap">
                              {e.summary}
                              {e.confidence === "inferred" && <span className="badge badge-sev-info" style={{ marginLeft: 6 }} title="Inferred, not confirmed by a scanner check">Inferred</span>}
                              {e.ai && (
                                <div style={{ marginTop: 4, fontSize: 12, color: "var(--text-dim, #94a3b8)" }}>
                                  <span className="badge badge-sev-info" style={{ marginRight: 6 }} title={`Advisory, generated by ${e.ai.model}. Check it before acting.`}>AI</span>
                                  {e.ai.summary} <strong style={{ fontWeight: 600 }}>Next:</strong> {e.ai.action}
                                  {e.ai.severity && e.ai.severity !== e.severity && (
                                    <span style={{ marginLeft: 6 }}>(AI rates this {e.ai.severity}; the rules say {e.severity})</span>
                                  )}
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="empty">
                      {tab === "pending" ? "Nothing is awaiting confirmation."
                        : (severity !== "all" || category !== "all") ? "No changes match these filters."
                          : `No changes since scan #${current.baseline_scan_id}.`}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
