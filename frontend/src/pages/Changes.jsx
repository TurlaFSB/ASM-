import { useState, useEffect, useMemo } from "react";
import { GitCompare, ChevronRight, Globe } from "lucide-react";
import Picker from "../components/Picker";
import Segmented from "../components/Segmented";
import Skeleton from "../components/Skeleton";
import { getScans, getScanChanges, getChanges } from "../api";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CATEGORIES = ["asset", "port", "technology", "http", "path", "finding"];
const CATEGORY_LABELS = { asset: "Assets", port: "Ports", technology: "Technologies", http: "HTTP", path: "Paths", finding: "Findings" };
const CHANGE_COLOR = { added: "var(--orange)", removed: "var(--green)", modified: "var(--blue)" };
const COLS = { "--cols": "84px 92px 104px minmax(120px,1.2fr) minmax(0,3.5fr)" };

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

  if (loading) return <div className="page"><div className="page-header"><h1>Changes</h1></div><Skeleton rows={6} /></div>;

  const tabs = [["confirmed", `Changes (${total})`], ["pending", `Awaiting confirmation (${pending.length})`]];
  const cats = [["all", "All"], ...CATEGORIES.map(c => [c, CATEGORY_LABELS[c]])];

  return (
    <div className="page">
      <div className="page-header">
        <h1>Changes</h1>
        <GitCompare size={24} color="var(--accent)" aria-hidden="true" />
      </div>

      {scans.length === 0 ? (
        <div className="empty">No completed scans yet. Run a scan, then run another to see what changed.</div>
      ) : (
        <>
          <div className="filters">
            <Picker value={targetId} onChange={changeTarget} icon={Globe} ariaLabel="Target" minWidth={260}
              options={targets.map(([id, name]) => ({ value: id, label: name }))} />
            <Picker value={scanId} onChange={selectScan} ariaLabel="Scan" minWidth={300}
              options={targetScans.map(s => ({ value: s.id, label: `Scan #${s.id} · ${s.profile || "standard"}`, hint: fmtTime(s.completed_at || s.started_at) }))} />
          </div>

          {error && <div className="empty">Could not load the changes for this scan.</div>}
          {!error && !current && <Skeleton rows={4} />}

          {current && (
            <>
              <p className="dl-note" style={{ marginTop: 14 }}>
                {current.is_baseline
                  ? <>Scan #{current.scan_id} is the <strong>baseline</strong> for the {current.profile} profile: nothing to compare against yet. Changes appear from the next scan.</>
                  : <>Scan #{current.scan_id} compared with scan #{current.baseline_scan_id} ({current.profile} profile): <strong>{total}</strong> change{total === 1 ? "" : "s"}
                    {current.pending_removals > 0 && <>, <strong>{current.pending_removals}</strong> removal{current.pending_removals === 1 ? "" : "s"} awaiting confirmation</>}.</>}
              </p>

              {!current.is_baseline && (
                <div className="tiles">
                  {["critical", "high", "medium", "low"].map(sev => (
                    <button type="button" key={sev} className={"tile sev-" + sev + (severity === sev ? " active" : "")}
                      aria-pressed={severity === sev} onClick={() => setSeverity(severity === sev ? "all" : sev)}>
                      <span className="tile-num">{current.counts[sev] || 0}</span>
                      <span className="tile-label">{sev}</span>
                    </button>
                  ))}
                </div>
              )}

              {lowCoverage.length > 0 && (
                <div className="dl-note" role="note">
                  <strong>Low coverage.</strong> Some services were not fully tested in this scan, so their removals are held
                  as pending instead of being reported as fixed:
                  <ul style={{ margin: "6px 0 0 18px" }}>{lowCoverage.map((n, i) => <li key={i}>{n.reason}</li>)}</ul>
                </div>
              )}
              {otherSkips.length > 0 && (
                <details className="dl-note">
                  <summary style={{ cursor: "pointer" }}>Not compared ({otherSkips.length})</summary>
                  <ul style={{ margin: "6px 0 0 18px" }}>
                    {otherSkips.map((n, i) => <li key={i}><span className="mono">{n.section}</span>: {n.reason}</li>)}
                  </ul>
                </details>
              )}

              {!current.is_baseline && (
                <div className="filters">
                  <Segmented value={tab} onChange={setTab} options={tabs} label="View" />
                  <span className="field-label">Category</span>
                  <Segmented value={category} onChange={setCategory} options={cats} label="Category" />
                </div>
              )}
              {tab === "pending" && !current.is_baseline && (
                <p className="dl-note">
                  Something present in the previous scan was missing in this one. It is only reported as removed if the next comparable scan
                  also misses it; if it comes back, it was a flap and is dropped.
                </p>
              )}

              {!current.is_baseline && (
                <div style={{ marginTop: 16 }}>
                  {(shown.length > 0 || shownRollups.length > 0) ? (
                    <div className="dl" style={COLS}>
                      <div className="dl-head" aria-hidden="true">
                        <div>Severity</div><div>Change</div><div>Category</div><div>Where</div><div>What</div>
                      </div>
                      {shownRollups.map(r => (
                        <div key={key(r)} className={"dl-item" + (open[key(r)] ? " open" : "")}>
                          <div className="dl-row clickable" onClick={() => setOpen(o => ({ ...o, [key(r)]: !o[key(r)] }))}>
                            <div><span className={"badge badge-sev-" + r.severity}>{r.severity}</span></div>
                            <div style={{ color: CHANGE_COLOR[r.change_type] }}>{r.change_type}</div>
                            <div>Findings</div>
                            <div className="dl-sub mono" style={{ marginTop: 0 }}>{r.asset}</div>
                            <div className="dl-main">
                              <div className="dl-title wrap">
                                <button type="button" className="dl-toggle" aria-expanded={!!open[key(r)]}>
                                  <ChevronRight size={14} className="dl-caret" />
                                  {r.shown} CVE{r.shown === 1 ? "" : "s"} {r.change_type === "removed" ? "no longer match" : "now match"} {r.component}
                                </button>
                                {r.kev_count > 0 && <span className="badge badge-sev-critical" style={{ marginLeft: 6 }}>KEV {r.kev_count}</span>}
                                <span className="badge badge-sev-info" style={{ marginLeft: 6 }} title="Inferred from a service version">Unverified</span>
                              </div>
                            </div>
                          </div>
                          {open[key(r)] && (
                            <div className="dl-sub-row">
                              {r.cves.map(c => (
                                <div className="dl-row" key={`${key(r)}-${c.event_id}`}>
                                  <div><span className={"badge badge-sev-" + c.severity}>{c.severity}</span></div>
                                  <div />
                                  <div />
                                  <div className="dl-sub" style={{ marginTop: 0 }}>
                                    {c.cvss != null ? `CVSS ${Number(c.cvss).toFixed(1)}` : ""} {c.kev && <span className="badge badge-sev-critical">KEV</span>}
                                  </div>
                                  <div>
                                    {c.cve_id ? <a className="cve-link" target="_blank" rel="noreferrer" href={"https://nvd.nist.gov/vuln/detail/" + c.cve_id}>{c.cve_id}</a> : "—"}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                      {shown.map(e => (
                        <div key={e.id} className="dl-item">
                          <div className="dl-row">
                            <div><span className={"badge badge-sev-" + e.severity}
                              title={e.rule_severity && e.rule_severity !== e.severity ? `Rules said ${e.rule_severity}; AI triage adjusted it` : undefined}>{e.severity}</span></div>
                            <div style={{ color: CHANGE_COLOR[e.change_type] }}>{e.change_type}</div>
                            <div>{CATEGORY_LABELS[e.category] || e.category}</div>
                            <div className="dl-sub mono" style={{ marginTop: 0 }}>{e.asset || "—"}</div>
                            <div className="dl-main">
                              <div className="dl-title wrap">
                                {e.summary}
                                {e.confidence === "inferred" && <span className="badge badge-sev-info" style={{ marginLeft: 6 }} title="Inferred, not confirmed by a scanner check">Inferred</span>}
                              </div>
                              {e.ai && (
                                <div className="dl-sub" style={{ whiteSpace: "normal" }}>
                                  <span className="badge badge-sev-info" style={{ marginRight: 6 }} title={`Advisory, generated by ${e.ai.model}. Check it before acting.`
                                    + (e.ai.severity && e.ai.severity !== e.severity ? ` It rates this ${e.ai.severity}; severity here comes from the rules (${e.severity}).` : "")}>AI</span>
                                  {e.ai.summary} <strong style={{ fontWeight: 600 }}>Next:</strong> {e.ai.action}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
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
