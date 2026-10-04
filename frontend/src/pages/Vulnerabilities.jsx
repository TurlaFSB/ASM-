import { useState, useEffect } from "react";
import { ChevronRight, CircleDot, ShieldOff, Clock, CheckCircle2, RotateCcw } from "lucide-react";
import Skeleton from "../components/Skeleton";
import Segmented from "../components/Segmented";
import RowMenu from "../components/RowMenu";
import Sheet from "../components/Sheet";
import useRole from "../components/useRole";
import { useToast } from "../components/toastContext";
import { getVulnRollup, getVulnSummary, setFindingTriage, getHiddenFindings } from "../api";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VM_PREFIX = "[version match] ";

const sevRank = (s) => (s in SEVERITY_ORDER ? SEVERITY_ORDER[s] : 5); // 0 is a valid rank (critical)

const TRIAGE_LABEL = { in_progress: "In progress", false_positive: "False positive", accepted_risk: "Accepted risk", resolved: "Resolved" };
const REVIEW_DAYS = [[30, "30 days"], [90, "90 days"], [180, "180 days"], [365, "1 year"]];
const SHEET_TEXT = {
  false_positive: { title: "Mark as false positive", help: "Hidden from the list and from reports, and stays hidden in future scans of the same finding.", needsNote: true },
  accepted_risk: { title: "Accept the risk", help: "Hidden until the review date, then it comes back so someone looks at it again.", needsNote: true },
};

function TriageChip({ t }) {
  if (!t) return null;
  const until = t.status === "accepted_risk" && t.expires_at ? ` until ${new Date(t.expires_at).toLocaleDateString()}` : "";
  const tip = [t.by ? `By ${t.by}` : null, t.at ? new Date(t.at).toLocaleString() : null, t.note].filter(Boolean).join(" · ");
  return <span className="badge badge-sev-info" title={tip}>{TRIAGE_LABEL[t.status] || t.status}{until}</span>;
}

export default function Vulnerabilities() {
  const role = useRole();
  const canEdit = role === "admin";
  const { toast } = useToast();
  const [triageMode, setTriageMode] = useState("active");   // active | triaged | all
  const [hidden, setHidden] = useState(0);
  const [reload, setReload] = useState(0);
  const [sheet, setSheet] = useState(null);                  // { ids, status, label }
  const [note, setNote] = useState("");
  const [days, setDays] = useState(90);
  const [saving, setSaving] = useState(false);
  const [items, setItems] = useState([]);       // roll-up: verified findings + one line per CVE component
  const [stats, setStats] = useState({ findings: 0, lines: 0 });
  const [open, setOpen] = useState({});          // expanded component lines
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");   // all | verified | version
  const [scope, setScope] = useState("latest");  // latest scan per target | all history

  useEffect(() => {
    const params = { scope, triage: triageMode };
    Promise.all([getVulnRollup(params), getVulnSummary(params), getHiddenFindings({ scope })])
      .then(([v, s, h]) => {
        setItems(v.data.items);
        setStats({ findings: v.data.findings, lines: v.data.lines });
        setSummary(s.data);
        setHidden(h.data.hidden);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scope, triageMode, reload]);

  const apply = async (ids, status, extra = {}) => {
    setSaving(true);
    try {
      await setFindingTriage({ ids, status, ...extra });
      setSheet(null); setNote("");
      setReload(n => n + 1);
    } catch (e) {
      const d = e.response?.data?.detail;
      toast(typeof d === "string" ? d : "Could not save that decision.", "bad");
    } finally { setSaving(false); }
  };

  // Menu for one finding (ids = [id]) or a whole component line (ids = all its CVEs)
  const menuFor = (ids, label, current) => {
    const pick = (status) => () => {
      if (SHEET_TEXT[status]) { setNote(""); setDays(90); setSheet({ ids, status, label }); }
      else apply(ids, status);
    };
    return [
      { label: "In progress", icon: CircleDot, onClick: pick("in_progress"), active: current === "in_progress" },
      { label: "False positive...", icon: ShieldOff, onClick: pick("false_positive"), active: current === "false_positive" },
      { label: "Accept risk...", icon: Clock, onClick: pick("accepted_risk"), active: current === "accepted_risk" },
      { label: "Resolved", icon: CheckCircle2, onClick: pick("resolved"), active: current === "resolved" },
      { type: "divider" },
      { label: "Back to open", icon: RotateCcw, onClick: pick("open") },
    ];
  };

  const changeScope = (next) => { setLoading(true); setScope(next); };
  const changeTriage = (next) => { setLoading(true); setTriageMode(next); };

  const isVerified = (it) => it.kind === "finding" && it.verified;
  const filtered = items.filter(it =>
    (severity === "all" || it.severity === severity) &&
    (source === "all" || (source === "verified" ? isVerified(it) : !isVerified(it)))
  );

  // Server already orders by urgency (severity, KEV, CVSS); keep a stable client sort too.
  const sorted = [...filtered].sort((a, b) =>
    sevRank(a.severity) - sevRank(b.severity) || (b.max_cvss ?? b.cvss_score ?? 0) - (a.max_cvss ?? a.cvss_score ?? 0)
  );

  const unverifiedCount = items.filter(it => !isVerified(it)).reduce((n, it) => n + (it.shown || 1), 0);
  const rowKey = (it) => it.kind === "component" ? `c-${it.scan_id}-${it.host}-${it.component}` : `f-${it.id}`;
  const cveUrl = (cveId) => "https://nvd.nist.gov/vuln/detail/" + cveId;
  const isKev = (v) => (v.tags || []).includes("kev");

  const SOURCES = [["all", "All"], ["verified", "Scanner-verified"], ["version", `Version match${unverifiedCount ? ` (${unverifiedCount})` : ""}`]];
  const SCOPES = [["latest", "Latest scan"], ["all", "All history"]];
  const TRIAGE_MODES = [["active", "Active"], ["triaged", "Triaged"], ["all", "Everything"]];

  const flagsFor = (it) => (
    <div className="dl-flags">
      {it.is_exploitable_confirmed && <span className="badge badge-sev-critical" title={(it.exploitability_reasons || []).join(" · ")}>Exploitable</span>}
      {(it.kev_count > 0 || isKev(it)) && <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV{it.kev_count > 1 ? ` ${it.kev_count}` : ""}</span>}
      {!isVerified(it) && <span className="badge badge-sev-info" title="Inferred from a service version; not confirmed by a scanner check">Unverified</span>}
      <TriageChip t={it.triage} />
    </div>
  );

  return (
    <div className="page">
      <div className="page-header">
        <h1>Vulnerabilities</h1>
      </div>

      <div className="tiles">
        {["critical", "high", "medium", "low"].map(sev => (
          <button type="button" key={sev} className={"tile sev-" + sev + (severity === sev ? " active" : "")}
            aria-pressed={severity === sev} onClick={() => setSeverity(severity === sev ? "all" : sev)}>
            <span className="tile-num">{summary[sev] || 0}</span>
            <span className="tile-label">{sev}</span>
          </button>
        ))}
      </div>

      <div className="filters">
        <span className="field-label">Source</span>
        <Segmented value={source} onChange={setSource} options={SOURCES} label="Source" />
        <span className="field-label" style={{ marginLeft: 8 }}>Showing</span>
        <Segmented value={scope} onChange={changeScope} options={SCOPES} label="Scope" />
        <span className="field-label" style={{ marginLeft: 8 }}>Triage</span>
        <Segmented value={triageMode} onChange={changeTriage} options={TRIAGE_MODES} label="Triage" />
      </div>
      {!loading && triageMode === "active" && hidden > 0 && (
        <p className="dl-note">{hidden} finding{hidden === 1 ? " is" : "s are"} hidden because someone marked {hidden === 1 ? "it" : "them"} as false positive, accepted risk or resolved.{" "}
          <button type="button" className="link-btn" onClick={() => changeTriage("triaged")}>Show them</button></p>
      )}

      <Sheet open={!!sheet} title={sheet ? SHEET_TEXT[sheet.status].title : ""} onClose={() => setSheet(null)}
        footer={<>
          <button type="button" className="btn btn-secondary" onClick={() => setSheet(null)}>Cancel</button>
          <button type="button" className="btn btn-primary" disabled={saving || note.trim().length < 3}
            onClick={() => apply(sheet.ids, sheet.status, { note, ...(sheet.status === "accepted_risk" ? { expires_in_days: days } : {}) })}>
            {saving ? "Saving..." : "Save decision"}
          </button>
        </>}>
        {sheet && (
          <>
            <p className="sheet-hint" style={{ marginTop: 0 }}>{sheet.label}. {SHEET_TEXT[sheet.status].help}</p>
            <div className="form-field">
              <label htmlFor="tri-note">Reason</label>
              <textarea id="tri-note" rows={4} maxLength={1000} value={note} onChange={e => setNote(e.target.value)}
                placeholder={sheet.status === "false_positive" ? "Why is this not a real issue?" : "Why is this acceptable, and what is the plan?"} />
            </div>
            {sheet.status === "accepted_risk" && (
              <div className="form-field">
                <label>Review again in</label>
                <Segmented value={days} onChange={setDays} options={REVIEW_DAYS} label="Review date" />
              </div>
            )}
          </>
        )}
      </Sheet>
      {!loading && stats.findings > stats.lines && (
        <p className="dl-note">{stats.findings} findings shown as {stats.lines} lines: version-matched CVEs are grouped per component and host. Select a component to see its CVEs.</p>
      )}
      {source !== "verified" && unverifiedCount > 0 && (
        <p className="dl-note">Version-match findings are inferred from service version strings and are unverified: distributions often backport fixes without changing the version. Treat them as leads to confirm.</p>
      )}

      <div style={{ marginTop: 16 }}>
        {loading ? <Skeleton rows={6} /> : (
          <div className="dl" style={{ "--cols": "84px minmax(0,3fr) minmax(120px,1.2fr) 52px minmax(120px,1fr) 36px" }}>
            <div className="dl-head" aria-hidden="true">
              <div>Severity</div><div>Finding</div><div>Flags</div><div className="dl-num">CVSS</div><div>CVE</div><div />
            </div>
            {sorted.map(it => it.kind === "component" ? (
              <div key={rowKey(it)} className={"dl-item" + (open[rowKey(it)] ? " open" : "")}>
                <div className="dl-row clickable" onClick={() => setOpen(o => ({ ...o, [rowKey(it)]: !o[rowKey(it)] }))}>
                  <div><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></div>
                  <div className="dl-main">
                    <div className="dl-title">
                      <button type="button" className="dl-toggle" aria-expanded={!!open[rowKey(it)]}>
                        <ChevronRight size={14} className="dl-caret" />{it.component}
                        <span style={{ color: "var(--text-secondary)", fontWeight: 400 }}>
                          {" "}· {it.capped ? `${it.shown} of ${it.total}` : it.shown} CVE{it.shown === 1 && !it.capped ? "" : "s"}{it.capped ? ", highest risk shown" : ""}
                        </span>
                      </button>
                    </div>
                    <div className="dl-sub mono">{it.host}</div>
                  </div>
                  {flagsFor(it)}
                  <div className="dl-num">{it.max_cvss ? Number(it.max_cvss).toFixed(1) : "—"}</div>
                  <div className="dl-sub" style={{ marginTop: 0 }}>{Object.entries(it.by_severity).map(([k, n]) => `${n} ${k}`).join(" · ")}</div>
                  {canEdit ? <div onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
                    <RowMenu label={`Triage all ${it.shown} CVEs of ${it.component}`} items={menuFor(it.cves.map(c => c.id), `All ${it.shown} CVE${it.shown === 1 ? "" : "s"} of ${it.component} on ${it.host}`)} />
                  </div> : <div />}
                </div>
                {open[rowKey(it)] && (
                  <div className="dl-sub-row">
                    {it.cves.map(c => (
                      <div className="dl-row" key={`${rowKey(it)}-${c.id}`}>
                        <div style={{ paddingLeft: 14 }}><span className={"badge badge-sev-" + c.severity}>{c.severity}</span></div>
                        <div className="dl-main"><div className="dl-sub" style={{ whiteSpace: "normal", color: "var(--text-secondary)" }}>{c.summary || "No description"}</div></div>
                        <div className="dl-flags">{c.kev && <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>}<TriageChip t={c.triage} /></div>
                        <div className="dl-num">{c.cvss != null ? Number(c.cvss).toFixed(1) : "—"}</div>
                        <div>{c.cve_id ? <a href={cveUrl(c.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{c.cve_id}</a> : "—"}</div>
                        {canEdit ? <RowMenu label={`Triage ${c.cve_id || "finding"}`} items={menuFor([c.id], c.cve_id || "This finding", c.triage?.status)} /> : <div />}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div key={rowKey(it)} className="dl-item">
                <div className={"dl-row" + (it.triage?.suppressed ? " paused" : "")}>
                  <div><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></div>
                  <div className="dl-main">
                    <div className="dl-title wrap" title={it.template_id}>{(it.name || "").startsWith(VM_PREFIX) ? it.name.slice(VM_PREFIX.length) : it.name}</div>
                    <div className="dl-sub mono">{it.matched_at || (it.host + (it.port ? ":" + it.port : ""))}</div>
                  </div>
                  {flagsFor(it)}
                  <div className="dl-num">{it.cvss_score != null ? Number(it.cvss_score).toFixed(1) : "—"}</div>
                  <div>{it.cve_id ? <a href={cveUrl(it.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{it.cve_id}</a> : "—"}</div>
                  {canEdit ? <RowMenu label={`Triage ${it.name}`} items={menuFor([it.id], it.name, it.triage?.status)} /> : <div />}
                </div>
              </div>
            ))}
            {sorted.length === 0 && <div className="empty">{triageMode === "triaged" ? "Nothing has been triaged yet. Use the menu on a finding to mark it." : "No vulnerabilities match. Run a scan or change the filters."}</div>}
          </div>
        )}
      </div>
    </div>
  );
}
