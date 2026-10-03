import { useState, useEffect } from "react";
import { ChevronRight } from "lucide-react";
import Skeleton from "../components/Skeleton";
import Segmented from "../components/Segmented";
import { getVulnRollup, getVulnSummary } from "../api";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VM_PREFIX = "[version match] ";

const sevRank = (s) => (s in SEVERITY_ORDER ? SEVERITY_ORDER[s] : 5); // 0 is a valid rank (critical)

export default function Vulnerabilities() {
  const [items, setItems] = useState([]);       // roll-up: verified findings + one line per CVE component
  const [stats, setStats] = useState({ findings: 0, lines: 0 });
  const [open, setOpen] = useState({});          // expanded component lines
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");   // all | verified | version
  const [scope, setScope] = useState("latest");  // latest scan per target | all history

  useEffect(() => {
    const params = { scope };
    Promise.all([getVulnRollup(params), getVulnSummary(params)])
      .then(([v, s]) => {
        setItems(v.data.items);
        setStats({ findings: v.data.findings, lines: v.data.lines });
        setSummary(s.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scope]);

  const changeScope = (next) => { setLoading(true); setScope(next); };

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

  const flagsFor = (it) => (
    <div className="dl-flags">
      {it.is_exploitable_confirmed && <span className="badge badge-sev-critical" title={(it.exploitability_reasons || []).join(" · ")}>Exploitable</span>}
      {(it.kev_count > 0 || isKev(it)) && <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV{it.kev_count > 1 ? ` ${it.kev_count}` : ""}</span>}
      {!isVerified(it) && <span className="badge badge-sev-info" title="Inferred from a service version; not confirmed by a scanner check">Unverified</span>}
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
      </div>
      {!loading && stats.findings > stats.lines && (
        <p className="dl-note">{stats.findings} findings shown as {stats.lines} lines: version-matched CVEs are grouped per component and host. Select a component to see its CVEs.</p>
      )}
      {source !== "verified" && unverifiedCount > 0 && (
        <p className="dl-note">Version-match findings are inferred from service version strings and are unverified: distributions often backport fixes without changing the version. Treat them as leads to confirm.</p>
      )}

      <div style={{ marginTop: 16 }}>
        {loading ? <Skeleton rows={6} /> : (
          <div className="dl" style={{ "--cols": "84px minmax(0,3fr) minmax(120px,1.2fr) 52px minmax(120px,1fr)" }}>
            <div className="dl-head" aria-hidden="true">
              <div>Severity</div><div>Finding</div><div>Flags</div><div className="dl-num">CVSS</div><div>CVE</div>
            </div>
            {sorted.map(it => it.kind === "component" ? (
              <div key={rowKey(it)} className={"dl-item" + (open[rowKey(it)] ? " open" : "")}>
                <div className="dl-row clickable" role="button" tabIndex={0} aria-expanded={!!open[rowKey(it)]}
                  onClick={() => setOpen(o => ({ ...o, [rowKey(it)]: !o[rowKey(it)] }))}
                  onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen(o => ({ ...o, [rowKey(it)]: !o[rowKey(it)] })); } }}>
                  <div><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></div>
                  <div className="dl-main">
                    <div className="dl-title"><ChevronRight size={14} className="dl-caret" />{it.component}
                      <span style={{ color: "var(--text-secondary)", fontWeight: 400 }}>
                        {" "}· {it.capped ? `${it.shown} of ${it.total}` : it.shown} CVE{it.shown === 1 && !it.capped ? "" : "s"}{it.capped ? ", highest risk shown" : ""}
                      </span>
                    </div>
                    <div className="dl-sub mono">{it.host}</div>
                  </div>
                  {flagsFor(it)}
                  <div className="dl-num">{it.max_cvss ? Number(it.max_cvss).toFixed(1) : "—"}</div>
                  <div className="dl-sub" style={{ marginTop: 0 }}>{Object.entries(it.by_severity).map(([k, n]) => `${n} ${k}`).join(" · ")}</div>
                </div>
                {open[rowKey(it)] && (
                  <div className="dl-sub-row">
                    {it.cves.map(c => (
                      <div className="dl-row" key={`${rowKey(it)}-${c.id}`}>
                        <div style={{ paddingLeft: 14 }}><span className={"badge badge-sev-" + c.severity}>{c.severity}</span></div>
                        <div className="dl-main"><div className="dl-sub" style={{ whiteSpace: "normal", color: "var(--text-secondary)" }}>{c.summary || "No description"}</div></div>
                        <div className="dl-flags">{c.kev && <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>}</div>
                        <div className="dl-num">{c.cvss != null ? Number(c.cvss).toFixed(1) : "—"}</div>
                        <div>{c.cve_id ? <a href={cveUrl(c.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{c.cve_id}</a> : "—"}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div key={rowKey(it)} className="dl-item">
                <div className="dl-row">
                  <div><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></div>
                  <div className="dl-main">
                    <div className="dl-title wrap" title={it.template_id}>{(it.name || "").startsWith(VM_PREFIX) ? it.name.slice(VM_PREFIX.length) : it.name}</div>
                    <div className="dl-sub mono">{it.matched_at || (it.host + (it.port ? ":" + it.port : ""))}</div>
                  </div>
                  {flagsFor(it)}
                  <div className="dl-num">{it.cvss_score != null ? Number(it.cvss_score).toFixed(1) : "—"}</div>
                  <div>{it.cve_id ? <a href={cveUrl(it.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{it.cve_id}</a> : "—"}</div>
                </div>
              </div>
            ))}
            {sorted.length === 0 && <div className="empty">No vulnerabilities match. Run a scan or change the filters.</div>}
          </div>
        )}
      </div>
    </div>
  );
}
