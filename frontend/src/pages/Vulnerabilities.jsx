import React, { useState, useEffect, useRef } from "react";
import { AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import ScrollHint from "../components/ScrollHint";
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
  const tableContainerRef = useRef(null);

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

  const chip = (active) => ({
    padding: "4px 12px", borderRadius: 14, fontSize: 12, cursor: "pointer",
    border: "1px solid var(--border)", background: active ? "var(--surface-3)" : "transparent",
    color: active ? "var(--text-primary)" : "var(--text-secondary)",
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1>Vulnerabilities</h1>
        <AlertTriangle size={24} color="#f87171" />
      </div>

      <div className="vuln-summary">
        {["critical", "high", "medium", "low"].map(sev => (
          <div
            key={sev}
            className={"vuln-stat sev-" + sev + (severity === sev ? " active" : "")}
            onClick={() => setSeverity(severity === sev ? "all" : sev)}
          >
            <span className="vuln-count">{summary[sev] || 0}</span>
            <span className="vuln-label">{sev.toUpperCase()}</span>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16, alignItems: "center" }}>
        <span style={{ fontSize: 12, color: "var(--text-tertiary)" }}>Source</span>
        <button style={chip(source === "all")} onClick={() => setSource("all")}>All</button>
        <button style={chip(source === "verified")} onClick={() => setSource("verified")}>Scanner-verified</button>
        <button style={chip(source === "version")} onClick={() => setSource("version")}>
          Version match ({unverifiedCount})
        </button>
        <span style={{ fontSize: 12, color: "var(--text-tertiary)", marginLeft: 12 }}>Showing</span>
        <button style={chip(scope === "latest")} onClick={() => changeScope("latest")}>Latest scan</button>
        <button style={chip(scope === "all")} onClick={() => changeScope("all")}>All history</button>
      </div>
      {!loading && stats.findings > stats.lines && (
        <div style={{ fontSize: 12, color: "var(--text-tertiary)", marginTop: 8 }}>
          {stats.findings} findings shown as {stats.lines} lines: version-matched CVEs are grouped per component and host.
          Click a component to see its CVEs.
        </div>
      )}
      {source !== "verified" && unverifiedCount > 0 && (
        <div style={{ fontSize: 12, color: "var(--text-tertiary)", marginTop: 8 }}>
          Version-match findings are inferred from service version strings and are unverified: distributions often
          backport fixes without changing the version. Treat them as leads to confirm.
        </div>
      )}

      <ScrollHint containerRef={tableContainerRef} />

      <div className="table-container" ref={tableContainerRef} style={{ marginTop: 16 }}>
        {loading ? <div className="loading">Loading...</div> : (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Flags</th>
              <th>Finding</th>
              <th>Location</th>
              <th>CVSS</th>
              <th>CVE</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(it => it.kind === "component" ? (
              <React.Fragment key={rowKey(it)}>
                <tr style={{ cursor: "pointer" }} onClick={() => setOpen(o => ({ ...o, [rowKey(it)]: !o[rowKey(it)] }))}>
                  <td><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></td>
                  <td>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {it.kev_count > 0 && (
                        <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV {it.kev_count}</span>
                      )}
                      <span className="badge badge-sev-info" title="Inferred from a service version; not confirmed by a scanner check">Unverified</span>
                    </div>
                  </td>
                  <td className="wrap" style={{ color: "var(--text-primary)", fontWeight: 500, minWidth: 260 }}>
                    {open[rowKey(it)] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}{" "}
                    {it.component}
                    <span style={{ color: "var(--text-secondary)", fontWeight: 400 }}>
                      {" "}— {it.capped ? `${it.shown} of ${it.total}` : it.shown} CVE{it.shown === 1 && !it.capped ? "" : "s"}
                      {it.capped ? " (highest-risk shown)" : ""}
                    </span>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: 12, whiteSpace: "nowrap" }}>{it.host}</td>
                  <td style={{ fontVariantNumeric: "tabular-nums" }}>{it.max_cvss ? Number(it.max_cvss).toFixed(1) : "—"}</td>
                  <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                    {Object.entries(it.by_severity).map(([k, n]) => `${n} ${k}`).join(" · ")}
                  </td>
                </tr>
                {open[rowKey(it)] && it.cves.map(c => (
                  <tr key={`${rowKey(it)}-${c.id}`} style={{ background: "var(--surface-2, transparent)" }}>
                    <td style={{ paddingLeft: 24 }}><span className={"badge badge-sev-" + c.severity}>{c.severity}</span></td>
                    <td>{c.kev && <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>}</td>
                    <td className="wrap" colSpan={2} style={{ fontSize: 12, color: "var(--text-secondary)" }}>{c.summary || "—"}</td>
                    <td style={{ fontVariantNumeric: "tabular-nums" }}>{c.cvss != null ? Number(c.cvss).toFixed(1) : "—"}</td>
                    <td>
                      {c.cve_id ? (
                        <a href={cveUrl(c.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{c.cve_id}</a>
                      ) : "—"}
                    </td>
                  </tr>
                ))}
              </React.Fragment>
            ) : (
              <tr key={rowKey(it)}>
                <td><span className={"badge badge-sev-" + it.severity}>{it.severity}</span></td>
                <td>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {it.is_exploitable_confirmed && (
                      <span className="badge badge-sev-critical" title={(it.exploitability_reasons || []).join(" · ")}>Exploitable</span>
                    )}
                    {isKev(it) && (
                      <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>
                    )}
                    {!it.verified && (
                      <span className="badge badge-sev-info" title="Inferred from a service version; not confirmed by a scanner check">Unverified</span>
                    )}
                  </div>
                </td>
                <td className="wrap" title={it.template_id} style={{ color: "var(--text-primary)", fontWeight: 500, minWidth: 260 }}>
                  {(it.name || "").startsWith(VM_PREFIX) ? it.name.slice(VM_PREFIX.length) : it.name}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 12, whiteSpace: "nowrap" }}>
                  {it.matched_at || (it.host + (it.port ? ":" + it.port : ""))}
                </td>
                <td style={{ fontVariantNumeric: "tabular-nums" }}>
                  {it.cvss_score != null ? Number(it.cvss_score).toFixed(1) : "—"}
                </td>
                <td>
                  {it.cve_id ? (
                    <a href={cveUrl(it.cve_id)} target="_blank" rel="noreferrer" className="cve-link">{it.cve_id}</a>
                  ) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
        {!loading && sorted.length === 0 && (
          <div className="empty">No vulnerabilities match. Run a scan or change the filters.</div>
        )}
      </div>
    </div>
  );
}
