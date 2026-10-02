import { useState, useEffect, useRef } from "react";
import { AlertTriangle } from "lucide-react";
import ScrollHint from "../components/ScrollHint";
import { getVulnerabilities, getVulnSummary } from "../api";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VM_PREFIX = "[version match] ";

const sevRank = (s) => (s in SEVERITY_ORDER ? SEVERITY_ORDER[s] : 5); // 0 is a valid rank (critical)

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");   // all | verified | version
  const [scope, setScope] = useState("latest");  // latest scan per target | all history
  const tableContainerRef = useRef(null);

  useEffect(() => {
    const params = { scope };
    Promise.all([getVulnerabilities(params), getVulnSummary(params)])
      .then(([v, s]) => {
        setVulns(v.data);
        setSummary(s.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scope]);

  const changeScope = (next) => { setLoading(true); setScope(next); };

  const filtered = vulns.filter(v =>
    (severity === "all" || v.severity === severity) &&
    (source === "all" || (source === "verified" ? v.verified : !v.verified))
  );

  // Server already orders by severity, confirmed-exploitable, CVSS; keep a stable client sort too.
  const sorted = [...filtered].sort((a, b) =>
    sevRank(a.severity) - sevRank(b.severity) || (b.cvss_score || 0) - (a.cvss_score || 0)
  );

  const unverifiedCount = vulns.filter(v => !v.verified).length;
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
            {sorted.map(vuln => (
              <tr key={vuln.id}>
                <td>
                  <span className={"badge badge-sev-" + vuln.severity}>{vuln.severity}</span>
                </td>
                <td>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {vuln.is_exploitable_confirmed && (
                      <span className="badge badge-sev-critical" title={(vuln.exploitability_reasons || []).join(" · ")}>
                        Exploitable
                      </span>
                    )}
                    {isKev(vuln) && (
                      <span className="badge badge-sev-critical" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span>
                    )}
                    {!vuln.verified && (
                      <span className="badge badge-sev-info" title="Inferred from a service version; not confirmed by a scanner check">
                        Unverified
                      </span>
                    )}
                  </div>
                </td>
                <td className="wrap" title={vuln.template_id} style={{ color: "var(--text-primary)", fontWeight: 500, minWidth: 260 }}>
                  {(vuln.name || "").startsWith(VM_PREFIX) ? vuln.name.slice(VM_PREFIX.length) : vuln.name}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 12, whiteSpace: "nowrap" }}>
                  {vuln.matched_at || (vuln.host + (vuln.port ? ":" + vuln.port : ""))}
                </td>
                <td style={{ fontVariantNumeric: "tabular-nums" }}>
                  {vuln.cvss_score != null ? Number(vuln.cvss_score).toFixed(1) : "—"}
                </td>
                <td>
                  {vuln.cve_id ? (
                    <a href={cveUrl(vuln.cve_id)} target="_blank" rel="noreferrer" className="cve-link">
                      {vuln.cve_id}
                    </a>
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
