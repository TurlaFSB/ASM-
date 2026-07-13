import { useState, useEffect } from "react";
import { AlertTriangle } from "lucide-react";
import axios from "axios";

const API = "http://192.168.16.130:8000";

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    Promise.all([
      axios.get(API + "/vulnerabilities/"),
      axios.get(API + "/vulnerabilities/summary")
    ])
      .then(([v, s]) => {
        setVulns(v.data);
        setSummary(s.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const filtered = filter === "all"
    ? vulns
    : vulns.filter(v => v.severity === filter);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  const sorted = [...filtered].sort((a, b) =>
    (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
  );

  const cveUrl = (cveId) => "https://nvd.nist.gov/vuln/detail/" + cveId;

  if (loading) return <div className="loading">Loading...</div>;

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
            className={"vuln-stat sev-" + sev + (filter === sev ? " active" : "")}
            onClick={() => setFilter(filter === sev ? "all" : sev)}
          >
            <span className="vuln-count">{summary[sev] || 0}</span>
            <span className="vuln-label">{sev.toUpperCase()}</span>
          </div>
        ))}
      </div>

      <div className="table-container" style={{ marginTop: 20 }}>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Name</th>
              <th>Host</th>
              <th>Matched At</th>
              <th>CVE</th>
              <th>Template</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(vuln => (
              <tr key={vuln.id}>
                <td>
                  <span className={"badge badge-sev-" + vuln.severity}>
                    {vuln.severity}
                  </span>
                </td>
                <td style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                  {vuln.name}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 12 }}>
                  {vuln.host}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 12 }}>
                  {vuln.matched_at || ""}
                </td>
                <td>
                  {vuln.cve_id ? (
                    <a href={cveUrl(vuln.cve_id)} target="_blank" rel="noreferrer" className="cve-link">
                      {vuln.cve_id}
                    </a>
                  ) : ""}
                </td>
                <td style={{ fontSize: 12, color: "var(--text-tertiary)" }}>
                  {vuln.template_id}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {sorted.length === 0 && (
          <div className="empty">No vulnerabilities found. Run a scan first.</div>
        )}
      </div>
    </div>
  );
}