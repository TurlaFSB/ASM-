import { useState, useEffect, useRef } from "react";
import { getAssets } from "../api";
import ScrollHint from "../components/ScrollHint";
import { Database, Search } from "lucide-react";

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showDisappeared, setShowDisappeared] = useState(false);
  const tableContainerRef = useRef(null);

  useEffect(() => {
    getAssets()
      .then(r => setAssets(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const filtered = assets
    .filter(a => showDisappeared || a.status !== "disappeared")
    .filter(a =>
      a.subdomain.toLowerCase().includes(search.toLowerCase()) ||
      (a.ip && a.ip.includes(search)) ||
      (a.http_title && a.http_title.toLowerCase().includes(search.toLowerCase()))
    );

  const disappearedCount = assets.filter(a => a.status === "disappeared").length;

  const formatDate = (d) => {
    if (!d) return "—";
    return new Date(d).toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
    });
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Asset Inventory</h1>
        <Database size={24} />
      </div>

      <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "16px" }}>
        <div className="search-bar" style={{ marginBottom: 0 }}>
          <Search size={18} />
          <input
            placeholder="Search by subdomain, IP, or title..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <button
          className={showDisappeared ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
          onClick={() => setShowDisappeared(!showDisappeared)}
        >
          {showDisappeared ? "Hide" : "Show"} Disappeared ({disappearedCount})
        </button>
      </div>

      <ScrollHint containerRef={tableContainerRef} />

      <div className="table-container" ref={tableContainerRef}>
        <table>
          <thead>
            <tr>
              <th>Subdomain</th>
              <th>IP</th>
              <th>HTTP Status</th>
              <th>Title</th>
              <th>Technologies</th>
              <th>Open Ports</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(asset => (
              <tr key={asset.id}>
                <td className="mono">{asset.subdomain}</td>
                <td className="mono">{asset.ip || "—"}</td>
                <td>{asset.http_status || "—"}</td>
                <td className="wrap">{asset.http_title || "—"}</td>
                <td className="wrap">{asset.technologies?.join(", ") || "—"}</td>
                <td>
                  {asset.open_ports?.length > 0
                    ? asset.open_ports.map(p => p.port).join(", ")
                    : "—"}
                </td>
                <td>
                  {asset.risk_level ? (
                    <span className={`badge badge-risk-${asset.risk_level.toLowerCase()}`}>
                      {asset.risk_level}{asset.risk_score != null ? ` (${asset.risk_score})` : ""}
                    </span>
                  ) : (
                    <span className="badge badge-risk-informational">Unscored</span>
                  )}
                </td>
                <td>
                  <span className={`badge badge-${asset.status}`}>
                    {asset.status}
                  </span>
                </td>
                <td style={{ fontSize: 12 }}>{formatDate(asset.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="empty">No assets found.</div>
        )}
      </div>
    </div>
  );
}
