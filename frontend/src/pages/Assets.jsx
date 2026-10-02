import { useState, useEffect, useRef } from "react";
import React from "react";
import { getAssets, getAssetPaths } from "../api";
import ScrollHint from "../components/ScrollHint";
import { Database, Search, ChevronRight, ChevronDown, FolderSearch } from "lucide-react";

// whatweb emits both "Jetty" and "Jetty:8.1.7"; keep the versioned form, drop bare duplicates and noise.
const TECH_NOISE = new Set(["cookies", "httponly", "httpserver", "index-of", "x-frame-options", "x-xss-protection"]);
function cleanTech(list) {
  const items = (list || []).filter(t => t && !TECH_NOISE.has(t.toLowerCase()));
  const versioned = new Set(items.filter(t => t.includes(":")).map(t => t.split(":")[0].toLowerCase()));
  const out = items.filter(t => t.includes(":") || !versioned.has(t.toLowerCase()));
  return [...new Set(out.map(t => t.replace(/^Apache HTTP Server:/, "Apache:")))]
    .filter((t, i, a) => !(t === "Apache" && a.some(x => x.startsWith("Apache:"))));
}

function PathsPanel({ data }) {
  if (!data) return <div className="loading">Loading discovered paths...</div>;
  if (data === "error") return <div className="empty">Could not load discovered paths.</div>;
  if (data.paths.length === 0) {
    return (
      <div className="empty" style={{ padding: 16 }}>
        <FolderSearch size={14} style={{ verticalAlign: -2, marginRight: 6 }} />
        No paths discovered. Directory discovery may be off for this profile or target (Quick scans skip it).
      </div>
    );
  }
  return (
    <div style={{ padding: "8px 4px" }}>
      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 6 }}>
        {data.paths.length} path(s) from scan #{data.scan_id}; sensitive-looking ones first
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 60px 80px 90px", gap: "6px 12px", fontSize: 12, alignItems: "center" }}>
        {data.paths.map(p => (
          <React.Fragment key={`${p.path}-${p.status_code}`}>
            <span className="mono">{p.path}{p.redirect_location ? <span style={{ color: "var(--text-secondary)" }}> → {p.redirect_location}</span> : null}</span>
            <span style={{ color: p.status_code >= 400 ? "var(--orange)" : "var(--green)" }}>{p.status_code ?? "—"}</span>
            <span style={{ color: "var(--text-secondary)" }}>{p.content_length != null ? `${p.content_length} B` : "—"}</span>
            <span>{p.sensitive ? <span className="badge badge-sev-high">sensitive</span> : null}</span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showDisappeared, setShowDisappeared] = useState(false);
  const tableContainerRef = useRef(null);
  const [openId, setOpenId] = useState(null);
  const [pathsById, setPathsById] = useState({});   // { assetId: {scan_id, paths} | "error" }

  const togglePaths = (id) => {
    if (openId === id) { setOpenId(null); return; }
    setOpenId(id);
    if (!pathsById[id]) {
      getAssetPaths(id)
        .then(r => setPathsById(prev => ({ ...prev, [id]: r.data })))
        .catch(() => setPathsById(prev => ({ ...prev, [id]: "error" })));
    }
  };

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
              <th style={{ width: 28 }}></th>
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
              <React.Fragment key={asset.id}>
              <tr>
                <td>
                  <button className="icon-btn" onClick={() => togglePaths(asset.id)}
                          title="Discovered paths (directory discovery)" aria-expanded={openId === asset.id}>
                    {openId === asset.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                </td>
                <td className="mono">{asset.subdomain}</td>
                <td className="mono">{asset.ip || "—"}</td>
                <td>{asset.http_status || "—"}</td>
                <td className="wrap">{asset.http_title || "—"}</td>
                <td className="wrap">{cleanTech(asset.technologies).join(", ") || "—"}</td>
                <td>
                  {asset.open_ports?.length > 0
                    ? asset.open_ports.map(p => (
                        <span key={p.port} title={[p.service, p.product, p.version].filter(Boolean).join(" ") || "unknown service"}
                              style={{ marginRight: 6 }}>{p.port}</span>
                      ))
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
              {openId === asset.id && (
                <tr>
                  <td colSpan={10} style={{ background: "var(--surface-2)" }}>
                    <PathsPanel data={pathsById[asset.id]} />
                  </td>
                </tr>
              )}
              </React.Fragment>
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
