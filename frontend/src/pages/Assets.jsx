import React, { useState, useEffect, useMemo } from "react";
import { getAssets, getAssetPaths } from "../api";
import { timeAgo } from "../lib/time";
import { Search, ChevronRight, FolderSearch } from "lucide-react";

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
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 56px 60px 80px 90px", gap: "6px 12px", fontSize: 12, alignItems: "center" }}>
        {data.paths.map(p => (
          <React.Fragment key={`${p.port}-${p.path}-${p.status_code}`}>
            <span className="mono">{p.path}{p.redirect_location ? <span style={{ color: "var(--text-secondary)" }}> → {p.redirect_location}</span> : null}</span>
            <span className="mono" style={{ color: "var(--text-secondary)" }}>{p.port ? `:${p.port}` : ""}</span>
            <span style={{ color: p.status_code >= 400 ? "var(--orange)" : "var(--green)" }}>{p.status_code ?? "—"}</span>
            <span style={{ color: "var(--text-secondary)" }}>{p.content_length != null ? `${p.content_length} B` : "—"}</span>
            <span>{p.sensitive ? <span className="badge badge-sev-high">sensitive</span> : null}</span>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

const FILTERS = [["all", "All"], ["new", "New"], ["changed", "Changed"], ["disappeared", "Disappeared"]];

function Chips({ items, max, mono, empty = "None" }) {
  if (!items.length) return <span className="as-none">{empty}</span>;
  const shown = items.slice(0, max);
  const rest = items.slice(max);
  return (
    <span className="as-chips">
      {shown.map(t => <span key={t} className={"as-chip" + (mono ? " mono" : "")}>{t}</span>)}
      {rest.length > 0 && <span className="as-chip as-more" title={rest.join(", ")}>+{rest.length}</span>}
    </span>
  );
}

function statusTone(code) {
  if (!code) return "";
  if (code >= 500) return "bad";
  if (code >= 400) return "warn";
  if (code >= 300) return "info";
  return "ok";
}

function AssetRow({ asset, open, onToggle, paths }) {
  const techs = cleanTech(asset.technologies);
  const ports = (asset.open_ports || []).map(p => ({ n: String(p.port), tip: [p.service, p.product, p.version].filter(Boolean).join(" ") }));
  const flagged = ["new", "changed", "disappeared"].includes(asset.status);
  const onKey = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onToggle(); } };
  return (
    <div className={"as-item" + (open ? " open" : "") + (asset.status === "disappeared" ? " gone" : "")}>
      <div className="as-row" role="button" tabIndex={0} aria-expanded={open} onClick={onToggle} onKeyDown={onKey}>
        <div className="as-cell as-name">
          <ChevronRight size={14} className="as-caret" />
          <div className="as-name-text">
            <div className="as-host">
              <span className="as-host-name">{asset.subdomain}</span>
              {flagged && <span className={`badge badge-${asset.status}`}>{asset.status}</span>}
            </div>
            <div className="as-sub mono">{asset.ip || "No IP"}</div>
          </div>
        </div>
        <div className="as-cell as-web">
          {asset.http_status
            ? <><span className={"as-code " + statusTone(asset.http_status)}>{asset.http_status}</span><span className="as-title" title={asset.http_title || ""}>{asset.http_title || "No title"}</span></>
            : <span className="as-none">No web response</span>}
        </div>
        <div className="as-cell as-techs"><Chips items={techs} max={3} empty="None detected" /></div>
        <div className="as-cell as-ports">
          {ports.length
            ? <span className="as-chips">
                {ports.slice(0, 4).map(p => <span key={p.n} className="as-chip mono" title={p.tip || "unknown service"}>{p.n}</span>)}
                {ports.length > 4 && <span className="as-chip as-more" title={ports.slice(4).map(p => p.n).join(", ")}>+{ports.length - 4}</span>}
              </span>
            : <span className="as-none">None open</span>}
        </div>
        <div className="as-cell as-risk">
          {asset.risk_level
            ? <span className={`badge badge-risk-${asset.risk_level.toLowerCase()}`} title={asset.risk_score != null ? `Score ${asset.risk_score}` : undefined}>{asset.risk_level}</span>
            : <span className="as-none">Unscored</span>}
        </div>
        <div className="as-cell as-seen" title={asset.last_seen ? new Date(asset.last_seen).toLocaleString() : ""}>{asset.last_seen ? timeAgo(asset.last_seen) : "Never"}</div>
      </div>
      {open && <div className="as-detail"><PathsPanel data={paths} /></div>}
    </div>
  );
}

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
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
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  }, []);

  const counts = useMemo(() => {
    const c = { all: 0, new: 0, changed: 0, disappeared: 0 };
    for (const a of assets) {
      if (a.status !== "disappeared") c.all += 1;
      if (c[a.status] !== undefined) c[a.status] += 1;
    }
    return c;
  }, [assets]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return assets
      .filter(a => (filter === "all" ? a.status !== "disappeared" : a.status === filter))
      .filter(a => !q || a.subdomain.toLowerCase().includes(q) || (a.ip && a.ip.includes(q)) || (a.http_title && a.http_title.toLowerCase().includes(q)));
  }, [assets, filter, search]);

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Assets</h1>
        <span className="as-total">{counts.all} active</span>
      </div>

      <div className="as-toolbar">
        <label className="as-search">
          <Search size={15} />
          <input placeholder="Search name, IP or title" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search assets" />
        </label>
        <div className="seg" role="group" aria-label="Show">
          {FILTERS.map(([v, t]) => (
            <button key={v} type="button" className={"seg-item" + (filter === v ? " active" : "")} aria-pressed={filter === v} onClick={() => setFilter(v)}>
              {t}{v !== "all" && counts[v] > 0 ? <span className="seg-count">{counts[v]}</span> : null}
            </button>
          ))}
        </div>
      </div>

      {failed && <div className="empty">Could not load assets. Check that the API is running.</div>}
      {!failed && (
        <div className="as-table">
          <div className="as-head" aria-hidden="true">
            <div>Asset</div><div>Web</div><div>Technologies</div><div>Open ports</div><div>Risk</div><div>Last seen</div>
          </div>
          {filtered.map(asset => (
            <AssetRow key={asset.id} asset={asset} open={openId === asset.id} onToggle={() => togglePaths(asset.id)} paths={pathsById[asset.id]} />
          ))}
          {filtered.length === 0 && (
            <div className="empty">
              {assets.length === 0 ? "No assets yet. Run a scan from Targets and discovered hosts will appear here." : "Nothing matches. Clear the search or choose another filter."}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
