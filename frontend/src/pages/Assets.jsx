import { useState, useEffect } from "react";
import { getTargets } from "../api";
import { Database, Search } from "lucide-react";
import axios from "axios";

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    axios.get("http://192.168.16.130:8000/assets/")
      .then(r => setAssets(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const filtered = assets.filter(a =>
    a.subdomain.toLowerCase().includes(search.toLowerCase()) ||
    (a.ip && a.ip.includes(search)) ||
    (a.http_title && a.http_title.toLowerCase().includes(search.toLowerCase()))
  );

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Asset Inventory</h1>
        <Database size={24} />
      </div>

      <div className="search-bar">
        <Search size={18} />
        <input
          placeholder="Search by subdomain, IP, or title..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Subdomain</th>
              <th>IP</th>
              <th>HTTP Status</th>
              <th>Title</th>
              <th>Technologies</th>
              <th>Open Ports</th>
              <th>Status</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(asset => (
              <tr key={asset.id}>
                <td>{asset.subdomain}</td>
                <td>{asset.ip || "—"}</td>
                <td>{asset.http_status || "—"}</td>
                <td>{asset.http_title || "—"}</td>
                <td>{asset.technologies?.join(", ") || "—"}</td>
                <td>
                  {asset.open_ports?.length > 0
                    ? asset.open_ports.map(p => p.port).join(", ")
                    : "—"}
                </td>
                <td>
                  <span className={`badge badge-${asset.status}`}>
                    {asset.status}
                  </span>
                </td>
                <td>{asset.last_seen ? new Date(asset.last_seen).toLocaleString() : "—"}</td>
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