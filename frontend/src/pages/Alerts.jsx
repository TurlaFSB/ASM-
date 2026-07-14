import { useState, useEffect } from "react";
import { Bell, CheckCheck } from "lucide-react";
import { getAlerts, markAlertRead, markAllAlertsRead } from "../api";

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = () => {
    getAlerts()
      .then(r => setAlerts(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchAlerts(); }, []);

  const handleMarkAllRead = async () => {
    await markAllAlertsRead();
    fetchAlerts();
  };

  const handleMarkRead = async (id) => {
    await markAlertRead(id);
    fetchAlerts();
  };

  const alertColor = (type) => {
    if (type === "new_asset") return "green";
    if (type === "changed_asset") return "orange";
    if (type === "disappeared_asset") return "red";
    return "blue";
  };

  const alertLabel = (type) => {
    if (type === "new_asset") return "New Asset";
    if (type === "changed_asset") return "Changed";
    if (type === "disappeared_asset") return "Disappeared";
    return type;
  };

  const unreadCount = alerts.filter(a => a.is_read === "unread").length;

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <h1>Alerts</h1>
          {unreadCount > 0 && (
            <span className="badge badge-pending">{unreadCount} unread</span>
          )}
        </div>
        <button className="btn btn-secondary" onClick={handleMarkAllRead}>
          <CheckCheck size={16} /> Mark all read
        </button>
      </div>

      {alerts.length === 0 && (
        <div className="empty">No alerts yet. Run a scan to start detecting changes.</div>
      )}

      <div className="alerts-list">
        {alerts.map(alert => (
          <div
            key={alert.id}
            className={`alert-card ${alert.is_read === "unread" ? "unread" : ""}`}
            onClick={() => handleMarkRead(alert.id)}
          >
            <div className="alert-left">
              <span className={`alert-dot dot-${alertColor(alert.alert_type)}`} />
              <div>
                <div className="alert-header">
                  <span className={`badge badge-${alertColor(alert.alert_type) === "green" ? "new" : alertColor(alert.alert_type) === "orange" ? "changed" : "failed"}`}>
                    {alertLabel(alert.alert_type)}
                  </span>
                  <span className="alert-subdomain">{alert.asset_subdomain}</span>
                  {alert.asset_ip && (
                    <span className="alert-ip">{alert.asset_ip}</span>
                  )}
                </div>
                {alert.detail && (
                  <div className="alert-detail">
                    {alert.alert_type === "changed_asset" && (
                      <span>
                        Ports: {alert.detail.old_ports?.join(", ") || "—"} → {alert.detail.new_ports?.join(", ") || "—"}
                        {" | "}
                        Technologies: {alert.detail.old_technologies?.join(", ") || "—"} → {alert.detail.new_technologies?.join(", ") || "—"}
                      </span>
                    )}
                    {alert.alert_type === "new_asset" && (
                      <span>
                        Technologies: {alert.detail.technologies?.join(", ") || "—"}
                        {" | "}
                        HTTP: {alert.detail.http_status || "—"}
                      </span>
                    )}
                    {alert.alert_type === "disappeared_asset" && (
                      <span>{alert.detail.reason}</span>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="alert-time">
              {new Date(alert.created_at).toLocaleString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
