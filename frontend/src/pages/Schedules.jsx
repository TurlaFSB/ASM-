import { useState, useEffect } from "react";
import { Clock, Plus, Trash2, Power } from "lucide-react";
import { getSchedules, createSchedule, toggleSchedule, deleteSchedule, getTargets } from "../api";

function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map(d => d.msg || JSON.stringify(d)).join(", ");
  return fallback;
}

const PRESETS = [
  { value: "hourly", label: "Hourly" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
];

export default function Schedules() {
  const [schedules, setSchedules] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [message, setMessage] = useState("");
  const [mode, setMode] = useState("preset"); // "preset" | "cron"
  const [form, setForm] = useState({
    target_id: "",
    preset: "daily",
    cron_expression: "",
  });

  const fetchAll = () => {
    Promise.all([getSchedules(), getTargets()])
      .then(([s, t]) => {
        setSchedules(s.data);
        setTargets(t.data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  const targetDomain = (id) => targets.find(t => t.id === id)?.domain || `Target #${id}`;

  const handleSubmit = async () => {
    if (!form.target_id) {
      setMessage("Select a target.");
      return;
    }
    const payload = {
      target_id: parseInt(form.target_id, 10),
      enabled: true,
    };
    if (mode === "preset") {
      payload.preset = form.preset;
    } else {
      if (!form.cron_expression.trim()) {
        setMessage("Enter a cron expression.");
        return;
      }
      payload.cron_expression = form.cron_expression.trim();
    }
    try {
      await createSchedule(payload);
      setMessage("Schedule created.");
      setShowForm(false);
      setForm({ target_id: "", preset: "daily", cron_expression: "" });
      fetchAll();
    } catch (e) {
      setMessage(extractErrorMessage(e, "Failed to create schedule."));
    }
  };

  const handleToggle = async (id) => {
    try {
      await toggleSchedule(id);
      fetchAll();
    } catch {
      setMessage("Failed to toggle schedule.");
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteSchedule(id);
      fetchAll();
    } catch {
      setMessage("Failed to delete schedule.");
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Scheduled Scans</h1>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={16} /> New Schedule
        </button>
      </div>

      {message && <div className="message">{message}</div>}

      {showForm && (
        <div className="form-card">
          <h2>Create Schedule</h2>

          <div className="form-field">
            <select
              value={form.target_id}
              onChange={e => setForm({ ...form, target_id: e.target.value })}
              style={{
                background: "var(--black)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "11px 14px",
                color: "var(--text-primary)",
                fontSize: "13.5px",
                width: "100%",
              }}
            >
              <option value="">Select target...</option>
              {targets.map(t => (
                <option key={t.id} value={t.id}>{t.domain}</option>
              ))}
            </select>
          </div>

          <div className="form-actions" style={{ marginTop: 0 }}>
            <button
              className={mode === "preset" ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
              onClick={() => setMode("preset")}
            >
              Preset
            </button>
            <button
              className={mode === "cron" ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"}
              onClick={() => setMode("cron")}
            >
              Custom Cron
            </button>
          </div>

          {mode === "preset" ? (
            <div className="form-field">
              <select
                value={form.preset}
                onChange={e => setForm({ ...form, preset: e.target.value })}
                style={{
                  background: "var(--black)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "11px 14px",
                  color: "var(--text-primary)",
                  fontSize: "13.5px",
                  width: "100%",
                }}
              >
                {PRESETS.map(p => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </div>
          ) : (
            <div className="form-field">
              <input
                placeholder="Cron expression (e.g. 0 */6 * * *)"
                value={form.cron_expression}
                onChange={e => setForm({ ...form, cron_expression: e.target.value })}
              />
              <span className="char-count">Standard 5-field cron syntax</span>
            </div>
          )}

          <div className="form-actions">
            <button className="btn btn-primary" onClick={handleSubmit}>Create Schedule</button>
            <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Schedule</th>
              <th>Status</th>
              <th>Last Run</th>
              <th>Next Run</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {schedules.map(s => (
              <tr key={s.id}>
                <td className="mono">{targetDomain(s.target_id)}</td>
                <td className="mono">{s.preset ? s.preset : s.cron_expression}</td>
                <td>
                  <span className={`schedule-status ${s.enabled ? "enabled" : "disabled"}`}>
                    <Power size={12} /> {s.enabled ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td style={{ fontSize: 12 }}>
                  {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "Never"}
                </td>
                <td style={{ fontSize: 12 }}>
                  {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"}
                </td>
                <td className="actions">
                  <button className="btn btn-sm btn-secondary" onClick={() => handleToggle(s.id)}>
                    <Power size={14} />
                  </button>
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(s.id)}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {schedules.length === 0 && (
          <div className="empty">No scheduled scans yet. Create one to automate recurring assessments.</div>
        )}
      </div>
    </div>
  );
}
