import { useState, useEffect } from "react";
import { getTargets, createTarget, deleteTarget, triggerScan } from "../api";
import { Plus, Trash2, Play, Shield } from "lucide-react";

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState({
    domain: "",
    authorized: false,
    authorized_by: "",
    scope_note: "",
    rate_limit: 10,
  });

  const fetchTargets = () => {
    getTargets()
      .then(r => setTargets(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchTargets(); }, []);

  const handleSubmit = async () => {
    if (!form.authorized) {
      setMessage("You must confirm authorization before adding a target.");
      return;
    }
    if (!form.domain || !form.authorized_by) {
      setMessage("Domain and authorized by are required.");
      return;
    }
    try {
      await createTarget(form);
      setMessage("Target added successfully.");
      setShowForm(false);
      setForm({ domain: "", authorized: false, authorized_by: "", scope_note: "", rate_limit: 10 });
      fetchTargets();
    } catch (e) {
      setMessage(e.response?.data?.detail || "Failed to add target.");
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteTarget(id);
      fetchTargets();
    } catch (e) {
      setMessage("Failed to delete target.");
    }
  };

  const handleScan = async (id) => {
    try {
      await triggerScan(id);
      setMessage("Scan queued successfully.");
    } catch (e) {
      setMessage(e.response?.data?.detail || "Failed to trigger scan.");
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Targets</h1>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={16} /> Add Target
        </button>
      </div>

      {message && <div className="message">{message}</div>}

      {showForm && (
        <div className="form-card">
          <h2>Add New Target</h2>
          <input
            placeholder="Domain (e.g. example.com)"
            value={form.domain}
            onChange={e => setForm({...form, domain: e.target.value})}
          />
          <input
            placeholder="Authorized by (your name)"
            value={form.authorized_by}
            onChange={e => setForm({...form, authorized_by: e.target.value})}
          />
          <input
            placeholder="Scope note (optional)"
            value={form.scope_note}
            onChange={e => setForm({...form, scope_note: e.target.value})}
          />
          <input
            type="number"
            placeholder="Rate limit (requests/sec)"
            value={form.rate_limit}
            onChange={e => setForm({...form, rate_limit: parseInt(e.target.value)})}
          />
          <label className="auth-checkbox">
            <input
              type="checkbox"
              checked={form.authorized}
              onChange={e => setForm({...form, authorized: e.target.checked})}
            />
            I confirm I have explicit permission to scan this domain
          </label>
          <div className="form-actions">
            <button className="btn btn-primary" onClick={handleSubmit}>Add Target</button>
            <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Authorized By</th>
              <th>Rate Limit</th>
              <th>Scope Note</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {targets.map(target => (
              <tr key={target.id}>
                <td><Shield size={14} /> {target.domain}</td>
                <td>{target.authorized_by}</td>
                <td>{target.rate_limit} req/s</td>
                <td>{target.scope_note || "—"}</td>
                <td className="actions">
                  <button className="btn btn-success btn-sm" onClick={() => handleScan(target.id)}>
                    <Play size={14} /> Scan
                  </button>
                  <button className="btn btn-danger btn-sm" onClick={() => handleDelete(target.id)}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}