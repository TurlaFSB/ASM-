import React, { useState, useEffect } from "react";
import { getTargets, createTarget, deleteTarget, triggerScan, getTargetHistory } from "../api";
import { Plus, Trash2, Play, Shield, History } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map(d => d.msg || JSON.stringify(d)).join(", ");
  }
  return fallback;
}

// Mirrors backend/api/targets.py DOMAIN_REGEX exactly
const DOMAIN_REGEX = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$/;

const formatDate = (iso) =>
  new Date(iso).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
  });

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;
  return (
    <div
      style={{
        background: "rgba(20, 20, 24, 0.9)",
        backdropFilter: "blur(12px)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: "10px",
        padding: "10px 14px",
        fontSize: "13px",
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
      }}
    >
      <div style={{ color: "rgba(255,255,255,0.5)", marginBottom: "6px", fontSize: "12px" }}>
        {formatDate(label)}
      </div>
      {payload.map((p) => (
        <div key={p.dataKey} style={{ display: "flex", justifyContent: "space-between", gap: "16px", color: p.color }}>
          <span>{p.name}</span>
          <span style={{ fontVariantNumeric: "tabular-nums" }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

const validators = {
  domain: (v) => {
    const val = v.trim().toLowerCase();
    if (!val) return "Domain is required";
    if (val.length > 253) return "Domain exceeds 253 characters";
    if (!DOMAIN_REGEX.test(val)) return "Invalid format (e.g. example.com)";
    return null;
  },
  authorized_by: (v) => {
    const val = v.trim();
    if (!val) return "Authorized by is required";
    if (val.length < 2) return "Minimum 2 characters";
    if (val.length > 100) return "Exceeds 100 characters";
    return null;
  },
  scope_note: (v) => {
    if (v && v.length > 1000) return "Exceeds 1000 characters";
    return null;
  },
  rate_limit: (v) => {
    if (v === "" || v === null || Number.isNaN(v)) return "Rate limit is required";
    if (!Number.isInteger(v)) return "Must be a whole number";
    if (v <= 0) return "Must be greater than 0";
    if (v > 100) return "Cannot exceed 100 req/s";
    return null;
  },
};

const emptyForm = {
  domain: "",
  authorized: false,
  authorized_by: "",
  scope_note: "",
  rate_limit: 10,
};

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState(emptyForm);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [expandedId, setExpandedId] = useState(null);
  const [historyData, setHistoryData] = useState({});

  const fetchTargets = () => {
    getTargets()
      .then(r => setTargets(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchTargets(); }, []);

  const validateField = (field, value) => validators[field] ? validators[field](value) : null;

  const handleChange = (field, value) => {
    setForm(prev => ({ ...prev, [field]: value }));
    if (touched[field]) {
      setErrors(prev => ({ ...prev, [field]: validateField(field, value) }));
    }
  };

  const handleBlur = (field) => {
    setTouched(prev => ({ ...prev, [field]: true }));
    setErrors(prev => ({ ...prev, [field]: validateField(field, form[field]) }));
  };

  const runFullValidation = () => {
    const newErrors = {
      domain: validateField("domain", form.domain),
      authorized_by: validateField("authorized_by", form.authorized_by),
      scope_note: validateField("scope_note", form.scope_note),
      rate_limit: validateField("rate_limit", form.rate_limit),
    };
    setErrors(newErrors);
    setTouched({ domain: true, authorized_by: true, scope_note: true, rate_limit: true });
    return Object.values(newErrors).every(e => !e);
  };

  const isFormValid =
    !validators.domain(form.domain) &&
    !validators.authorized_by(form.authorized_by) &&
    !validators.scope_note(form.scope_note) &&
    !validators.rate_limit(form.rate_limit) &&
    form.authorized;

  const handleSubmit = async () => {
    const fieldsOk = runFullValidation();
    if (!form.authorized) {
      setMessage("You must confirm authorization before adding a target.");
      return;
    }
    if (!fieldsOk) {
      setMessage("Please fix the highlighted fields before submitting.");
      return;
    }
    setSubmitting(true);
    try {
      await createTarget(form);
      setMessage("Target added successfully.");
      setShowForm(false);
      setForm(emptyForm);
      setErrors({});
      setTouched({});
      fetchTargets();
    } catch (e) {
      setMessage(extractErrorMessage(e, "Failed to add target."));
    } finally {
      setSubmitting(false);
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
      await triggerScan({ target_id: id });
      setMessage("Scan queued successfully.");
    } catch (e) {
      setMessage(extractErrorMessage(e, "Failed to trigger scan."));
    }
  };

  const toggleHistory = async (id) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    if (!historyData[id]) {
      try {
        const res = await getTargetHistory(id);
        setHistoryData(prev => ({ ...prev, [id]: res.data.history }));
      } catch (e) {
        console.error(e);
      }
    }
  };

  const fieldClass = (field) =>
    touched[field] && errors[field] ? "input-error" : touched[field] ? "input-valid" : "";

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

          <div className="form-field">
            <input
              className={fieldClass("domain")}
              placeholder="Domain (e.g. example.com)"
              value={form.domain}
              onChange={e => handleChange("domain", e.target.value)}
              onBlur={() => handleBlur("domain")}
              maxLength={253}
            />
            {touched.domain && errors.domain && <span className="field-error">{errors.domain}</span>}
          </div>

          <div className="form-field">
            <input
              className={fieldClass("authorized_by")}
              placeholder="Authorized by (your name)"
              value={form.authorized_by}
              onChange={e => handleChange("authorized_by", e.target.value)}
              onBlur={() => handleBlur("authorized_by")}
              maxLength={100}
            />
            {touched.authorized_by && errors.authorized_by && (
              <span className="field-error">{errors.authorized_by}</span>
            )}
            <span className="char-count">{form.authorized_by.length}/100</span>
          </div>

          <div className="form-field">
            <input
              className={fieldClass("scope_note")}
              placeholder="Scope note (optional)"
              value={form.scope_note}
              onChange={e => handleChange("scope_note", e.target.value)}
              onBlur={() => handleBlur("scope_note")}
              maxLength={1000}
            />
            {touched.scope_note && errors.scope_note && (
              <span className="field-error">{errors.scope_note}</span>
            )}
            <span className="char-count">{form.scope_note.length}/1000</span>
          </div>

          <div className="form-field">
            <label className="field-label">Rate Limit (requests/sec)</label>
            <input
              type="number"
              className={fieldClass("rate_limit")}
              placeholder="e.g. 10"
              value={form.rate_limit}
              min={1}
              max={100}
              onChange={e => handleChange("rate_limit", e.target.value === "" ? "" : parseInt(e.target.value, 10))}
              onBlur={() => handleBlur("rate_limit")}
            />
            {touched.rate_limit && errors.rate_limit && (
              <span className="field-error">{errors.rate_limit}</span>
            )}
          </div>

          <label className="auth-checkbox">
            <input
              type="checkbox"
              checked={form.authorized}
              onChange={e => setForm({ ...form, authorized: e.target.checked })}
            />
            I confirm I have explicit permission to scan this domain
          </label>

          <div className="form-actions">
            <button
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={submitting || !isFormValid}
            >
              {submitting ? "Adding..." : "Add Target"}
            </button>
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
              <React.Fragment key={target.id}>
                <tr>
                  <td><Shield size={14} /> {target.domain}</td>
                  <td>{target.authorized_by}</td>
                  <td>{target.rate_limit} req/s</td>
                  <td>{target.scope_note || "—"}</td>
                  <td className="actions">
                    <button className="btn btn-success btn-sm" onClick={() => handleScan(target.id)}>
                      <Play size={14} /> Scan
                    </button>
                    <button className="btn btn-secondary btn-sm" onClick={() => toggleHistory(target.id)}>
                      <History size={14} /> History
                    </button>
                    <button className="btn btn-danger btn-sm" onClick={() => handleDelete(target.id)}>
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
                {expandedId === target.id && (
                  <tr>
                    <td colSpan={5}>
                      {!historyData[target.id] ? (
                        <div className="loading">Loading history...</div>
                      ) : historyData[target.id].length === 0 ? (
                        <div className="loading">No completed scans yet.</div>
                      ) : (
                        <div style={{ padding: "1rem 0" }}>
                          {historyData[target.id].length >= 2 && (() => {
                            const scans = historyData[target.id];
                            const latest = scans[scans.length - 1];
                            const prev = scans[scans.length - 2];
                            const parts = [];
                            if (latest.new_assets > 0) parts.push(`+${latest.new_assets} new asset${latest.new_assets > 1 ? "s" : ""}`);
                            if (latest.disappeared_assets > 0) parts.push(`${latest.disappeared_assets} asset${latest.disappeared_assets > 1 ? "s" : ""} disappeared`);
                            if (latest.changed_assets > 0) parts.push(`${latest.changed_assets} changed`);
                            const critDelta = latest.vuln_counts.critical - prev.vuln_counts.critical;
                            const highDelta = latest.vuln_counts.high - prev.vuln_counts.high;
                            if (critDelta > 0) parts.push(`${critDelta} new critical finding${critDelta > 1 ? "s" : ""}`);
                            if (critDelta < 0) parts.push(`${-critDelta} critical finding${-critDelta > 1 ? "s" : ""} resolved`);
                            if (highDelta > 0) parts.push(`${highDelta} new high finding${highDelta > 1 ? "s" : ""}`);
                            if (highDelta < 0) parts.push(`${-highDelta} high finding${-highDelta > 1 ? "s" : ""} resolved`);
                            return (
                              <div className="message" style={{ marginBottom: "1rem" }}>
                                {parts.length > 0 ? `Since last scan: ${parts.join(", ")}.` : "No change in attack surface since last scan."}
                              </div>
                            );
                          })()}
                          <div style={{ width: "100%", height: 300 }}>
                            <ResponsiveContainer width="100%" height="100%">
                              <LineChart data={historyData[target.id]}>
                                <CartesianGrid strokeDasharray="0" stroke="rgba(255,255,255,0.06)" vertical={false} />
                                <XAxis
                                  dataKey="scan_date"
                                  tickFormatter={formatDate}
                                  stroke="rgba(255,255,255,0.35)"
                                  fontSize={11}
                                  tickLine={false}
                                  axisLine={{ stroke: "rgba(255,255,255,0.08)" }}
                                />
                                <YAxis
                                  stroke="rgba(255,255,255,0.35)"
                                  fontSize={11}
                                  tickLine={false}
                                  axisLine={false}
                                  width={28}
                                />
                                <Tooltip content={<CustomTooltip />} cursor={{ stroke: "rgba(255,255,255,0.15)" }} />
                                <Legend
                                  iconType="circle"
                                  iconSize={8}
                                  wrapperStyle={{ fontSize: "12px", color: "rgba(255,255,255,0.6)", paddingTop: "12px" }}
                                />
                                <Line type="monotone" dataKey="total_assets" name="Total Assets" stroke="#8b5cf6" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                                <Line type="monotone" dataKey="new_assets" name="New Assets" stroke="#34d399" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                                <Line type="monotone" dataKey="changed_assets" name="Changed" stroke="#fbbf24" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                                <Line type="monotone" dataKey="vuln_counts.critical" name="Critical Vulns" stroke="#f87171" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                                <Line type="monotone" dataKey="vuln_counts.high" name="High Vulns" stroke="#fb923c" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                              </LineChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}