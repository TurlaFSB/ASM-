import { useState, useEffect, useCallback } from "react";
import { getTargets, createTarget, deleteTarget, triggerScan, getTargetHistory, getTargetInfrastructure, updateDirbusterToggle, getScans, getScanProfiles, updateTargetProfile } from "../api";
import { Plus, Trash2, Play, Shield, History, Globe, Bell, Loader2, Tag } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import RowMenu from "../components/RowMenu";
import Sheet from "../components/Sheet";
import Skeleton from "../components/Skeleton";
import "../components/ToggleSwitch.css";
import ProfilePicker from "../components/ProfilePicker";
import NotificationSettings from "../components/NotificationSettings";
import TagEditor from "../components/TagEditor";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/toastContext";
import { fgAlpha } from "../lib/theme";

function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map(d => d.msg || JSON.stringify(d)).join(", ");
  }
  return fallback;
}

// UX pre-check only; backend/validators.py is authoritative (private ranges etc.)
const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR_REGEX = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
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
        background: "var(--pop)",
        backdropFilter: "blur(12px)",
        border: "1px solid var(--border)",
        borderRadius: "10px",
        padding: "10px 14px",
        fontSize: "13px",
        boxShadow: "0 8px 24px rgba(0,0,0,0.25)",
      }}
    >
      <div style={{ color: "var(--text-secondary)", marginBottom: "6px", fontSize: "12px" }}>
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
    if (!DOMAIN_REGEX.test(val) && !IPV4_REGEX.test(val) && !CIDR_REGEX.test(val)) return "Invalid format (e.g. example.com, 8.8.8.8 or 203.0.113.0/28)";
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


const SEV_CLASS = { critical: "badge-sev-critical", high: "badge-sev-high", medium: "badge-sev-medium" };

function Fact({ label, children }) {
  return (
    <div className="fact">
      <div className="fact-label">{label}</div>
      <div className="fact-value">{children || "—"}</div>
    </div>
  );
}

function InfoSection({ title, empty, isEmpty, children }) {
  return (
    <section className="info-section">
      <h3>{title}</h3>
      {isEmpty ? <p className="muted-note">{empty}</p> : children}
    </section>
  );
}

function InfrastructurePanel({ data }) {
  const whois = data.whois_data?.domain_whois;
  const asn = data.whois_data?.asn;
  return (
    <div className="info-panel">
      <InfoSection title="Registration" isEmpty={!data.whois_data} empty="No WHOIS data available.">
        <div className="facts">
          <Fact label="Registrar">{whois?.registrar}</Fact>
          <Fact label="Created">{whois?.creation_date && formatDate(whois.creation_date)}</Fact>
          <Fact label="Expires">{whois?.expiration_date && formatDate(whois.expiration_date)}</Fact>
          <Fact label="Network (ASN)">{asn?.asn_description}</Fact>
        </div>
      </InfoSection>
      <InfoSection title="Technologies" isEmpty={data.technologies.length === 0} empty="No technologies detected.">
        <div className="tag-list">
          {data.technologies.map(tech => <span key={tech} className="tag">{tech}</span>)}
        </div>
      </InfoSection>
      <InfoSection title="TLS findings" isEmpty={data.tls_findings.length === 0} empty="No TLS misconfigurations found.">
        <ul className="finding-list">
          {data.tls_findings.map(f => (
            <li key={f.id}>
              <div>
                <div className="finding-name">{f.name}</div>
                <div className="mono-dim">{f.host}</div>
              </div>
              <span className={"badge " + (SEV_CLASS[f.severity] || "badge-sev-info")}>{f.severity}</span>
            </li>
          ))}
        </ul>
      </InfoSection>
    </div>
  );
}

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [expandedId, setExpandedId] = useState(null);
    const [historyData, setHistoryData] = useState({});
  const [profileChoice, setProfileChoice] = useState({});
  const [profiles, setProfiles] = useState([]);
  const [dirbusterEnabled, setDirbusterEnabled] = useState({});
  const [infraExpandedId, setInfraExpandedId] = useState(null);
  const [infraData, setInfraData] = useState({});
  const [notifExpandedId, setNotifExpandedId] = useState(null);
  const [tagEditId, setTagEditId] = useState(null);       // target whose tags are being edited
  const [tagFilter, setTagFilter] = useState(null);       // only show targets with this tag
  const [pendingDelete, setDeleteTarget] = useState(null);   // target awaiting delete confirmation
  const { toast } = useToast();
  const [activeScans, setActiveScans] = useState({});   // target id -> scan that is pending or running
  const [starting, setStarting] = useState({});         // target id -> a scan request is in flight

  const refreshActive = useCallback(() => {
    getScans().then(r => {
      const m = {};
      for (const sc of r.data) if (sc.status === "pending" || sc.status === "running") m[sc.target_id] = sc;
      setActiveScans(m);
    }).catch(() => {});
  }, []);

  useEffect(() => { refreshActive(); }, [refreshActive]);
  const anyActive = Object.keys(activeScans).length > 0;
  useEffect(() => {
    if (!anyActive) return undefined;
    const t = setInterval(refreshActive, 5000);
    return () => clearInterval(t);
  }, [anyActive, refreshActive]);

  const fetchTargets = () => {
    getTargets()
      .then(r => setTargets(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchTargets();
    getScanProfiles().then(r => setProfiles(r.data.profiles || [])).catch(() => {});
  }, []);

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
      toast("You must confirm authorization before adding a target.", "bad");
      return;
    }
    if (!fieldsOk) {
      toast("Please fix the highlighted fields before submitting.", "bad");
      return;
    }
    setSubmitting(true);
    try {
      await createTarget(form);
      toast("Target added.");
      setShowForm(false);
      setForm(emptyForm);
      setErrors({});
      setTouched({});
      fetchTargets();
    } catch (e) {
      toast(extractErrorMessage(e, "Failed to add target."), "bad");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    const t = pendingDelete;
    setDeleteTarget(null);
    try {
      await deleteTarget(t.id);
      toast(`${t.domain} removed. Its scan history is kept.`);
      fetchTargets();
    } catch {
      toast("Could not remove the target.", "bad");
    }
  };

  const handleScan = async (id) => {
    if (starting[id] || activeScans[id]) return;
    setStarting(prev => ({ ...prev, [id]: true }));
    try {
      const t = targets.find(x => x.id === id);
      const profile = profileChoice[id] ?? t?.default_profile ?? "standard";
      await triggerScan({ target_id: id, profile, run_dirbuster: dirbusterEnabled[id] ?? t?.dirbuster_enabled ?? true });
      refreshActive();
    } catch (e) {
      toast(extractErrorMessage(e, "Failed to trigger scan."), "bad");
    } finally {
      setStarting(prev => ({ ...prev, [id]: false }));
    }
  };

  const setDirScan = async (target, val) => {
    setDirbusterEnabled(prev => ({ ...prev, [target.id]: val }));
    try {
      await updateDirbusterToggle(target.id, val);
    } catch (e) {
      setDirbusterEnabled(prev => ({ ...prev, [target.id]: !val }));
      toast(extractErrorMessage(e, "Could not save the directory scan setting."), "bad");
    }
  };

  const toggleHistory = async (id) => {
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
  const toggleInfra = async (id) => {
    setInfraExpandedId(id);
    if (!infraData[id]) {
      try {
        const res = await getTargetInfrastructure(id);
        setInfraData(prev => ({ ...prev, [id]: res.data }));
      } catch (e) {
        console.error(e);
      }
    }
  };

  const fieldClass = (field) =>
    touched[field] && errors[field] ? "input-error" : touched[field] ? "input-valid" : "";

  const allTags = [...new Set(targets.flatMap(t => t.tags || []))].sort();
  const visibleTargets = tagFilter ? targets.filter(t => (t.tags || []).includes(tagFilter)) : targets;

  if (loading) return <div className="page"><div className="page-header"><h1>Targets</h1></div><Skeleton rows={4} height={64} /></div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Targets</h1>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          <Plus size={16} /> Add Target
        </button>
      </div>

      <ConfirmDialog open={!!pendingDelete} tone="danger" title={`Remove ${pendingDelete?.domain ?? "target"}?`}
        confirmLabel="Remove target" onConfirm={handleDelete} onCancel={() => setDeleteTarget(null)}>
        Scheduled scans for it stop and it leaves the target list. Past scans, findings and reports are kept.
      </ConfirmDialog>

      <Sheet open={showForm} title="Add target" onClose={() => setShowForm(false)}
        footer={<>
          <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
          <button className="btn btn-primary" onClick={handleSubmit} disabled={submitting || !isFormValid}>{submitting ? "Adding..." : "Add target"}</button>
        </>}>
        <div className="form-field">
          <label htmlFor="t-domain">Domain, IP address or range</label>
          <input
            className={fieldClass("domain")}
            id="t-domain" placeholder="example.com"
            value={form.domain}
            onChange={e => handleChange("domain", e.target.value)}
            onBlur={() => handleBlur("domain")}
            maxLength={253}
          />
          {touched.domain && errors.domain && <span className="field-error">{errors.domain}</span>}
        </div>

        <div className="form-field">
          <label htmlFor="t-auth">Authorized by</label>
          <input
            className={fieldClass("authorized_by")}
            id="t-auth" placeholder="Your name"
            value={form.authorized_by}
            onChange={e => handleChange("authorized_by", e.target.value)}
            onBlur={() => handleBlur("authorized_by")}
            maxLength={100}
          />
          {touched.authorized_by && errors.authorized_by && (
            <span className="field-error">{errors.authorized_by}</span>
          )}
        </div>

        <div className="form-field">
          <label htmlFor="t-scope">Scope note</label>
          <input
            className={fieldClass("scope_note")}
            id="t-scope" placeholder="Optional"
            value={form.scope_note}
            onChange={e => handleChange("scope_note", e.target.value)}
            onBlur={() => handleBlur("scope_note")}
            maxLength={1000}
          />
          {touched.scope_note && errors.scope_note && (
            <span className="field-error">{errors.scope_note}</span>
          )}
        </div>

        <div className="form-field">
          <label htmlFor="t-rate">Rate limit (requests per second)</label>
          <input
            id="t-rate"
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
          I confirm I have explicit permission to scan this target
        </label>

      </Sheet>

      {allTags.length > 0 && (
        <div className="tag-filter" role="group" aria-label="Filter targets by tag">
          <button type="button" className={"tag-chip" + (tagFilter === null ? " active" : "")} aria-pressed={tagFilter === null} onClick={() => setTagFilter(null)}>All</button>
          {allTags.map(t => (
            <button key={t} type="button" className={"tag-chip" + (tagFilter === t ? " active" : "")} aria-pressed={tagFilter === t}
              onClick={() => setTagFilter(tagFilter === t ? null : t)}>{t}</button>
          ))}
        </div>
      )}
      {targets.length === 0 && <div className="empty">No targets yet. Choose Add Target to start monitoring a domain you are authorized to scan.</div>}
      <div className="target-list">
        {visibleTargets.map(target => {
          const dirOn = dirbusterEnabled[target.id] ?? target.dirbuster_enabled ?? true;
          const open = (id) => (expandedId === id ? "history" : infraExpandedId === id ? "infra" : notifExpandedId === id ? "notif" : null);
          const panel = open(target.id);
          const show = (name) => {
            const toggleOff = panel === name;
            setExpandedId(null); setInfraExpandedId(null); setNotifExpandedId(null);
            if (toggleOff) return;
            if (name === "history") toggleHistory(target.id, true);
            if (name === "infra") toggleInfra(target.id, true);
            if (name === "notif") setNotifExpandedId(target.id);
          };
          return (
            <div className="target-row" key={target.id}>
              <div className="target-main">
                <div className="target-glyph"><Shield size={20} /></div>
                <div className="target-id">
                  <div className="target-domain">{target.domain}</div>
                  <div className="target-meta">
                    Authorized by {target.authorized_by} · {target.rate_limit} req/s{target.scope_note ? ` · ${target.scope_note}` : ""}
                  </div>
                  {target.tags?.length > 0 && (
                    <div className="target-tags" aria-label="Tags">
                      {target.tags.map(t => <button key={t} type="button" className="tag-chip small" onClick={() => setTagFilter(t)} title={`Show only ${t}`}>{t}</button>)}
                    </div>
                  )}
                </div>
                <div className="target-controls">
                  <div className="seg target-seg" role="group" aria-label={`Details for ${target.domain}`}>
                    <button type="button" className={"seg-item" + (panel === "history" ? " active" : "")} aria-pressed={panel === "history"} onClick={() => show("history")}><History size={14} /> History</button>
                    <button type="button" className={"seg-item" + (panel === "infra" ? " active" : "")} aria-pressed={panel === "infra"} onClick={() => show("infra")}><Globe size={14} /> Infrastructure</button>
                    <button type="button" className={"seg-item" + (panel === "notif" ? " active" : "")} aria-pressed={panel === "notif"} onClick={() => show("notif")}><Bell size={14} /> Notifications</button>
                  </div>
                  <label className="target-dir" title="Also discover directories and files on web servers (slower, more thorough)">
                    <span>Dir scan</span>
                    <span className="ios-toggle">
                      <input type="checkbox" checked={dirOn} onChange={e => setDirScan(target, e.target.checked)} />
                      <span className="ios-toggle-track"><span className="ios-toggle-knob" /></span>
                    </span>
                  </label>
                  <ProfilePicker
                    profiles={profiles}
                    value={profileChoice[target.id] ?? target.default_profile ?? "standard"}
                    onChange={(val) => {
                      setProfileChoice(prev => ({ ...prev, [target.id]: val }));
                      updateTargetProfile(target.id, val).catch(() => toast("Could not save default profile.", "bad"));
                    }}
                  />
                  {(() => {
                    const act = activeScans[target.id];
                    const busy = !!starting[target.id] || !!act;
                    return (
                      <button type="button" className="btn btn-primary" onClick={() => handleScan(target.id)} disabled={busy}
                        title={act ? `Scan #${act.id} is ${act.status}` : "Start a scan now"} aria-busy={busy}>
                        {busy ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
                        {act ? (act.status === "pending" ? "Queued" : "Scanning") : starting[target.id] ? "Starting" : "Scan"}
                      </button>
                    );
                  })()}
                  <RowMenu label={`More actions for ${target.domain}`} items={[
                    { label: "Edit tags", icon: Tag, onClick: () => setTagEditId(target.id) },
                    { label: "Remove target", icon: Trash2, danger: true, onClick: () => setDeleteTarget(target) },
                  ]} />
                </div>
              </div>
              {tagEditId === target.id && (
                <div className="target-panel">
                  <TagEditor target={target} onCancel={() => setTagEditId(null)}
                    onSaved={(t) => { setTargets(prev => prev.map(x => x.id === t.id ? { ...x, tags: t.tags } : x)); setTagEditId(null); toast("Tags saved."); }} />
                </div>
              )}
              {panel === "notif" && <div className="target-panel"><NotificationSettings target={target} /></div>}
              {panel === "history" && (
                <div className="target-panel">
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
                                  <CartesianGrid strokeDasharray="0" stroke={fgAlpha(0.06)} vertical={false} />
                                  <XAxis
                                    dataKey="scan_date"
                                    tickFormatter={formatDate}
                                    stroke={fgAlpha(0.35)}
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={{ stroke: fgAlpha(0.08) }}
                                  />
                                  <YAxis
                                    stroke={fgAlpha(0.35)}
                                    fontSize={11}
                                    tickLine={false}
                                    axisLine={false}
                                    width={28}
                                  />
                                  <Tooltip content={<CustomTooltip />} cursor={{ stroke: fgAlpha(0.15) }} />
                                  <Legend
                                    iconType="circle"
                                    iconSize={8}
                                    wrapperStyle={{ fontSize: "12px", color: fgAlpha(0.6), paddingTop: "12px" }}
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
                </div>
              )}
              {panel === "infra" && (
                <div className="target-panel">
        {!infraData[target.id] ? (
                          <div className="loading">Loading infrastructure data...</div>
                        ) : (
                          <InfrastructurePanel data={infraData[target.id]} />
                        )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}