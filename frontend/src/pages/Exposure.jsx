import { useState, useEffect, useCallback } from "react";
import { Play, ExternalLink, Globe } from "lucide-react";
import Picker from "../components/Picker";
import { timeAgo } from "../lib/time";
import {
  getTargets, getExposureSources, setExposureSources, runExposureNow,
  getExposureFindings, setExposureFindingStatus, getExposureRuns,
} from "../api";
import ToggleSwitch from "../components/ToggleSwitch";
import useRole from "../components/useRole";
import { useToast } from "../components/toastContext";

const STATUS = [["open", "Open"], ["dismissed", "Dismissed"], ["resolved", "Resolved"]];
const IMPORTANCE = [["important", "Medium and above"], ["all", "Everything"]];
const SOURCE_LABEL = { github_code: "GitHub public code", xposedornot: "Breach records", lookalike_domains: "Lookalike domain", ransomlook: "Ransomware leak site", hudsonrock: "Infostealer logs" };

function errorText(e, fallback) {
  const d = e?.response?.data?.detail;
  return typeof d === "string" ? d : fallback;
}

// Evidence links come from third-party sites: https only, show the host, never pass the referrer.
function SafeLink({ url }) {
  let host = null;
  try { const u = new URL(url); if (u.protocol === "https:") host = u.hostname; } catch { /* not a URL */ }
  if (!host) return null;
  return (
    <a className="finding-link" href={url} target="_blank" rel="noopener noreferrer">
      <ExternalLink size={12} /> {host}
    </a>
  );
}

function RunChip({ source, run }) {
  if (source.applicable === false) return <span className="stage-chip">Needs a public domain name</span>;
  if (!source.configured) return <span className="stage-chip">Needs {source.needs || "setup"}</span>;
  if (!run) return <span className="muted-note">{source.enabled ? "On. Waiting for the first check" : "Off"}</span>;
  if (run.status === "ok") return <span className="muted-note">Checked {timeAgo(run.finished_at || run.started_at)}, {run.found} found</span>;
  if (run.status === "skipped") return <span className="muted-note">Not applicable: {run.error || "skipped"}</span>;
  if (run.status === "running") return <span className="badge badge-running">running</span>;
  if (run.status === "rate_limited") return <span className="muted-note">Rate limited {timeAgo(run.started_at)}; retries within the hour</span>;
  return <span className="muted-note" style={{ color: "var(--red)" }}>Failed {timeAgo(run.started_at)}{run.error ? `: ${run.error}` : ""}</span>;
}

function FindingCard({ f, canEdit, onStatus }) {
  const rules = f.evidence?.rules || [];
  const data = f.evidence?.exposed_data || [];
  const lk = f.kind === "lookalike" ? f.evidence : null;
  const rw = f.kind === "ransomware_listing" ? f.evidence : null;
  const st = f.kind === "infostealer" ? f.evidence : null;
  return (
    <div className={"finding-card" + (f.status !== "open" ? " dim" : "")}>
      <div className="finding-head">
        <span className={"badge badge-sev-" + f.severity}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <span className="stage-chip">{SOURCE_LABEL[f.source] || f.source}</span>
      </div>
      <p className="finding-summary">{f.summary}</p>
      {rules.length > 0 && (
        <div className="finding-evidence" aria-label="Masked evidence">
          {rules.map((r, i) => <code key={i}>{r.rule.replace("assignment:", "")}: {r.sample}</code>)}
        </div>
      )}
      {data.length > 0 && (
        <div className="finding-evidence" aria-label="Exposed data">{data.map((d, i) => <code key={i}>{d}</code>)}</div>
      )}
      {lk && (
        <div className="finding-evidence" aria-label="DNS evidence">
          <code>{lk.technique}</code>
          {lk.a?.slice(0, 3).map((x, i) => <code key={"a" + i}>A {x}</code>)}
          {lk.mx?.slice(0, 2).map((x, i) => <code key={"m" + i}>MX {x}</code>)}
          {lk.same_infrastructure && <code>same infrastructure as your domain</code>}
        </div>
      )}
      {rw && (
        <div className="finding-evidence" aria-label="Listing details">
          <code>group: {rw.group}</code>
          {rw.discovered && <code>listed {rw.discovered}</code>}
          <code>listed as: {rw.listed_title}</code>
        </div>
      )}
      {st && (
        <div className="finding-evidence" aria-label="Infostealer details">
          <code>{st.employees.toLocaleString()} employee</code>
          <code>{st.users.toLocaleString()} customer</code>
          {st.last_employee_compromised && <code>last employee capture {st.last_employee_compromised}</code>}
          {st.last_user_compromised && <code>last customer capture {st.last_user_compromised}</code>}
          {st.stealer_families?.map((x, i) => <code key={"s" + i}>{x.name} {x.count.toLocaleString()}</code>)}
        </div>
      )}
      <div className="finding-foot">
        <span className="muted-note">
          First seen {timeAgo(f.first_seen)} · seen {f.seen_count} time{f.seen_count === 1 ? "" : "s"}
        </span>
        <SafeLink url={f.url} />
        {canEdit && f.status === "open" && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => onStatus(f, "dismissed")}>Dismiss</button>
        )}
        {canEdit && f.status === "dismissed" && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => onStatus(f, "open")}>Reopen</button>
        )}
      </div>
    </div>
  );
}

export default function Exposure() {
  const role = useRole();
  const canEdit = role === "admin";
  const { toast } = useToast();
  const [targets, setTargets] = useState([]);
  const [targetId, setTargetId] = useState(null);
  const [sources, setSources] = useState([]);
  const [runs, setRuns] = useState([]);
  const [findings, setFindings] = useState([]);
  const [status, setStatus] = useState("open");
  const [importance, setImportance] = useState("important");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(() => new Set());   // sources being saved
  const [waiting, setWaiting] = useState(null);             // time a check was queued, until it shows up

  useEffect(() => {
    getTargets()
      .then(r => { setTargets(r.data); if (r.data.length) setTargetId(r.data[0].id); })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  const load = useCallback(() => {
    if (!targetId) return;
    getExposureSources(targetId).then(r => setSources(r.data)).catch(() => setError(true));
    getExposureRuns({ target_id: targetId, limit: 30 }).then(r => setRuns(r.data)).catch(() => {});
    const params = { target_id: targetId, status, limit: 200 };
    if (importance === "important") params.severity = "critical,high,medium";
    getExposureFindings(params).then(r => { setFindings(r.data); setError(false); }).catch(() => setError(true));
  }, [targetId, status, importance]);

  useEffect(() => { load(); }, [load]);

  // while a run is in flight, refresh so results appear without a manual reload
  const running = runs.some(r => r.status === "running");
  // a queued check counts as in flight until a run newer than the click appears (or 45 s pass)
  const arrived = waiting != null && runs.some(r => new Date(r.started_at).getTime() >= waiting - 5000);
  const active = running || (waiting != null && !arrived);
  useEffect(() => {
    if (!active) return undefined;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [active, load]);

  const lastRun = (name) => runs.find(r => r.source === name);
  const enabledCount = sources.filter(s => s.enabled).length;

  // The switch moves at once; the server call happens in the background. Only the switch being saved is
  // locked, the others stay still. A failed save puts that one switch back and says why.
  const toggle = async (name, on) => {
    if (saving.has(name)) return;
    const next = sources.map(s => (s.name === name ? { ...s, enabled: on } : s));
    setSources(next);
    setSaving(prev => new Set(prev).add(name));
    try {
      await setExposureSources(targetId, next.filter(s => s.enabled).map(s => s.name));
    } catch (e) {
      setSources(cur => cur.map(s => (s.name === name ? { ...s, enabled: !on } : s)));
      toast(errorText(e, "Could not save that change"), "bad");
    } finally {
      setSaving(prev => { const n = new Set(prev); n.delete(name); return n; });
    }
  };

  const runNow = async () => {
    setBusy(true);
    try {
      await runExposureNow(targetId);
      setWaiting(Date.now());
      load();
      setTimeout(() => setWaiting(null), 45000);
    } catch (e) { toast(errorText(e, "Could not start the check"), "bad"); }
    finally { setBusy(false); }
  };

  const changeStatus = async (f, next) => {
    try {
      await setExposureFindingStatus(f.id, next);
      setFindings(list => list.filter(x => x.id !== f.id));
    } catch (e) { toast(errorText(e, "Could not update the finding"), "bad"); }
  };

  if (loading) return <div className="page"><div className="loading">Loading...</div></div>;

  if (!targets.length) {
    return (
      <div className="page">
        <div className="page-header"><h1>Exposure</h1></div>
        <div className="empty">Add a target first. Exposure checks look for leaks and breaches that mention it.</div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>Exposure</h1>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <Picker value={targetId} onChange={setTargetId} icon={Globe} ariaLabel="Target" minWidth={300}
            options={targets.map(t => ({ value: t.id, label: t.domain, hint: t.authorized_by ? `Authorized by ${t.authorized_by}` : undefined }))} />
          {canEdit && (
            <button type="button" className="btn btn-primary btn-lg" onClick={runNow} disabled={busy || enabledCount === 0 || active}
              title={enabledCount === 0 ? "Turn on a source first" : "Check the enabled sources now"}>
              <Play size={14} /> {active ? "Checking..." : "Check now"}
            </button>
          )}
        </div>
      </div>

      <p className="muted-note exposure-intro">
        Looks outside your own infrastructure for leaked credentials in public code and for public breach records.
        Only masked traces are stored, never a full secret. A mention is not proof of a leak, so review before you rotate anything.
      </p>

      {sources.length > 0 && sources.every(s => s.applicable === false) && (
        <p className="muted-note exposure-intro" role="note">
          This target is an IP address or an internal host. Exposure sources search the public internet for a domain name
          (public code, breach records, look-alike domains, ransomware listings), so none of them apply here. Pick a target
          with a public domain name.
        </p>
      )}

      <div className="exposure-sources">
        {sources.map(s => (
          <div key={s.name} className="exposure-source">
            <div>
              <div className="exposure-source-name">{s.label}</div>
              <div className="muted-note">{s.description}</div>
              <div style={{ marginTop: 6 }}><RunChip source={s} run={lastRun(s.name)} /></div>
            </div>
            {canEdit
              ? <ToggleSwitch checked={!!s.enabled} disabled={saving.has(s.name) || ((!s.configured || s.applicable === false) && !s.enabled)} onChange={on => toggle(s.name, on)} label="" ariaLabel={`Check ${s.label}`} />
              : <span className="muted-note">{s.enabled ? "On" : "Off"}</span>}
          </div>
        ))}
      </div>

      <div className="exposure-filters">
        <div className="seg" role="group" aria-label="Status">
          {STATUS.map(([v, t]) => (
            <button key={v} type="button" className={"seg-item" + (status === v ? " active" : "")} aria-pressed={status === v} onClick={() => setStatus(v)}>{t}</button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Importance">
          {IMPORTANCE.map(([v, t]) => (
            <button key={v} type="button" className={"seg-item" + (importance === v ? " active" : "")} aria-pressed={importance === v} onClick={() => setImportance(v)}>{t}</button>
          ))}
        </div>
      </div>

      <p className="muted-note exposure-credit">
        Ransomware listings: data from <a href="https://www.ransomlook.io" target="_blank" rel="noopener noreferrer">RansomLook.io</a>,
        licensed CC BY 4.0. A listing is the attacker's claim, not proof of stolen data.
      </p>

      {error && <div className="empty">Could not load exposure data. Check that the API is running.</div>}
      {!error && findings.length === 0 && (
        <div className="empty">
          {enabledCount === 0
            ? "No sources are on for this target. Turn one on above, then choose Check now."
            : status === "open"
              ? "Nothing found yet. Sources are checked on a schedule; choose Check now to run them straight away."
              : `No ${status} findings.`}
        </div>
      )}
      <div className="exposure-list">
        {findings.map(f => <FindingCard key={f.id} f={f} canEdit={canEdit} onStatus={changeStatus} />)}
      </div>
    </div>
  );
}
