import "../components/ToggleSwitch.css";
import { useState, useEffect } from "react";
import { Plus, Trash2, Globe } from "lucide-react";
import { getSchedules, createSchedule, setScheduleEnabled, deleteSchedule, getTargets } from "../api";
import Sheet from "../components/Sheet";
import Picker from "../components/Picker";
import Segmented from "../components/Segmented";
import RowMenu from "../components/RowMenu";
import Skeleton from "../components/Skeleton";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/toastContext";
import { timeAgo } from "../lib/time";

function extractErrorMessage(err, fallback) {
  const detail = err.response?.data?.detail;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map(d => d.msg || JSON.stringify(d)).join(", ");
  return fallback;
}

const FREQUENCIES = [["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["cron", "Custom"]];
const PRESET_TEXT = { hourly: "Every hour", daily: "Every day", weekly: "Every week" };

function inFuture(iso) {
  if (!iso) return "Not scheduled";
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  if (s <= 60) return "Any moment";
  if (s < 3600) return `In ${Math.round(s / 60)} min`;
  if (s < 86400) return `In ${Math.round(s / 3600)} h`;
  return `In ${Math.round(s / 86400)} d`;
}

export default function Schedules() {
  const [schedules, setSchedules] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState(null);
  const [form, setForm] = useState({ target_id: null, frequency: "daily", cron_expression: "" });
  const { toast } = useToast();

  const fetchAll = () => {
    Promise.all([getSchedules(), getTargets()])
      .then(([s, t]) => { setSchedules(s.data); setTargets(t.data); setFailed(false); })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  const targetDomain = (id) => targets.find(t => t.id === id)?.domain || `Target #${id}`;

  const openForm = () => {
    setForm({ target_id: targets[0]?.id ?? null, frequency: "daily", cron_expression: "" });
    setShowForm(true);
  };

  const handleSubmit = async () => {
    if (!form.target_id) { toast("Choose a target first.", "bad"); return; }
    const payload = { target_id: form.target_id, enabled: true };
    if (form.frequency === "cron") {
      if (!form.cron_expression.trim()) { toast("Enter a cron expression.", "bad"); return; }
      payload.cron_expression = form.cron_expression.trim();
    } else {
      payload.preset = form.frequency;
    }
    setSaving(true);
    try {
      await createSchedule(payload);
      toast("Schedule created.");
      setShowForm(false);
      fetchAll();
    } catch (e) {
      toast(extractErrorMessage(e, "Could not create the schedule."), "bad");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (s) => {
    try { await setScheduleEnabled(s.id, !s.enabled); fetchAll(); }
    catch { toast("Could not change the schedule.", "bad"); }
  };

  const confirmDelete = async () => {
    const s = pendingDelete;
    setPendingDelete(null);
    try { await deleteSchedule(s.id); toast("Schedule deleted."); fetchAll(); }
    catch { toast("Could not delete the schedule.", "bad"); }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Schedules</h1>
        <button className="btn btn-primary" onClick={openForm} disabled={targets.length === 0}
          title={targets.length === 0 ? "Add a target first" : undefined}>
          <Plus size={16} /> New schedule
        </button>
      </div>

      <ConfirmDialog open={!!pendingDelete} tone="danger" title="Delete this schedule?" confirmLabel="Delete schedule"
        onConfirm={confirmDelete} onCancel={() => setPendingDelete(null)}>
        {pendingDelete ? `${targetDomain(pendingDelete.target_id)} will no longer be scanned automatically. Past scans are kept.` : ""}
      </ConfirmDialog>

      <Sheet open={showForm} title="New schedule" onClose={() => setShowForm(false)}
        footer={<>
          <button className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
          <button className="btn btn-primary" onClick={handleSubmit} disabled={saving}>{saving ? "Creating..." : "Create schedule"}</button>
        </>}>
        <div className="form-field">
          <label>Target</label>
          <Picker value={form.target_id} onChange={v => setForm({ ...form, target_id: v })} icon={Globe} ariaLabel="Target" minWidth={0}
            options={targets.map(t => ({ value: t.id, label: t.domain }))} />
        </div>
        <div className="form-field">
          <label>Repeat</label>
          <Segmented value={form.frequency} onChange={v => setForm({ ...form, frequency: v })} options={FREQUENCIES} label="Repeat" />
          {form.frequency === "cron" ? (
            <>
              <input style={{ marginTop: 10 }} aria-label="Cron expression" placeholder="0 */6 * * *" value={form.cron_expression}
                onChange={e => setForm({ ...form, cron_expression: e.target.value })} />
              <p className="sheet-hint">Standard 5-field cron: minute, hour, day of month, month, day of week. Times are in UTC.</p>
            </>
          ) : (
            <p className="sheet-hint">{PRESET_TEXT[form.frequency]}. Scans use the target's default profile.</p>
          )}
        </div>
      </Sheet>

      {loading ? <Skeleton rows={4} /> : failed ? (
        <div className="empty">Could not load schedules. Check that the API is running.</div>
      ) : (
        <div className="dl" style={{ "--cols": "minmax(160px,1.6fr) minmax(130px,1.2fr) minmax(110px,1fr) minmax(110px,1fr) 70px 36px" }}>
          <div className="dl-head" aria-hidden="true">
            <div>Target</div><div>Repeats</div><div>Last run</div><div>Next run</div><div>Enabled</div><div />
          </div>
          {schedules.map(s => (
            <div className="dl-item" key={s.id}>
              <div className={"dl-row" + (s.enabled ? "" : " paused")}>
                <div className="dl-main"><div className="dl-title">{targetDomain(s.target_id)}</div></div>
                <div className="dl-main">
                  <div className="dl-title" style={{ fontWeight: 400 }}>{s.preset ? PRESET_TEXT[s.preset] || s.preset : "Custom"}</div>
                  {!s.preset && <div className="dl-sub mono">{s.cron_expression}</div>}
                </div>
                <div className="dl-main" title={s.last_run_at ? new Date(s.last_run_at).toLocaleString() : ""}>{s.last_run_at ? timeAgo(s.last_run_at) : "Never"}</div>
                <div className="dl-main" title={s.next_run_at ? new Date(s.next_run_at).toLocaleString() : ""}>{s.enabled ? inFuture(s.next_run_at) : "Paused"}</div>
                <div>
                  <label className="ios-toggle" title={s.enabled ? "Pause this schedule" : "Resume this schedule"}>
                    <input type="checkbox" checked={!!s.enabled} onChange={() => handleToggle(s)} aria-label={`Enabled for ${targetDomain(s.target_id)}`} />
                    <span className="ios-toggle-track"><span className="ios-toggle-knob" /></span>
                  </label>
                </div>
                <RowMenu label="Schedule actions" items={[{ label: "Delete schedule", icon: Trash2, danger: true, onClick: () => setPendingDelete(s) }]} />
              </div>
            </div>
          ))}
          {schedules.length === 0 && <div className="empty">No schedules yet. Create one to scan a target automatically on a regular basis.</div>}
        </div>
      )}
    </div>
  );
}
