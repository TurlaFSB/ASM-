import { useEffect, useState } from "react";
import { Plus, ShieldCheck, Eye, UserX, UserCheck, KeyRound } from "lucide-react";
import { getUsers, getMe, createUser, updateUser, resetUserPassword, resetUserMfa } from "../api";
import Sheet from "../components/Sheet";
import Segmented from "../components/Segmented";
import RowMenu from "../components/RowMenu";
import Skeleton from "../components/Skeleton";
import ConfirmDialog from "../components/ConfirmDialog";
import { useToast } from "../components/toastContext";
import { timeAgo } from "../lib/time";

function errText(e, fallback) {
  const d = e.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg).join(", ");
  return fallback;
}

const ROLE_OPTIONS = [["viewer", "Viewer"], ["admin", "Admin"]];

export default function Users() {
  const { toast } = useToast();
  const [users, setUsers] = useState([]);
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [confirmMfa, setConfirmMfa] = useState(null);
  const [sheet, setSheet] = useState(null);                // null | "new" | user (reset password)
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });
  const [busy, setBusy] = useState(false);
  const [confirmOff, setConfirmOff] = useState(null);

  const load = () => {
    Promise.all([getUsers(), getMe()])
      .then(([u, m]) => { setUsers(u.data); setMe(m.data.username); setFailed(false); })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const openNew = () => { setForm({ username: "", password: "", role: "viewer" }); setSheet("new"); };
  const openReset = (u) => { setForm({ username: u.username, password: "", role: u.role }); setSheet(u); };

  const submit = async () => {
    setBusy(true);
    try {
      if (sheet === "new") { await createUser(form); toast(`${form.username} added.`); }
      else { await resetUserPassword(sheet.id, form.password); toast(`New password set for ${sheet.username}. They are signed out everywhere.`); }
      setSheet(null);
      load();
    } catch (e) { toast(errText(e, "Could not save."), "bad"); }
    finally { setBusy(false); }
  };

  const patch = async (u, data, okText) => {
    try { await updateUser(u.id, data); toast(okText); load(); }
    catch (e) { toast(errText(e, "Could not update the account."), "bad"); }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1>Users</h1>
        <button type="button" className="btn btn-primary" onClick={openNew}><Plus size={16} /> Add user</button>
      </div>

      <ConfirmDialog open={!!confirmMfa} tone="danger" title={`Reset two-step sign-in for ${confirmMfa?.username}?`} confirmLabel="Reset"
        onConfirm={async () => {
          const u = confirmMfa; setConfirmMfa(null);
          try { await resetUserMfa(u.id); toast(`Two-step sign-in turned off for ${u.username}. They are signed out everywhere.`); load(); }
          catch (e) { toast(errText(e, "Could not reset two-step sign-in."), "bad"); }
        }} onCancel={() => setConfirmMfa(null)}>
        Use this when they lost their phone and recovery codes. They sign in with their password only until they turn it on again.
      </ConfirmDialog>
      <ConfirmDialog open={!!confirmOff} tone="danger" title={`Deactivate ${confirmOff?.username}?`} confirmLabel="Deactivate"
        onConfirm={() => { const u = confirmOff; setConfirmOff(null); patch(u, { is_active: false }, `${u.username} deactivated and signed out.`); }}
        onCancel={() => setConfirmOff(null)}>
        They are signed out everywhere straight away and cannot sign in again until you reactivate the account. Their audit history is kept.
      </ConfirmDialog>

      <Sheet open={!!sheet} title={sheet === "new" ? "Add user" : `Reset password for ${sheet?.username || ""}`} onClose={() => setSheet(null)}
        footer={<>
          <button type="button" className="btn btn-secondary" onClick={() => setSheet(null)}>Cancel</button>
          <button type="button" className="btn btn-primary" onClick={submit} disabled={busy || !form.password || (sheet === "new" && !form.username)}>
            {busy ? "Saving..." : sheet === "new" ? "Add user" : "Set password"}
          </button>
        </>}>
        {sheet === "new" && (
          <div className="form-field">
            <label htmlFor="nu-name">Username</label>
            <input id="nu-name" value={form.username} autoComplete="off" onChange={e => setForm({ ...form, username: e.target.value })} />
          </div>
        )}
        <div className="form-field">
          <label htmlFor="nu-pass">{sheet === "new" ? "Password" : "New password"}</label>
          <input id="nu-pass" type="password" value={form.password} autoComplete="new-password" onChange={e => setForm({ ...form, password: e.target.value })} />
          <p className="sheet-hint">At least 12 characters. Share it in person or through a secure channel; they can change it from the account menu.</p>
        </div>
        {sheet === "new" && (
          <div className="form-field">
            <label>Role</label>
            <Segmented value={form.role} onChange={v => setForm({ ...form, role: v })} options={ROLE_OPTIONS} label="Role" />
            <p className="sheet-hint">{form.role === "admin" ? "Admins can change targets, scans, schedules, exposure settings and users." : "Viewers can look at everything but cannot change anything."}</p>
          </div>
        )}
      </Sheet>

      {loading ? <Skeleton rows={4} /> : failed ? (
        <div className="empty">Could not load users. Only admins can see this page.</div>
      ) : (
        <div className="dl" style={{ "--cols": "minmax(160px,1.6fr) 100px 110px minmax(110px,1fr) minmax(110px,1fr) 36px" }}>
          <div className="dl-head" aria-hidden="true">
            <div>User</div><div>Role</div><div>Status</div><div>Last sign-in</div><div>Password changed</div><div />
          </div>
          {users.map(u => {
            const self = u.username === me;
            return (
              <div className="dl-item" key={u.id}>
                <div className={"dl-row" + (u.is_active ? "" : " paused")}>
                  <div className="dl-main"><div className="dl-title">{u.username}{self ? " (you)" : ""}</div></div>
                  <div className="dl-main">{u.role === "admin" ? "Admin" : "Viewer"}</div>
                  <div className="dl-main">{u.is_active ? "Active" : "Deactivated"}</div>
                  <div className="dl-main" title={u.last_login_at ? new Date(u.last_login_at).toLocaleString() : ""}>{u.last_login_at ? timeAgo(u.last_login_at) : "Never"}</div>
                  <div className="dl-main" title={u.password_changed_at ? new Date(u.password_changed_at).toLocaleString() : ""}>{u.password_changed_at ? timeAgo(u.password_changed_at) : "Never"}</div>
                  <RowMenu label={`Actions for ${u.username}`} items={[
                    ...(self ? [] : [
                      u.role === "admin"
                        ? { label: "Make viewer", icon: Eye, onClick: () => patch(u, { role: "viewer" }, `${u.username} is now a viewer.`) }
                        : { label: "Make admin", icon: ShieldCheck, onClick: () => patch(u, { role: "admin" }, `${u.username} is now an admin.`) },
                      { label: "Reset password", icon: KeyRound, onClick: () => openReset(u) },
                      ...(u.mfa_enabled ? [{ label: "Reset two-step sign-in", icon: ShieldCheck, onClick: () => setConfirmMfa(u) }] : []),
                      { type: "divider" },
                      u.is_active
                        ? { label: "Deactivate", icon: UserX, danger: true, onClick: () => setConfirmOff(u) }
                        : { label: "Reactivate", icon: UserCheck, onClick: () => patch(u, { is_active: true }, `${u.username} reactivated.`) },
                    ]),
                    ...(self ? [{ label: "Change your password in the account menu", icon: KeyRound, onClick: () => window.dispatchEvent(new Event("asm:change-password")) }] : []),
                  ]} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
