import { useEffect, useState } from "react";
import { Plus, KeyRound, Copy, Check, Trash2 } from "lucide-react";
import { getMe, getApiTokens, createApiToken, revokeApiToken } from "../api";
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

const SCOPES = [["read", "Read only"], ["write", "Full access"]];
const EXPIRY = [[30, "30 days"], [90, "90 days"], [365, "1 year"], [0, "Never"]];

function statusOf(t) {
  if (t.revoked_at) return "Revoked";
  if (t.expires_at && new Date(t.expires_at) <= new Date()) return "Expired";
  return "Active";
}

export default function Account() {
  const { toast } = useToast();
  const [me, setMe] = useState(null);
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", scope: "read", days: 90 });
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState(null);       // shown once, right after creating
  const [copied, setCopied] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(null);

  const load = () => {
    Promise.all([getMe(), getApiTokens()])
      .then(([m, t]) => { setMe(m.data); setTokens(t.data); setFailed(false); })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const isAdmin = (me?.role || "admin") === "admin";
  const openNew = () => { setForm({ name: "", scope: "read", days: 90 }); setSecret(null); setCopied(false); setOpen(true); };

  const create = async () => {
    setBusy(true);
    try {
      const r = await createApiToken({ name: form.name, scope: form.scope, expires_in_days: form.days || null });
      setSecret(r.data.token);
      load();
    } catch (e) { toast(errText(e, "Could not create the token."), "bad"); }
    finally { setBusy(false); }
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(secret); setCopied(true); }
    catch { toast("Could not copy. Select the token and copy it by hand.", "bad"); }
  };

  const revoke = async (t) => {
    try { await revokeApiToken(t.id); toast(`${t.name} revoked.`); load(); }
    catch (e) { toast(errText(e, "Could not revoke the token."), "bad"); }
  };

  return (
    <div className="page">
      <div className="page-header"><h1>Account</h1></div>

      <section className="account-section" aria-labelledby="acc-pw">
        <h2 id="acc-pw" className="section-title">Password</h2>
        <p className="muted-note">Changing your password signs you out everywhere else and ends all of your API tokens.</p>
        <button type="button" className="btn btn-secondary" onClick={() => window.dispatchEvent(new Event("asm:change-password"))}>
          <KeyRound size={16} /> Change password
        </button>
      </section>

      <section className="account-section" aria-labelledby="acc-tok">
        <div className="section-head">
          <h2 id="acc-tok" className="section-title">API tokens</h2>
          <button type="button" className="btn btn-primary" onClick={openNew}><Plus size={16} /> New token</button>
        </div>
        <p className="muted-note">
          For scripts and pipelines. Send one as <code>Authorization: Bearer asm_...</code>. A token acts as you, stops working when your account is
          deactivated, and is shown only once, so store it somewhere safe.
        </p>

        {loading ? <Skeleton rows={3} /> : failed ? (
          <div className="empty">Could not load your tokens. Check that the API is running.</div>
        ) : tokens.length === 0 ? (
          <div className="empty">No tokens yet. Create one when a script needs to read or change data.</div>
        ) : (
          <div className="dl" style={{ "--cols": "minmax(140px,1.4fr) minmax(120px,1fr) 100px 90px minmax(110px,1fr) minmax(110px,1fr) 36px" }}>
            <div className="dl-head" aria-hidden="true">
              <div>Name</div><div>Starts with</div><div>Access</div><div>Status</div><div>Last used</div><div>Expires</div><div />
            </div>
            {tokens.map(t => {
              const st = statusOf(t);
              return (
                <div className="dl-item" key={t.id}>
                  <div className={"dl-row" + (st === "Active" ? "" : " paused")}>
                    <div className="dl-main"><div className="dl-title">{t.name}</div></div>
                    <div className="dl-main mono">{t.prefix}...</div>
                    <div className="dl-main">{t.scope === "write" ? "Full access" : "Read only"}</div>
                    <div className="dl-main">{st}</div>
                    <div className="dl-main">{t.last_used_at ? timeAgo(t.last_used_at) : "Never"}</div>
                    <div className="dl-main">{t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "Never"}</div>
                    {st === "Active"
                      ? <RowMenu label={`Actions for token ${t.name}`} items={[{ label: "Revoke", icon: Trash2, danger: true, onClick: () => setConfirmRevoke(t) }]} />
                      : <div />}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <ConfirmDialog open={!!confirmRevoke} tone="danger" title={`Revoke ${confirmRevoke?.name}?`} confirmLabel="Revoke"
        onConfirm={() => { const t = confirmRevoke; setConfirmRevoke(null); revoke(t); }} onCancel={() => setConfirmRevoke(null)}>
        Anything using this token stops working straight away. This cannot be undone.
      </ConfirmDialog>

      <Sheet open={open} title={secret ? "Copy your token" : "New API token"} onClose={() => setOpen(false)}
        footer={secret ? (
          <button type="button" className="btn btn-primary" onClick={() => setOpen(false)}>Done</button>
        ) : (
          <>
            <button type="button" className="btn btn-secondary" onClick={() => setOpen(false)}>Cancel</button>
            <button type="button" className="btn btn-primary" onClick={create} disabled={busy || !form.name.trim()}>
              {busy ? "Creating..." : "Create token"}
            </button>
          </>
        )}>
        {secret ? (
          <>
            <p className="sheet-hint" style={{ marginTop: 0 }}>This is the only time the token is shown. Copy it now and keep it secret.</p>
            <div className="form-field">
              <label htmlFor="tok-secret">Token</label>
              <input id="tok-secret" className="mono" readOnly value={secret} onFocus={e => e.target.select()} />
            </div>
            <button type="button" className="btn btn-secondary" onClick={copy}>
              {copied ? <Check size={16} /> : <Copy size={16} />} {copied ? "Copied" : "Copy token"}
            </button>
          </>
        ) : (
          <>
            <div className="form-field">
              <label htmlFor="tok-name">Name</label>
              <input id="tok-name" value={form.name} maxLength={80} autoComplete="off" placeholder="For example: CI pipeline"
                onChange={e => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="form-field">
              <label>Access</label>
              {isAdmin
                ? <Segmented value={form.scope} onChange={v => setForm({ ...form, scope: v })} options={SCOPES} label="Access" />
                : <p className="sheet-hint" style={{ marginTop: 0 }}>Read only. Viewer accounts cannot create tokens that change data.</p>}
              <p className="sheet-hint">{form.scope === "write" && isAdmin ? "Can do everything you can, including starting scans and changing targets." : "Can look at everything you can see but cannot change anything."}</p>
            </div>
            <div className="form-field">
              <label>Expires</label>
              <Segmented value={form.days} onChange={v => setForm({ ...form, days: v })} options={EXPIRY} label="Expires" />
            </div>
          </>
        )}
      </Sheet>
    </div>
  );
}
