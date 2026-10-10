import { useEffect, useState } from "react";
import { Plus, KeyRound, Copy, Check, Trash2, ShieldCheck } from "lucide-react";
import QRCode from "qrcode";
import { getMe, getApiTokens, createApiToken, revokeApiToken, mfaSetup, mfaEnable, mfaDisable, mfaNewRecoveryCodes } from "../api";
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

  // Two-step sign-in. mfa: null | { step: "password" | "scan" | "codes" | "off" | "regen", ... }
  const [mfa, setMfa] = useState(null);
  const [mfaForm, setMfaForm] = useState({ password: "", code: "" });
  const [mfaBusy, setMfaBusy] = useState(false);
  const [mfaErr, setMfaErr] = useState("");

  const openMfa = (step) => { setMfaForm({ password: "", code: "" }); setMfaErr(""); setMfa({ step }); };
  const mfaRun = async (fn) => {
    setMfaBusy(true); setMfaErr("");
    try { await fn(); } catch (e) { setMfaErr(errText(e, "That did not work.")); }
    finally { setMfaBusy(false); }
  };
  const startEnrol = () => mfaRun(async () => {
    const r = await mfaSetup(mfaForm.password);
    const qr = await QRCode.toDataURL(r.data.otpauth_uri, { margin: 1, width: 192 });
    setMfaForm({ password: "", code: "" });
    setMfa({ step: "scan", secret: r.data.secret, qr });
  });
  const finishEnrol = () => mfaRun(async () => {
    const r = await mfaEnable(mfaForm.code);
    setMfa({ step: "codes", codes: r.data.recovery_codes });
    load();
  });
  const turnOff = () => mfaRun(async () => {
    await mfaDisable(mfaForm.password, mfaForm.code);
    setMfa(null); toast("Two-step sign-in is off."); load();
  });
  const regenerate = () => mfaRun(async () => {
    const r = await mfaNewRecoveryCodes(mfaForm.password, mfaForm.code);
    setMfa({ step: "codes", codes: r.data.recovery_codes });
  });

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

      <section className="account-section" aria-labelledby="acc-mfa">
        <h2 id="acc-mfa" className="section-title">Two-step sign-in</h2>
        <p className="muted-note">
          {me?.mfa_enabled
            ? "On. Signing in needs a 6-digit code from your authenticator app after your password. API tokens are not affected."
            : "Off. Add an authenticator app (Google Authenticator, Authy, 1Password and similar) so a stolen password alone is not enough to sign in."}
        </p>
        {me?.mfa_enabled ? (
          <div className="section-head" style={{ justifyContent: "flex-start", gap: 8 }}>
            <button type="button" className="btn btn-secondary" onClick={() => openMfa("regen")}>New recovery codes</button>
            <button type="button" className="btn btn-secondary" onClick={() => openMfa("off")}>Turn off</button>
          </div>
        ) : (
          <button type="button" className="btn btn-secondary" onClick={() => openMfa("password")}><ShieldCheck size={16} /> Turn on</button>
        )}
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

      <Sheet open={!!mfa} onClose={() => setMfa(null)}
        title={{ password: "Turn on two-step sign-in", scan: "Scan the code", codes: "Save your recovery codes", off: "Turn off two-step sign-in", regen: "New recovery codes" }[mfa?.step] || ""}
        footer={mfa?.step === "codes" ? (
          <button type="button" className="btn btn-primary" onClick={() => setMfa(null)}>I have saved them</button>
        ) : (
          <>
            <button type="button" className="btn btn-secondary" onClick={() => setMfa(null)}>Cancel</button>
            {mfa?.step === "password" && <button type="button" className="btn btn-primary" disabled={mfaBusy || !mfaForm.password} onClick={startEnrol}>Continue</button>}
            {mfa?.step === "scan" && <button type="button" className="btn btn-primary" disabled={mfaBusy || mfaForm.code.length < 6} onClick={finishEnrol}>Turn on</button>}
            {mfa?.step === "off" && <button type="button" className="btn btn-primary" disabled={mfaBusy || !mfaForm.password || !mfaForm.code} onClick={turnOff}>Turn off</button>}
            {mfa?.step === "regen" && <button type="button" className="btn btn-primary" disabled={mfaBusy || !mfaForm.password || !mfaForm.code} onClick={regenerate}>Create new codes</button>}
          </>
        )}>
        {mfaErr && <div className="login-error" role="alert">{mfaErr}</div>}
        {mfa?.step === "password" && (
          <div className="form-field">
            <label htmlFor="mfa-pw">Your password</label>
            <input id="mfa-pw" type="password" autoComplete="current-password" value={mfaForm.password} onChange={e => setMfaForm({ ...mfaForm, password: e.target.value })} />
          </div>
        )}
        {mfa?.step === "scan" && (
          <>
            <p className="sheet-hint" style={{ marginTop: 0 }}>Scan this with your authenticator app, then type the 6-digit code it shows.</p>
            <img src={mfa.qr} alt="QR code for your authenticator app" width={192} height={192} />
            <p className="sheet-hint">Cannot scan? Enter this key by hand: <code>{mfa.secret}</code></p>
            <div className="form-field">
              <label htmlFor="mfa-code">6-digit code</label>
              <input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={mfaForm.code} onChange={e => setMfaForm({ ...mfaForm, code: e.target.value })} />
            </div>
          </>
        )}
        {mfa?.step === "codes" && (
          <>
            <p className="sheet-hint" style={{ marginTop: 0 }}>If you lose your phone, each of these signs you in once. They are shown only now, so store them somewhere safe.</p>
            <pre className="mono" aria-label="Recovery codes">{(mfa.codes || []).join("\n")}</pre>
          </>
        )}
        {(mfa?.step === "off" || mfa?.step === "regen") && (
          <>
            <p className="sheet-hint" style={{ marginTop: 0 }}>Confirm with your password and a code from your app (or a recovery code).{mfa.step === "regen" ? " Your old recovery codes stop working." : ""}</p>
            <div className="form-field">
              <label htmlFor="mfa-pw2">Your password</label>
              <input id="mfa-pw2" type="password" autoComplete="current-password" value={mfaForm.password} onChange={e => setMfaForm({ ...mfaForm, password: e.target.value })} />
            </div>
            <div className="form-field">
              <label htmlFor="mfa-code2">Code</label>
              <input id="mfa-code2" autoComplete="one-time-code" value={mfaForm.code} onChange={e => setMfaForm({ ...mfaForm, code: e.target.value })} />
            </div>
          </>
        )}
      </Sheet>

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
