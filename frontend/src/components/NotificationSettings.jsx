import { useState, useEffect } from "react";
import { Copy, Check } from "lucide-react";
import { getNotificationSettings, updateNotificationSettings, testWebhook, testEmail } from "../api";

const SEVERITIES = [
  ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Everything"],
];
const FORMATS = [["json", "JSON"], ["slack", "Slack"], ["discord", "Discord"]];

function errorText(e, fallback) {
  const d = e?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg).join(", ");
  return fallback;
}

const parseEmails = (text) => text.split(/[,;\s]+/).map(x => x.trim()).filter(Boolean);

function Segmented({ label, options, value, onChange }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, text]) => (
        <button key={v} type="button" className={"seg-item" + (value === v ? " active" : "")}
          aria-pressed={value === v} onClick={() => onChange(v)}>{text}</button>
      ))}
    </div>
  );
}

export default function NotificationSettings({ target }) {
  const [saved, setSaved] = useState(null);       // what the server has
  const [minSeverity, setMinSeverity] = useState("medium");
  const [format, setFormat] = useState("json");
  const [url, setUrl] = useState("");
  const [emails, setEmails] = useState("");        // comma-separated, as typed
  const [secret, setSecret] = useState(null);     // shown once, right after it is created or rotated
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);         // { tone: "ok" | "bad", text }

  useEffect(() => {
    let live = true;
    getNotificationSettings(target.id)
      .then(r => {
        if (!live) return;
        setSaved(r.data); setMinSeverity(r.data.alert_min_severity); setFormat(r.data.webhook_format);
        setEmails((r.data.email_recipients || []).join(", "));
      })
      .catch(() => live && setNote({ tone: "bad", text: "Could not load notification settings." }));
    return () => { live = false; };
  }, [target.id]);

  const apply = (r) => {
    setSaved(r.data); setMinSeverity(r.data.alert_min_severity); setFormat(r.data.webhook_format);
    setEmails((r.data.email_recipients || []).join(", "));
    if (r.data.webhook_secret) { setSecret(r.data.webhook_secret); setCopied(false); }
  };

  const save = async (extra = {}) => {
    setBusy(true); setNote(null);
    try {
      const body = { alert_min_severity: minSeverity, webhook_format: format, email_recipients: parseEmails(emails), ...extra };
      if (url.trim()) body.webhook_url = url.trim();
      apply(await updateNotificationSettings(target.id, body));
      setUrl("");
      setNote({ tone: "ok", text: "Saved." });
    } catch (e) {
      setNote({ tone: "bad", text: errorText(e, "Could not save.") });
    } finally { setBusy(false); }
  };

  const removeWebhook = async () => {
    setBusy(true); setNote(null);
    try {
      apply(await updateNotificationSettings(target.id, { alert_min_severity: minSeverity, webhook_format: format, webhook_url: "" }));
      setSecret(null);
      setNote({ tone: "ok", text: "Webhook removed." });
    } catch (e) { setNote({ tone: "bad", text: errorText(e, "Could not remove the webhook.") }); }
    finally { setBusy(false); }
  };

  const sendTest = async () => {
    setBusy(true); setNote(null);
    try {
      const r = (await testWebhook(target.id)).data;
      setNote(r.status === "sent"
        ? { tone: "ok", text: "Test delivered." }
        : { tone: "bad", text: `Test ${r.status}${r.error ? `: ${r.error}` : ""}.` });
    } catch (e) { setNote({ tone: "bad", text: errorText(e, "Could not send the test.") }); }
    finally { setBusy(false); }
  };

  const sendTestEmail = async () => {
    setBusy(true); setNote(null);
    try {
      const r = (await testEmail(target.id)).data;
      setNote(r.status === "sent"
        ? { tone: "ok", text: "Test email sent." }
        : { tone: "bad", text: `Test email ${r.status}${r.error ? `: ${r.error}` : ""}.` });
    } catch (e) { setNote({ tone: "bad", text: errorText(e, "Could not send the test email.") }); }
    finally { setBusy(false); }
  };

  const copy = async () => {
    try { await navigator.clipboard.writeText(secret); setCopied(true); } catch { /* clipboard blocked: the text is selectable */ }
  };

  if (!saved) return <div className="loading">{note ? note.text : "Loading..."}</div>;

  const savedEmails = (saved.email_recipients || []).join(", ");
  const dirty = minSeverity !== saved.alert_min_severity || format !== saved.webhook_format || url.trim() !== ""
    || parseEmails(emails).join(", ") !== savedEmails;

  return (
    <div className="notif">
      <section>
        <h3>Alert me about</h3>
        <Segmented label="Minimum severity" options={SEVERITIES} value={minSeverity} onChange={setMinSeverity} />
        <p className="muted-note">
          Only confirmed changes at or above this level create an alert or a webhook message.
          Everything is still recorded on the Changes page.
        </p>
      </section>

      <section>
        <h3>Webhook</h3>
        <Segmented label="Message format" options={FORMATS} value={format} onChange={setFormat} />
        <div className="notif-row">
          <input type="url" value={url} onChange={e => setUrl(e.target.value)} spellCheck={false}
            aria-label="Webhook URL"
            placeholder={saved.webhook_configured ? `Sending to ${saved.webhook_host}. Paste a new URL to replace it.` : "https://hooks.slack.com/services/..."} />
        </div>
        <p className="muted-note">
          One message per scan, listing what changed. HTTPS only; private and internal addresses are blocked.
          {format === "json" && " JSON messages are signed so your receiver can check they came from this platform."}
        </p>

        {secret && (
          <div className="secret-box">
            <div className="muted-note">Signing secret. Copy it now; it will not be shown again.</div>
            <div className="secret-line">
              <code>{secret}</code>
              <button type="button" className="btn btn-secondary btn-sm" onClick={copy}>
                {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
      </section>

      <section>
        <h3>Email</h3>
        <div className="notif-row">
          <input type="text" value={emails} onChange={e => setEmails(e.target.value)} spellCheck={false}
            aria-label="Email recipients" placeholder="security@example.com, oncall@example.com" />
        </div>
        <p className="muted-note">
          {saved.smtp_configured
            ? "One email per scan, listing what changed. Up to 10 addresses, separated by commas."
            : "Email is not set up on this server yet. An admin needs to set the ASM_SMTP_* variables first (see the README)."}
        </p>
        {saved.smtp_configured && saved.email_recipients?.length > 0 && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={sendTestEmail} disabled={busy}>Send test email</button>
        )}
      </section>

      <div className="notif-actions">
        <button className="btn btn-primary btn-sm" onClick={() => save()} disabled={busy || !dirty}>Save changes</button>
        {saved.webhook_configured && (
          <>
            <button className="btn btn-secondary btn-sm" onClick={sendTest} disabled={busy}>Send test</button>
            {format === "json" && (
              <button className="btn btn-secondary btn-sm" onClick={() => save({ rotate_secret: true })} disabled={busy}>Rotate secret</button>
            )}
            <button className="btn btn-danger btn-sm" onClick={removeWebhook} disabled={busy}>Remove webhook</button>
          </>
        )}
        {note && <span className={"notif-note " + note.tone} role="status">{note.text}</span>}
      </div>
    </div>
  );
}
