import { useState } from "react";
import Sheet from "./Sheet";
import { changePassword } from "../api";
import { useToast } from "./toastContext";

// Side panel for changing your own password. Other devices are signed out; this one stays signed in.
export default function ChangePassword({ open, onClose }) {
  const { toast } = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const close = () => { setCurrent(""); setNext(""); setConfirm(""); setError(""); onClose(); };

  const submit = async () => {
    setError("");
    if (next !== confirm) { setError("The two new passwords do not match."); return; }
    setBusy(true);
    try {
      await changePassword(current, next);
      toast("Password changed. Your other sessions were signed out.");
      close();
    } catch (e) {
      const d = e.response?.data?.detail;
      setError(typeof d === "string" ? d : Array.isArray(d) ? d.map(x => x.msg).join(", ") : "Could not change the password.");
    } finally { setBusy(false); }
  };

  return (
    <Sheet open={open} title="Change password" onClose={close}
      footer={<>
        <button type="button" className="btn btn-secondary" onClick={close}>Cancel</button>
        <button type="button" className="btn btn-primary" onClick={submit} disabled={busy || !current || !next || !confirm}>{busy ? "Saving..." : "Change password"}</button>
      </>}>
      <div className="form-field">
        <label htmlFor="cp-cur">Current password</label>
        <input id="cp-cur" type="password" value={current} autoComplete="current-password" onChange={e => setCurrent(e.target.value)} />
      </div>
      <div className="form-field">
        <label htmlFor="cp-new">New password</label>
        <input id="cp-new" type="password" value={next} autoComplete="new-password" onChange={e => setNext(e.target.value)} />
        <p className="sheet-hint">At least 12 characters.</p>
      </div>
      <div className="form-field">
        <label htmlFor="cp-conf">Confirm new password</label>
        <input id="cp-conf" type="password" value={confirm} autoComplete="new-password" onChange={e => setConfirm(e.target.value)} />
      </div>
      {error && <div className="login-error" role="alert">{error}</div>}
    </Sheet>
  );
}
