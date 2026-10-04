import { useState } from "react";
import { updateTargetTags } from "../api";
import { parseTags } from "../lib/tags";

// Inline editor for a target's tags. Typed as comma-separated text; the server normalises and validates.
export default function TagEditor({ target, onSaved, onCancel }) {
  const [text, setText] = useState((target.tags || []).join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const save = async (e) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const r = await updateTargetTags(target.id, parseTags(text));
      onSaved(r.data);
    } catch (err) {
      const d = err?.response?.data?.detail;
      setError(typeof d === "string" ? d : Array.isArray(d) ? d.map(x => x.msg.replace(/^Value error, /, "")).join(", ") : "Could not save tags.");
    } finally { setBusy(false); }
  };

  return (
    <form className="tag-editor" onSubmit={save}>
      <label htmlFor={`tags-${target.id}`}>Tags for {target.domain}</label>
      <div className="notif-row">
        <input id={`tags-${target.id}`} type="text" value={text} onChange={e => setText(e.target.value)}
          placeholder="prod, team-a, customer-x" spellCheck={false} autoFocus />
      </div>
      <p className="muted-note">Up to 10 tags, separated by commas. Use them to group targets and filter this list.</p>
      <div className="notif-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy}>Save tags</button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onCancel} disabled={busy}>Cancel</button>
        {error && <span className="notif-note bad" role="alert">{error}</span>}
      </div>
    </form>
  );
}
