import { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { getTicketing, updateTicketing, checkTicketing } from "../api";
import Segmented from "./Segmented";

const SEVERITIES = [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]];
const PLACEHOLDER = { github: "owner/repository", jira: "Project key, for example SEC" };
const PROVIDER = { github: "GitHub Issues", jira: "Jira" };

function errorText(e, fallback) {
  const d = e?.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg).join(", ");
  return fallback;
}

export default function TicketingSettings({ target }) {
  const [saved, setSaved] = useState(null);
  const [destination, setDestination] = useState("");
  const [minSeverity, setMinSeverity] = useState("high");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);

  const apply = (data) => { setSaved(data); setDestination(data.destination || ""); setMinSeverity(data.min_severity); };

  useEffect(() => {
    let live = true;
    getTicketing(target.id)
      .then(r => live && apply(r.data))
      .catch(() => live && setNote({ tone: "bad", text: "Could not load ticketing settings." }));
    return () => { live = false; };
  }, [target.id]);

  const save = async () => {
    setBusy(true); setNote(null);
    try {
      apply((await updateTicketing(target.id, { destination: destination.trim(), min_severity: minSeverity })).data);
      setNote({ tone: "ok", text: "Saved." });
    } catch (e) { setNote({ tone: "bad", text: errorText(e, "Could not save.") }); }
    finally { setBusy(false); }
  };

  const check = async () => {
    setBusy(true); setNote(null);
    try {
      const r = (await checkTicketing(target.id)).data;
      setNote({ tone: r.ok ? "ok" : "bad", text: r.message });
    } catch (e) { setNote({ tone: "bad", text: errorText(e, "Could not check the connection.") }); }
    finally { setBusy(false); }
  };

  if (!saved) return <div className="loading">{note ? note.text : "Loading..."}</div>;

  const dirty = destination.trim() !== (saved.destination || "") || minSeverity !== saved.min_severity;

  return (
    <div className="notif">
      <section>
        <h3>Tickets</h3>
        {!saved.configured ? (
          <p className="muted-note">
            {saved.provider
              ? `${PROVIDER[saved.provider]} is chosen on this server but needs ${saved.missing.join(", ")}.`
              : "Ticketing is not set up on this server. An admin needs to set ASM_TICKETS_PROVIDER and its credentials first (see the README)."}
          </p>
        ) : (
          <>
            <p className="muted-note">
              Open one {PROVIDER[saved.provider]} ticket for each new confirmed change at or above the level below.
              A change never gets a second ticket.
            </p>
            <div className="notif-row">
              <input type="text" value={destination} onChange={e => setDestination(e.target.value)} spellCheck={false}
                aria-label="Ticket destination" placeholder={PLACEHOLDER[saved.provider]} maxLength={100} />
            </div>
            <Segmented label="Open tickets for" options={SEVERITIES} value={minSeverity} onChange={setMinSeverity} />
            <div className="notif-actions">
              <button className="btn btn-primary btn-sm" onClick={save} disabled={busy || !dirty}>Save changes</button>
              {saved.destination && !dirty && (
                <button className="btn btn-secondary btn-sm" onClick={check} disabled={busy}>Check connection</button>
              )}
              {note && <span className={"notif-note " + note.tone} role="status">{note.text}</span>}
            </div>
          </>
        )}
      </section>

      {saved.recent.length > 0 && (
        <section>
          <h3>Recent tickets</h3>
          <ul className="plain-list">
            {saved.recent.map(t => (
              <li key={t.id}>
                <span className={"badge badge-sev-" + (t.severity === "critical" || t.severity === "high" ? "high" : "info")}>{t.severity}</span>{" "}
                {t.status === "created" && t.url
                  ? <a href={t.url} target="_blank" rel="noopener noreferrer">{t.key} <ExternalLink size={12} aria-hidden="true" /></a>
                  : <span>Not created{t.error ? `: ${t.error}` : ""}</span>}{" "}
                <span className="muted-note">{t.title}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {!saved.configured && note && <span className={"notif-note " + note.tone} role="status">{note.text}</span>}
    </div>
  );
}
