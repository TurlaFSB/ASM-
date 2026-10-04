import { useEffect, useRef, useState } from "react";
import Sheet from "./Sheet";
import { getScanScreenshots, getScanScreenshotImage } from "../api";

// One picture, fetched as a blob (so the session cookie or token is used) once it scrolls into view.
function Thumb({ scanId, shot, onOpen }) {
  const ref = useRef(null);
  const [src, setSrc] = useState(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let url = null;
    let live = true;
    const load = () => getScanScreenshotImage(scanId, shot.id)
      .then(r => { if (live) { url = URL.createObjectURL(r.data); setSrc(url); } })
      .catch(() => live && setFailed(true));
    if (typeof IntersectionObserver === "undefined") { load(); return () => { live = false; }; }
    const io = new IntersectionObserver((entries) => {
      if (entries.some(e => e.isIntersecting)) { io.disconnect(); load(); }
    }, { rootMargin: "200px" });
    if (ref.current) io.observe(ref.current);
    return () => { live = false; io.disconnect(); if (url) URL.revokeObjectURL(url); };
  }, [scanId, shot.id]);

  return (
    <button type="button" ref={ref} className="shot" onClick={() => src && onOpen({ ...shot, src })} disabled={!src}
      aria-label={`Open screenshot of ${shot.host}`}>
      {src ? <img src={src} alt={`Screenshot of ${shot.host}`} />
        : <span className="shot-ph">{failed ? "Could not load" : "Loading"}</span>}
      <span className="shot-cap">{shot.host}</span>
    </button>
  );
}

// Mounted fresh for each scan (see the key below), so its state never needs resetting.
function GalleryBody({ scanId }) {
  const [shots, setShots] = useState(null);
  const [error, setError] = useState(false);
  const [big, setBig] = useState(null);

  useEffect(() => {
    let live = true;
    getScanScreenshots(scanId)
      .then(r => live && setShots(r.data.screenshots))
      .catch(() => live && setError(true));
    return () => { live = false; };
  }, [scanId]);

  return (
    <>
      {error && <div className="muted-note" role="alert">Could not load the screenshots. Try again in a moment.</div>}
      {!error && shots === null && <div className="loading">Loading...</div>}
      {shots && shots.length === 0 && (
        <div className="muted-note">No screenshots for this scan. They are kept for the retention period, then removed.</div>
      )}
      {big && (
        <figure className="shot-big">
          <img src={big.src} alt={`Screenshot of ${big.host}`} />
          <figcaption>
            <span>{big.url || big.host}</span>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => setBig(null)}>Back to all</button>
          </figcaption>
        </figure>
      )}
      {shots && shots.length > 0 && (
        <div className="shot-grid" hidden={!!big}>
          {shots.map(s => <Thumb key={s.id} scanId={scanId} shot={s} onOpen={setBig} />)}
        </div>
      )}
    </>
  );
}

export default function ScreenshotGallery({ scanId, onClose }) {
  return (
    <Sheet open={scanId != null} title={`Screenshots, scan #${scanId}`} onClose={onClose}>
      {scanId != null && <GalleryBody key={scanId} scanId={scanId} />}
    </Sheet>
  );
}
