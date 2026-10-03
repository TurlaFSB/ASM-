import { useEffect, useRef } from "react";

// Modal confirmation on the native <dialog>: focus is trapped, Escape cancels, background is inert.
// Replaces window.confirm. `tone="danger"` styles the confirm button as destructive.
export default function ConfirmDialog({ open, title, children, confirmLabel = "Confirm", cancelLabel = "Cancel", tone, busy, onConfirm, onCancel }) {
  const ref = useRef(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog ref={ref} className="confirm" onCancel={(e) => { e.preventDefault(); onCancel(); }}
      onClick={(e) => { if (e.target === ref.current) onCancel(); }}>
      <div className="confirm-body">
        <h2>{title}</h2>
        {children && <div className="confirm-text">{children}</div>}
        <div className="confirm-actions">
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={busy}>{cancelLabel}</button>
          <button type="button" className={"btn " + (tone === "danger" ? "btn-danger" : "btn-primary")} onClick={onConfirm} disabled={busy} autoFocus>
            {busy ? "Working..." : confirmLabel}
          </button>
        </div>
      </div>
    </dialog>
  );
}
