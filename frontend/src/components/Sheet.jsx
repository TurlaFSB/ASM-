import { useEffect, useRef } from "react";
import { X } from "lucide-react";

// Slide-in side panel on the native <dialog>: focus is trapped, Escape and a click on the dimmed
// background close it, and the page behind stays still. Use it for create/edit forms.
export default function Sheet({ open, title, onClose, footer, children }) {
  const ref = useRef(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog ref={ref} className="sheet" aria-labelledby="sheet-title"
      onCancel={(e) => { e.preventDefault(); onClose(); }}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}>
      {open && (
        <div className="sheet-panel">
          <header className="sheet-head">
            <h2 id="sheet-title">{title}</h2>
            <button type="button" className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
          </header>
          <div className="sheet-body">{children}</div>
          {footer && <footer className="sheet-foot">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}
