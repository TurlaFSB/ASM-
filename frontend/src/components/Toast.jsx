import { useCallback, useMemo, useRef, useState } from "react";
import { ToastContext } from "./toastContext";

// Transient, non-blocking feedback. Replaces window.alert. Polite live region so screen readers hear it.
export default function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id) => setItems(list => list.filter(t => t.id !== id)), []);

  const toast = useCallback((text, tone = "ok") => {
    const id = nextId.current++;
    setItems(list => [...list.slice(-3), { id, text, tone }]);
    setTimeout(() => dismiss(id), tone === "bad" ? 7000 : 4000);
  }, [dismiss]);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {items.map(t => (
          <div key={t.id} className={"toast " + t.tone}>
            <span>{t.text}</span>
            <button type="button" className="toast-close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
