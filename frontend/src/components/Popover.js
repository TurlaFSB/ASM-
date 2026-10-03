import { useEffect, useRef, useState, useCallback } from "react";

// Shared behaviour for the Picker and RowMenu popovers: open/close, position under (or above) the
// trigger, close on outside click, Escape, scroll and resize.
export default function usePopover(estimatedHeight = 260, align = "left") {
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0, width: 0 });

  const show = useCallback(() => {
    const r = triggerRef.current.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const top = below < estimatedHeight + 16 && r.top > below ? Math.max(8, r.top - estimatedHeight - 6) : r.bottom + 6;
    setPos({ top, left: align === "right" ? r.right : r.left, width: r.width });
    setOpen(true);
  }, [estimatedHeight, align]);

  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return undefined;
    const outside = (e) => {
      if (triggerRef.current?.contains(e.target) || menuRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    const key = (e) => { if (e.key === "Escape") { setOpen(false); triggerRef.current?.focus(); } };
    const dismiss = (e) => { if (!menuRef.current?.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", key);
    window.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", key);
      window.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", close);
    };
  }, [open, close]);

  return { triggerRef, menuRef, open, pos, show, close, toggle: () => (open ? close() : show()) };
}
