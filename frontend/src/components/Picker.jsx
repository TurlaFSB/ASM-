import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronsUpDown, Search } from "lucide-react";
import usePopover from "./Popover";

/**
 * A large, keyboard-friendly replacement for <select>.
 * options: [{ value, label, hint? }]. Shows a search box once the list is long.
 */
export default function Picker({ value, onChange, options, icon: Icon, ariaLabel, minWidth = 280 }) {
  const { triggerRef, menuRef, open, pos, show, close } = usePopover(Math.min(options.length, 7) * 52 + 24);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const searchable = options.length > 7;

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? options.filter(o => `${o.label} ${o.hint || ""}`.toLowerCase().includes(q)) : options;
  }, [options, query]);

  const current = options.find(o => o.value === value) || options[0];

  const openMenu = () => { setQuery(""); setActive(Math.max(0, options.findIndex(o => o.value === value))); show(); };
  const toggleMenu = () => (open ? close() : openMenu());

  const choose = (o) => { onChange(o.value); close(); triggerRef.current?.focus(); };

  const onKeyDown = (e) => {
    if (!open && ["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) { e.preventDefault(); openMenu(); return; }
    if (!open) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActive(i => Math.min(shown.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive(i => Math.max(0, i - 1)); }
    else if (e.key === "Home") { e.preventDefault(); setActive(0); }
    else if (e.key === "End") { e.preventDefault(); setActive(shown.length - 1); }
    else if (e.key === "Enter") { e.preventDefault(); if (shown[active]) choose(shown[active]); }
  };

  return (
    <div className="pk" onKeyDown={onKeyDown}>
      <button type="button" ref={triggerRef} className={"pk-trigger" + (open ? " open" : "")} aria-haspopup="listbox"
        aria-expanded={open} aria-label={ariaLabel} onClick={toggleMenu} style={{ minWidth }}>
        {Icon && <Icon size={18} className="pk-icon" />}
        <span className="pk-text">
          <span className="pk-label">{current?.label ?? "Select"}</span>
          {current?.hint && <span className="pk-hint">{current.hint}</span>}
        </span>
        <ChevronsUpDown size={16} className="pk-chevron" />
      </button>
      {open && createPortal(
        <div ref={menuRef} className="pk-menu" role="listbox" aria-label={ariaLabel}
          style={{ position: "fixed", top: pos.top, left: pos.left, minWidth: Math.max(pos.width, minWidth) }}>
          {searchable && (
            <div className="pk-search">
              <Search size={14} />
              <input autoFocus value={query} onChange={e => { setQuery(e.target.value); setActive(0); }} placeholder="Search" aria-label="Search" />
            </div>
          )}
          <div className="pk-list">
            {shown.length === 0 && <div className="pk-empty">No matches</div>}
            {shown.map((o, i) => (
              <button type="button" role="option" key={o.value} aria-selected={o.value === value}
                className={"pk-item" + (i === active ? " active" : "")} onMouseEnter={() => setActive(i)} onClick={() => choose(o)}>
                <span className="pk-text">
                  <span className="pk-label">{o.label}</span>
                  {o.hint && <span className="pk-hint">{o.hint}</span>}
                </span>
                {o.value === value && <Check size={16} className="pk-check" />}
              </button>
            ))}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
