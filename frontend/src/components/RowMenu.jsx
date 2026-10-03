import "./ToggleSwitch.css";
import { createPortal } from "react-dom";
import { MoreHorizontal } from "lucide-react";
import usePopover from "./Popover";

/**
 * Overflow menu for a row's secondary actions.
 * items: { label, icon?, onClick, danger?, active? } | { type: "switch", label, checked, onToggle } | { type: "divider" }
 */
export default function RowMenu({ items, label = "More actions" }) {
  const { triggerRef, menuRef, open, pos, close, toggle } = usePopover(items.length * 40 + 16, "right");

  const onKeyDown = (e) => {
    if (!open) return;
    const els = [...(menuRef.current?.querySelectorAll("[data-rm-item]") || [])];
    const i = els.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); els[(i + 1) % els.length]?.focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); els[(i - 1 + els.length) % els.length]?.focus(); }
  };

  return (
    <div onKeyDown={onKeyDown}>
      <button type="button" ref={triggerRef} className={"icon-btn" + (open ? " open" : "")} aria-label={label}
        aria-haspopup="menu" aria-expanded={open} title={label} onClick={toggle}>
        <MoreHorizontal size={18} />
      </button>
      {open && createPortal(
        <div ref={menuRef} className="rm-menu" role="menu"
          style={{ position: "fixed", top: pos.top, left: Math.max(8, pos.left - 232), width: 232 }}>
          {items.map((it, i) => {
            if (it.type === "divider") return <div key={i} className="rm-divider" role="separator" />;
            if (it.type === "switch") {
              return (
                <label key={i} className="rm-item rm-switch" data-rm-item tabIndex={0}
                  onKeyDown={e => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); it.onToggle(!it.checked); } }}>
                  <span>{it.label}</span>
                  <span className="ios-toggle">
                    <input type="checkbox" checked={it.checked} onChange={e => it.onToggle(e.target.checked)} tabIndex={-1} />
                    <span className="ios-toggle-track"><span className="ios-toggle-knob" /></span>
                  </span>
                </label>
              );
            }
            const Icon = it.icon;
            return (
              <button key={i} type="button" role="menuitem" data-rm-item
                className={"rm-item" + (it.danger ? " danger" : "") + (it.active ? " active" : "")}
                onClick={() => { close(); it.onClick(); }}>
                {Icon && <Icon size={16} />}
                <span>{it.label}</span>
              </button>
            );
          })}
        </div>,
        document.body
      )}
    </div>
  );
}
