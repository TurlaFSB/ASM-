import { useState, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import { ChevronDown, Check, Gauge } from "lucide-react";
import { FALLBACK_PROFILES, PROFILE_ICONS, PROFILE_COLORS } from "./profileMeta";

export function ProfileBadge({ name }) {
  if (!name) return null;
  const Icon = PROFILE_ICONS[name] || Gauge;
  const color = PROFILE_COLORS[name] || "var(--text-secondary)";
  return (
    <span className="profile-badge" style={{ color, borderColor: color }}>
      <Icon size={11} /> {name}
    </span>
  );
}

export default function ProfilePicker({ value, onChange, profiles }) {
  const options = profiles && profiles.length ? profiles : FALLBACK_PROFILES;
  const [open, setOpen] = useState(false);
  const [menuPos, setMenuPos] = useState({ top: 0, left: 0, width: 0 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);

  const openMenu = () => {
    const rect = triggerRef.current.getBoundingClientRect();
    const menuHeight = options.length * 64 + 12 + 6;
    // Flip above the trigger when there is no room below (last table row case).
    const spaceBelow = window.innerHeight - rect.bottom;
    const top = spaceBelow < menuHeight ? rect.top - menuHeight - 6 : rect.bottom + 6;
    setMenuPos({ top, left: rect.left, width: rect.width });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e) => {
      if (
        triggerRef.current && !triggerRef.current.contains(e.target) &&
        menuRef.current && !menuRef.current.contains(e.target)
      ) setOpen(false);
    };
    const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
    const close = () => setOpen(false);
    document.addEventListener("mousedown", onClickOutside);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  const current = options.find(o => o.name === value) || options.find(o => o.name === "standard") || options[0];
  const Icon = PROFILE_ICONS[current.name] || Gauge;

  return (
    <div className="select-menu">
      <button
        type="button"
        ref={triggerRef}
        className="select-menu-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        title={`${current.label}: ${current.description}`}
        onClick={() => (open ? setOpen(false) : openMenu())}
      >
        <Icon size={13} style={{ color: PROFILE_COLORS[current.name] }} />
        <span className="select-menu-label">{current.label}</span>
        <span className="select-menu-est">{current.estimate}</span>
        <ChevronDown size={13} className={open ? "select-menu-chevron open" : "select-menu-chevron"} />
      </button>
      {open && createPortal(
        <div
          ref={menuRef}
          role="listbox"
          className="select-menu-menu"
          style={{ position: "fixed", top: menuPos.top, left: menuPos.left, minWidth: Math.max(menuPos.width, 280) }}
        >
          {options.map(opt => {
            const OptIcon = PROFILE_ICONS[opt.name] || Gauge;
            return (
              <button
                type="button"
                role="option"
                aria-selected={opt.name === current.name}
                key={opt.name}
                className="select-menu-item"
                onClick={() => { onChange(opt.name); setOpen(false); }}
              >
                <OptIcon size={16} style={{ color: PROFILE_COLORS[opt.name], flexShrink: 0 }} />
                <div className="select-menu-item-text">
                  <span className="select-menu-item-label">
                    {opt.label} <span className="select-menu-est">{opt.estimate}</span>
                  </span>
                  <span className="select-menu-item-hint">{opt.description}</span>
                </div>
                {opt.name === current.name && <Check size={14} className="select-menu-check" />}
              </button>
            );
          })}
        </div>,
        document.body
      )}
    </div>
  );
}
