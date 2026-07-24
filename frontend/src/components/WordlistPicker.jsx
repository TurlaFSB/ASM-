import { useState, useRef, useEffect } from "react";
import { createPortal } from "react-dom";
import { ChevronDown, Check } from "lucide-react";

const OPTIONS = [
  { value: "small", label: "Small", hint: "~20k words · fast" },
  { value: "medium", label: "Medium", hint: "~30k words · thorough" },
];

export default function WordlistPicker({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const [menuPos, setMenuPos] = useState({ top: 0, left: 0 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);

  const openMenu = () => {
    const rect = triggerRef.current.getBoundingClientRect();
    const menuHeight = Math.min(OPTIONS.length * 52 + 12, 240) + 6;
    // Flip above the trigger if there isn't room below the viewport --
    // this is exactly the case that broke on the last table row.
    const spaceBelow = window.innerHeight - rect.bottom;
    const top = spaceBelow < menuHeight
      ? rect.top - menuHeight - 6
      : rect.bottom + 6;
    setMenuPos({ top, left: rect.left, width: Math.max(rect.width, 210) });
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
    const onScrollOrResize = () => setOpen(false);
    document.addEventListener("mousedown", onClickOutside);
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [open]);

  const current = OPTIONS.find(o => o.value === value) || OPTIONS[0];

  return (
    <div className="wordlist-picker">
      <button
        type="button"
        ref={triggerRef}
        className="wordlist-picker-trigger"
        onClick={() => (open ? setOpen(false) : openMenu())}
      >
        <span className="wordlist-picker-label">Wordlist: {current.label}</span>
        <ChevronDown size={13} className={open ? "wordlist-picker-chevron open" : "wordlist-picker-chevron"} />
      </button>
      {open && createPortal(
        <div
          ref={menuRef}
          className="wordlist-picker-menu"
          style={{ position: "fixed", top: menuPos.top, left: menuPos.left, minWidth: Math.max(menuPos.width, 190) }}
        >
          {OPTIONS.map(opt => (
            <button
              type="button"
              key={opt.value}
              className="wordlist-picker-item"
              onClick={() => { onChange(opt.value); setOpen(false); }}
            >
              <div className="wordlist-picker-item-text">
                <span className="wordlist-picker-item-label">{opt.label}</span>
                <span className="wordlist-picker-item-hint">{opt.hint}</span>
              </div>
              {opt.value === value && <Check size={14} className="wordlist-picker-check" />}
            </button>
          ))}
        </div>,
        document.body
      )}
    </div>
  );
}
