import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

// Drop this directly above a `.table-container` div. Shows a frosted-glass
// control with left/right arrow buttons that smoothly scroll the table.
// Buttons disable themselves at each end, and the whole control hides once
// there's nothing left to scroll (table fits, or no overflow at all).
export default function ScrollHint({ containerRef }) {
  const [state, setState] = useState({ hasOverflow: false, atStart: true, atEnd: false });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const update = () => {
      const hasOverflow = el.scrollWidth > el.clientWidth + 4;
      const atStart = el.scrollLeft <= 4;
      const atEnd = el.scrollLeft >= el.scrollWidth - el.clientWidth - 4;
      setState({ hasOverflow, atStart, atEnd });
    };

    update();
    el.addEventListener("scroll", update, { passive: true });
    const resizeObserver = new ResizeObserver(update);
    resizeObserver.observe(el);

    return () => {
      el.removeEventListener("scroll", update);
      resizeObserver.disconnect();
    };
  }, [containerRef]);

  const scrollBy = (dir) => {
    const el = containerRef.current;
    if (!el) return;
    el.scrollBy({ left: dir * Math.min(el.clientWidth * 0.7, 320), behavior: "smooth" });
  };

  if (!state.hasOverflow) return null;

  return (
    <div className="scroll-hint-wrap">
      <div className="scroll-hint">
        <button
          className="scroll-hint-btn"
          onClick={() => scrollBy(-1)}
          disabled={state.atStart}
          aria-label="Scroll left"
          type="button"
        >
          <ChevronLeft size={14} />
        </button>
        <span>Scroll for more</span>
        <button
          className="scroll-hint-btn"
          onClick={() => scrollBy(1)}
          disabled={state.atEnd}
          aria-label="Scroll right"
          type="button"
        >
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}
