// Animated expand/collapse. Animates the real height (grid 0fr -> 1fr), so content of any size
// slides open without a measured max-height. Hidden content is inert so it cannot take focus.
export default function Collapse({ open, children }) {
  return (
    <div className={"collapse" + (open ? " open" : "")} aria-hidden={!open} inert={!open}>
      <div className="collapse-inner">{children}</div>
    </div>
  );
}
