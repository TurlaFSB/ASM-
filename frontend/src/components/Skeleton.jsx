// Placeholder rows shown while a list loads: keeps the layout stable and feels faster than a spinner.
export default function Skeleton({ rows = 5, height = 52 }) {
  return (
    <div className="skeleton-list" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton-row" style={{ height, animationDelay: `${i * 90}ms` }} />)}
    </div>
  );
}
