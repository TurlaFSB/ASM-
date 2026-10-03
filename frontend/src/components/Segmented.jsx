// Apple-style segmented control. options: [[value, label, count?]]
export default function Segmented({ value, onChange, options, label }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(([v, t, n]) => (
        <button key={v} type="button" className={"seg-item" + (value === v ? " active" : "")} aria-pressed={value === v} onClick={() => onChange(v)}>
          {t}{n ? <span className="seg-count">{n}</span> : null}
        </button>
      ))}
    </div>
  );
}
