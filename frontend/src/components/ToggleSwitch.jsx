import './ToggleSwitch.css';

export default function ToggleSwitch({ checked, onChange, label }) {
  return (
    <label className="toggle-row">
      {label && <span className="toggle-label">{label}</span>}
      <span className="ios-toggle">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className="ios-toggle-track">
          <span className="ios-toggle-knob" />
        </span>
      </span>
    </label>
  );
}
