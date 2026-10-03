import './ToggleSwitch.css';

export default function ToggleSwitch({ checked, onChange, label, ariaLabel, disabled }) {
  return (
    <label className="toggle-row">
      {label && <span className="toggle-label">{label}</span>}
      <span className="ios-toggle">
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          aria-label={label ? undefined : ariaLabel}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className="ios-toggle-track">
          <span className="ios-toggle-knob" />
        </span>
      </span>
    </label>
  );
}
