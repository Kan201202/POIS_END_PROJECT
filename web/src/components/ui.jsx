// Reusable UI primitives.
import { useState } from "react";

export function Card({ title, sub, children, action }) {
  return (
    <div className="card">
      {(title || action) && (
        <div className="card-header">
          <div>
            {title && <h3 className="card-title">{title}</h3>}
            {sub && <p className="card-sub">{sub}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export function Button({ children, variant = "primary", loading, ...props }) {
  return (
    <button className={`btn-${variant}`} disabled={loading || props.disabled} {...props}>
      {loading && <span className="spinner" />}
      {children}
    </button>
  );
}

export function Field({ label, hint, children }) {
  return (
    <div>
      {label && <label>{label}</label>}
      {children}
      {hint && <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

export function TextInput({ value, onChange, placeholder, mono = true, ...props }) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      style={{ fontFamily: mono ? "var(--mono)" : "var(--sans)" }}
      {...props}
    />
  );
}

export function Output({ label, children, kind = "default" }) {
  return (
    <div className="output">
      {label && <div className="output-label">{label}</div>}
      {children}
    </div>
  );
}

export function KV({ k, v, success, error }) {
  const cls = success ? "success" : error ? "error" : "";
  return (
    <div className="output-row">
      <span className="output-key">{k}</span>
      <span className={`output-value ${cls}`}>{String(v)}</span>
    </div>
  );
}

export function Badge({ children, variant = "muted" }) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}

export function ErrorBanner({ children }) {
  if (!children) return null;
  return <div className="error-banner">⚠ {children}</div>;
}

export function Description({ children }) {
  return <div className="description-box">{children}</div>;
}

export function ToggleGroup({ value, onChange, options }) {
  return (
    <div className="btn-group">
      {options.map((o) => (
        <button
          key={o.value}
          className={value === o.value ? "active" : ""}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Collapse({ title, children, initial = false }) {
  const [open, setOpen] = useState(initial);
  return (
    <div className="card" style={{ padding: "12px 16px" }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 8, userSelect: "none" }}
      >
        <span style={{ color: "var(--text-faint)", fontSize: 11 }}>{open ? "▼" : "▶"}</span>
        <span style={{ fontWeight: 500, fontSize: 13 }}>{title}</span>
      </div>
      {open && <div style={{ marginTop: 12 }}>{children}</div>}
    </div>
  );
}
