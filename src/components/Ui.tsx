import { useState, type ReactNode } from "react";

export function Dot({ tone = "healthy" }: { tone?: string }) {
  return <span className={`dot ${tone}`} />;
}

export function Button({
  children,
  dark = false,
  onClick,
  className = "",
  download = false,
  disabled = false,
}: {
  children: ReactNode;
  dark?: boolean;
  onClick?: () => void;
  className?: string;
  download?: boolean;
  disabled?: boolean;
}) {
  return (
    <button className={`button ${dark ? "dark" : ""} ${className}`} onClick={onClick} disabled={disabled}>
      {download && (
        <svg className="button-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M10 2.75v9.5m0 0 3.5-3.5M10 12.25l-3.5-3.5M4 14.75v2.5h12v-2.5" />
        </svg>
      )}
      {children}
    </button>
  );
}

export function Toggle({
  initial = false,
  checked,
  onChange,
  disabled = false,
  title,
}: {
  initial?: boolean;
  checked?: boolean;
  onChange?: (next: boolean) => void;
  disabled?: boolean;
  title?: string;
}) {
  const [on, setOn] = useState(initial);
  const value = checked ?? on;
  return (
    <button
      type="button"
      aria-label={disabled ? "Not available yet" : value ? "Disable" : "Enable"}
      aria-pressed={value}
      disabled={disabled}
      title={title}
      className={`toggle ${value ? "on" : ""}`}
      onClick={() => {
        if (disabled) return;
        if (onChange) onChange(!value);
        else setOn(!value);
      }}
    >
      <i />
    </button>
  );
}

export function PageTitle({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {action}
    </div>
  );
}

export function Stat({
  label,
  value,
  note,
  figure,
  onClick,
}: {
  label: string;
  value: string;
  note?: string;
  figure?: ReactNode;
  onClick?: () => void;
}) {
  const body = (
    <>
      <span>{label}</span>
      <strong>{value}</strong>
      {note && <small>{note}</small>}
      {figure && (
        <div className="stat-figure" aria-hidden="true">
          {figure}
        </div>
      )}
    </>
  );

  if (onClick) {
    return (
      <button type="button" className="stat card stat-link" onClick={onClick}>
        {body}
      </button>
    );
  }

  return <div className="stat card">{body}</div>;
}

export function CodeCard({
  title,
  label,
  code,
  footer,
}: {
  title: string;
  label: string;
  code: string;
  footer?: string;
}) {
  return (
    <section className="card code-card">
      <div className="card-heading">
        <h3>{title}</h3>
        <span>{label}</span>
      </div>
      <pre>{code}</pre>
      {footer && <code>{footer}</code>}
    </section>
  );
}

export function NavIcon({ path }: { path: string }) {
  return (
    <svg
      className="nav-icon"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.6}
      aria-hidden="true"
    >
      {path.split(" M").map((seg, i) => (
        <path key={i} strokeLinecap="round" strokeLinejoin="round" d={i === 0 ? seg : "M" + seg} />
      ))}
    </svg>
  );
}
