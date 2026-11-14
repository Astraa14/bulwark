import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import { supabase } from "@/lib/supabase";
import AuthScreen from "@/screens/AuthScreen";
import { apiGet, apiPost } from "@/lib/api";
import {
  acceptBaseline,
  addConnection,
  createSite,
  deleteSite,
  explainFinding,
  listConnections,
  listPlatformFindings,
  removeConnection,
  relTime,
  scanConnection,
  scanSiteNow,
  setFindingStatus,
  setSiteInterval,
  setSiteStatus,
  setWebhookSecret,
  shortDate,
  useApiKeys,
  useConnections,
  useSettings,
  useWorkspace,
  verifySite,
  type ApiKeyRow,
  type ConnectionRow,
  type ConnectionType,
  type FindingRow,
  type FindingStatus,
  type ScanCheckResult,
  type ScanRow,
  type Settings,
  type Severity,
  type SiteRow,
} from "@/lib/workspace";

type Theme = "dark" | "light";

type Page =
  | "Overview"
  | "Sites"
  | "Threats"
  | "Scans"
  | "AI Copilot"
  | "Reports"
  | "Integrations"
  | "API Keys"
  | "Settings";

const PLAN_SITE_LIMIT = 10;

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Icon map for sidebar nav items
const NAV_ICONS: Record<string, string> = {
  Overview: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
  Sites: "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9",
  Threats: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
  Scans: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2",
  "AI Copilot": "M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z",
  Reports: "M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z",
  Integrations: "M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1",
  "API Keys": "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z",
  Settings: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z",
};

const INTERVAL_OPTIONS = [
  { value: 15, label: "Every 15 minutes" },
  { value: 30, label: "Every 30 minutes" },
  { value: 60, label: "Every hour" },
  { value: 180, label: "Every 3 hours" },
  { value: 360, label: "Every 6 hours" },
  { value: 1440, label: "Once a day" },
];

const KEY_PROVIDERS = {
  openai: { label: "OpenAI", model: "gpt-4o-mini", placeholder: "sk-..." },
  anthropic: { label: "Anthropic", model: "claude-3-5-haiku-latest", placeholder: "sk-ant-..." },
} as const;

function intervalLabel(minutes: number) {
  return INTERVAL_OPTIONS.find((o) => o.value === minutes)?.label ?? `Every ${minutes} minutes`;
}

function csvCell(value: unknown) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function downloadCsv(name: string, header: string[], rows: unknown[][]) {
  const csv = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Dot({ tone = "healthy" }: { tone?: string }) {
  return <span className={`dot ${tone}`} />;
}

function Button({
  children,
  dark = false,
  onClick,
  className = "",
  download = false,
  disabled = false,
}: {
  children: React.ReactNode;
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

function Header({
  page,
  onMenu,
  email,
  onSignOut,
  onGoKeys,
  monitoringState,
  monitoringLabel,
  onGoSites,
  theme,
  onToggleTheme,
}: {
  page: Page;
  onMenu: () => void;
  email?: string | null;
  onSignOut?: () => void;
  onGoKeys?: () => void;
  monitoringState: "active" | "setup" | "paused";
  monitoringLabel: string;
  onGoSites: () => void;
  theme: Theme;
  onToggleTheme: () => void;
}) {
  const [userMenu, setUserMenu] = useState(false);
  const label = email ?? "you@bulwark.app";
  return (
    <header className="topbar">
      <button className="mobile-menu" onClick={onMenu} aria-label="Open navigation">
        <span />
        <span />
        <span />
      </button>
      <div className="crumb">
        <span>Workspace</span>
        <b>/</b>
        <strong>{page}</strong>
      </div>
      <div className="top-actions">
        <button className="model-picker byok-btn" onClick={onGoKeys} title="Manage AI API keys">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" width="12" height="12" aria-hidden="true">
            <path fillRule="evenodd" d="M9.75 2a.75.75 0 0 1 .75.75v.096A6.5 6.5 0 0 1 14.5 9.5a.75.75 0 0 1-1.5 0 5 5 0 0 0-3.25-4.667V5a.75.75 0 0 1-.75.75h-.5a.75.75 0 0 1-.75-.75v-.25A5 5 0 0 0 4.5 9.5a.75.75 0 0 1-1.5 0A6.5 6.5 0 0 1 7.5 2.846V2.75A.75.75 0 0 1 8.25 2h1.5ZM7 11.5a1 1 0 1 1 2 0 1 1 0 0 1-2 0Z" clipRule="evenodd" />
          </svg>
          AI: BYOK
        </button>
        <button
          type="button"
          className="theme-toggle"
          onClick={onToggleTheme}
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === "dark" ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M20.5 14.2A8.4 8.4 0 0 1 9.8 3.5 8.7 8.7 0 1 0 20.5 14.2Z" />
            </svg>
          )}
          <span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
        </button>
        <button
          type="button"
          className={`system-pill monitoring-status ${monitoringState}`}
          onClick={onGoSites}
          title="View site monitoring status"
          aria-label={`${monitoringLabel}. Open Sites`}
        >
          <Dot tone={monitoringState === "active" ? "healthy" : monitoringState === "setup" ? "medium" : "low"} />
          {monitoringLabel}
          <span className="status-hint">View sites</span>
        </button>
        <div className="user-menu">
          <button
            className="avatar"
            aria-haspopup="menu"
            aria-expanded={userMenu}
            onClick={() => setUserMenu((v) => !v)}
            title={label}
          >
            {label.slice(0, 2).toUpperCase()}
          </button>
          {userMenu && (
            <>
              <button className="menu-scrim" aria-label="Close menu" onClick={() => setUserMenu(false)} />
              <div className="user-pop" role="menu">
                <span>{label}</span>
                <button
                  role="menuitem"
                  onClick={() => {
                    setUserMenu(false);
                    onSignOut?.();
                  }}
                >
                  Sign out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

function NavIcon({ path }: { path: string }) {
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

function Sidebar({
  page,
  setPage,
  open,
  close,
  threatCount,
  siteCount,
}: {
  page: Page;
  setPage: (p: Page) => void;
  open: boolean;
  close: () => void;
  threatCount: number;
  siteCount: number;
}) {
  const nav: Page[] = [
    "Overview",
    "Sites",
    "Threats",
    "Scans",
    "AI Copilot",
    "Reports",
    "Integrations",
    "API Keys",
    "Settings",
  ];
  return (
    <>
      {open && <button className="scrim" onClick={close} aria-label="Close navigation" />}
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <img src="/bulwark-icon.svg" alt="Bulwark" className="brand-logo" />
          <span className="sr-only">Bulwark</span>
        </div>
        <div className="workspace" aria-label="Current workspace">
          Indie workspace
        </div>
        <nav>
          {nav.map((item) => (
            <button
              key={item}
              className={page === item ? "active" : ""}
              onClick={() => {
                setPage(item);
                close();
              }}
            >
              <span className="nav-label">
                {NAV_ICONS[item] && <NavIcon path={NAV_ICONS[item]} />}
                {item}
              </span>
              {item === "Threats" && threatCount > 0 && <small>{threatCount}</small>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="plan">
            <div className="plan-header">
              <strong>Free plan</strong>
              <span className="plan-upgrade">Upgrade ↗</span>
            </div>
            <span>
              {siteCount} of {PLAN_SITE_LIMIT} sites connected
            </span>
            <div className="progress">
              <i style={{ width: `${Math.max(2, (siteCount / PLAN_SITE_LIMIT) * 100)}%` }} />
            </div>
          </div>
          <a href="https://docs.bulwarksecure.app" target="_blank" rel="noreferrer">Documentation ↗</a>
        </div>
      </aside>
    </>
  );
}

function PageTitle({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle: string;
  action?: React.ReactNode;
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

function Stat({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="stat card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </div>
  );
}

function siteHealth(site: SiteRow, findings: FindingRow[]) {
  if (site.status === "pending") return { label: "Awaiting verification", tone: "medium" };
  if (site.status === "paused") return { label: "Paused", tone: "low" };
  const open = findings.filter((f) => f.site_id === site.id && f.status === "open");
  if (open.some((f) => f.severity === "critical" || f.severity === "high")) {
    return { label: "At risk", tone: "critical" };
  }
  if (open.length) return { label: "Needs attention", tone: "high" };
  return { label: "Healthy", tone: "healthy" };
}

type CheckOutcome = "passed" | "finding" | "not_checked" | "error";

type ScanOutcomeSummary = Record<CheckOutcome, number> & {
  detailed: boolean;
  total: number;
  completed: number;
};

const CHECK_OUTCOME_LABEL: Record<CheckOutcome, string> = {
  passed: "Passed",
  finding: "Finding",
  not_checked: "Not checked",
  error: "Error",
};

const CHECK_OUTCOME_ORDER: CheckOutcome[] = ["passed", "finding", "not_checked", "error"];

function outcomeText(outcome: CheckOutcome, count: number) {
  const label = CHECK_OUTCOME_LABEL[outcome].toLowerCase();
  return `${count} ${label}${count === 1 ? "" : "s"}`;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : null;
}

function checkOutcome(result: ScanCheckResult): CheckOutcome {
  const status = String(result.status ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");

  if (status === "error" || status === "errored" || status === "failed") return "error";
  if (
    result.complete === false ||
    status === "not_checked" ||
    status === "skipped" ||
    status === "unavailable"
  ) {
    return "not_checked";
  }
  if (status === "finding" || status === "findings" || status === "issue" || status === "observed") {
    return "finding";
  }
  if (status === "passed" || status === "pass" || status === "clean" || status === "complete") {
    return "passed";
  }
  return "not_checked";
}

function scanOutcomeSummary(scan: ScanRow): ScanOutcomeSummary {
  const results = Array.isArray(scan.check_results) ? scan.check_results : [];
  const hasStoredCounts = scan.checks_errored != null || scan.checks_skipped != null;
  const detailed = results.length > 0 || hasStoredCounts;
  const fromResults: Record<CheckOutcome, number> = {
    passed: 0,
    finding: 0,
    not_checked: 0,
    error: 0,
  };

  for (const result of results) fromResults[checkOutcome(result)] += 1;

  if (!detailed) {
    return {
      ...fromResults,
      detailed: false,
      total: numberOrNull(scan.checks_total) ?? 0,
      completed: 0,
    };
  }

  // The recorded outcomes are authoritative when present: some checks can
  // report more than one specific finding, so the stored checks_total is not
  // always the right denominator for check-level coverage.
  const total = results.length || (numberOrNull(scan.checks_total) ?? 0);
  const passed = results.length
    ? fromResults.passed
    : (numberOrNull(scan.checks_passed) ?? 0);
  const error = results.length
    ? fromResults.error
    : (numberOrNull(scan.checks_errored) ?? 0);
  const notChecked = results.length
    ? fromResults.not_checked
    : (numberOrNull(scan.checks_skipped) ?? 0);
  const finding = results.length
    ? fromResults.finding
    : Math.max(0, total - passed - error - notChecked);

  return {
    passed,
    finding,
    not_checked: notChecked,
    error,
    detailed: true,
    total,
    completed: passed + finding,
  };
}

function scanState(scan: ScanRow, summary = scanOutcomeSummary(scan)) {
  if (scan.status === "failed") return { label: "Failed", tone: "critical" };
  if (scan.status === "running") return { label: "Running", tone: "medium" };
  if (scan.status === "partial" || (summary.detailed && (summary.error || summary.not_checked))) {
    return { label: "Partial", tone: "medium" };
  }
  return { label: "Complete", tone: "healthy" };
}

function Overview({
  go,
  openModal,
  sites,
  findings,
  scanCount,
}: {
  go: (p: Page) => void;
  openModal: () => void;
  sites: SiteRow[];
  findings: FindingRow[];
  scanCount: number;
}) {
  const openFindings = findings.filter((f) => f.status === "open");
  const critical = openFindings.filter((f) => f.severity === "critical").length;
  const high = openFindings.filter((f) => f.severity === "high").length;
  const medium = openFindings.filter((f) => f.severity === "medium").length;
  const low = openFindings.filter((f) => f.severity === "low").length;
  const info = openFindings.filter((f) => f.severity === "info").length;
  const activeSites = sites.filter((site) => site.status === "verified").length;
  const pausedSites = sites.filter((site) => site.status === "paused").length;
  const pendingSites = sites.filter((site) => site.status === "pending").length;
  const priorityFindings = [...openFindings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime(),
  );
  const isSetupRequired = sites.length === 0 || pendingSites > 0;
  const isAllPaused = activeSites === 0 && pausedSites > 0;
  const briefingState =
    openFindings.length > 0 ? "has-findings" :
    isSetupRequired ? "needs-setup" :
    isAllPaused ? "is-paused" : "is-clear";
  const briefingTone =
    openFindings.length > 0
      ? critical > 0 ? "critical" : high > 0 ? "high" : "medium"
      : isSetupRequired ? "medium" : isAllPaused ? "low" : "healthy";

  const buckets = Array.from({ length: 10 }, () => ({ d: 0, r: 0 }));
  for (const f of findings) {
    const daysAgo = (Date.now() - new Date(f.last_seen_at).getTime()) / 86_400_000;
    if (daysAgo < 0 || daysAgo > 30) continue;
    const idx = 9 - Math.min(9, Math.floor(daysAgo / 3));
    if (f.status === "resolved") buckets[idx].r += 1;
    else buckets[idx].d += 1;
  }
  const peak = Math.max(1, ...buckets.map((b) => b.d + b.r));

  // Dynamic chart date labels
  const now = new Date();
  const chartDateFmt = (daysBack: number) => {
    const d = new Date(now);
    d.setDate(d.getDate() - daysBack);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  // Dynamic y-axis ticks based on peak
  const yTop = Math.max(4, Math.ceil(peak / 2) * 2);
  const yMid = Math.round(yTop / 2);

  return (
    <>
      <PageTitle
        title="Overview"
        subtitle="A quieter way to keep your code safe."
      />
      <section className={`briefing card ${briefingState}`}>
        <div className="eyebrow-row">
          <span className="briefing-kicker">
            <Dot tone={briefingTone} />
            {openFindings.length > 0 ? "ACTION REQUIRED" : isSetupRequired ? "SETUP REQUIRED" : isAllPaused ? "MONITORING PAUSED" : "SECURITY STATUS"}
          </span>
          <code>
            {new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" })} ·{" "}
            {new Date().toUTCString().slice(17, 22)} UTC
          </code>
        </div>
        <div className="briefing-main">
          <div className="briefing-copy">
            <h2>
              {openFindings.length === 0
                ? "Nothing needs attention"
                : `${openFindings.length} thing${openFindings.length === 1 ? "" : "s"} need attention`}
            </h2>
            <p className="briefing-summary">
              {openFindings.length > 0
                ? `${critical} critical · ${high} high · ${medium} medium · ${low} low${info > 0 ? ` · ${info} info` : ""} across your monitored sites. Start with the highest severity.`
                : sites.length === 0
                  ? "Connect your first site to begin continuous security checks."
                  : activeSites === 0 && pausedSites > 0
                    ? "Your connected sites are paused. Resume monitoring whenever you are ready."
                    : pendingSites > 0
                      ? "Verify your pending site to start monitoring it."
                      : "Your monitored sites are clear at the latest check. Bulwark keeps watching."}
            </p>
          </div>
          {openFindings.length > 0 ? (
            <Button dark onClick={() => go("Threats")}>Review threats</Button>
          ) : sites.length === 0 ? (
            <Button dark onClick={openModal}>+ Add site</Button>
          ) : pendingSites > 0 || activeSites === 0 ? (
            <Button onClick={() => go("Sites")}>{pendingSites > 0 ? "Verify site" : "Manage sites"}</Button>
          ) : null}
        </div>
        {openFindings.length > 0 && (
          <>
            <div className="attention-caption">Highest-priority findings</div>
            <div className="attention-grid">
            {priorityFindings.slice(0, 3).map((f) => (
              <div className="attention" key={f.id}>
                <div>
                  <span className="severity">
                    <Dot tone={f.severity} />
                    {f.severity}
                  </span>
                  <strong title={f.title}>{f.title}</strong>
                  <code title={sites.find((s) => s.id === f.site_id)?.domain ?? ""}>
                    {sites.find((s) => s.id === f.site_id)?.domain ?? ""}
                  </code>
                </div>
              </div>
            ))}
            </div>
          </>
        )}
      </section>
      <section className="stats" aria-label="Workspace metrics">
        <Stat
          label="Connected sites"
          value={String(sites.length)}
          note={sites.length === 0 ? "No sites connected yet" : `${activeSites} active · ${pausedSites} paused · ${pendingSites} awaiting setup`}
        />
        <Stat
          label="Open threats"
          value={String(openFindings.length)}
          note={`${critical} critical · ${high} high · ${medium} medium · ${low} low${info > 0 ? ` · ${info} info` : ""}`}
        />
        <Stat label="Scans completed" value={scanCount.toLocaleString()} note="Across all your sites" />
        <Stat
          label="Active monitors"
          value={String(activeSites)}
          note={activeSites > 0 ? "Verified sites currently scanning" : pausedSites > 0 ? "All verified sites are paused" : "Verify a site to start monitoring"}
        />
      </section>
      <section className="overview-grid">
        <div className="card chart-card">
          <div className="card-heading">
            <h3>Threat activity</h3>
            <span className="chart-range" aria-label="Threat activity for the last 30 days">Last 30 days</span>
          </div>
          <div className="chart-count">
            <strong>{findings.length}</strong>
            <span>tracked</span>
            <div className="legend">
              <i /> Detected <i /> Resolved
            </div>
          </div>
          <div className="chart">
            <div className="grid-line l1" />
            <div className="grid-line l2" />
            <div className="grid-line l3" />
            <div className="y-axis">
              <span>{yTop}</span>
              <span>{yMid}</span>
              <span>0</span>
            </div>
            <div className="bars">
              {buckets.map((b, i) => (
                <span className="bar-slot" key={i}>
                  <i className="detected" style={{ height: `${(b.d / peak) * 54}px` }} />
                  <i className="resolved" style={{ height: `${(b.r / peak) * 54}px` }} />
                </span>
              ))}
            </div>
            <span>{chartDateFmt(27)}</span>
            <span>{chartDateFmt(14)}</span>
            <span>{chartDateFmt(0)}</span>
          </div>
        </div>
        <div className="card feed">
          <div className="card-heading">
            <h3>Live threat feed</h3>
            <span>
              <Dot /> Live
            </span>
          </div>
          {priorityFindings.slice(0, 3).map((f) => (
            <div className="feed-row" key={f.id}>
              <span>
                <Dot tone={f.severity} />
                {f.severity}
              </span>
              <div>
                <strong title={f.title}>{f.title}</strong>
                <code>
                  {sites.find((s) => s.id === f.site_id)?.domain ?? ""} · {relTime(f.last_seen_at)}
                </code>
              </div>
            </div>
          ))}
          {priorityFindings.length === 0 && <p className="feed-empty">No open threats. New findings will appear here.</p>}
        </div>
      </section>
      {sites.length > 0 && (
      <section className="card sites-health">
        <div className="card-heading">
          <h3>Sites health</h3>
          <button onClick={() => go("Sites")}>View all sites →</button>
        </div>
        <div className="table">
          <div className="tr th">
            <span>Domain</span>
            <span>Health</span>
            <span>Last scan</span>
            <span>Open threats</span>
            <span>Autonomy</span>
          </div>
          {sites.map((s) => {
            const health = siteHealth(s, findings);
            return (
              <div className="tr" key={s.id}>
                <code className="table-domain" title={s.domain}>{s.domain}</code>
                <span>
                  <Dot tone={health.tone} />
                  {health.label}
                </span>
                <code>{relTime(s.last_scan_at)}</code>
                <span>{findings.filter((f) => f.site_id === s.id && f.status === "open").length}</span>
                <span>{s.autonomy === "auto_fix" ? "Auto-fix" : "Suggest only"}</span>
              </div>
            );
          })}
        </div>
      </section>
      )}
    </>
  );
}

function Sites({
  openModal,
  onVerify,
  sites,
  findings,
  onScan,
  onChanged,
}: {
  openModal: () => void;
  onVerify: (site: SiteRow) => void;
  sites: SiteRow[];
  findings: FindingRow[];
  onScan: (id: string) => void;
  onChanged: () => void;
}) {
  const [search, setSearch] = useState("");
  const [healthFilter, setHealthFilter] = useState("all");
  const [autonomyFilter, setAutonomyFilter] = useState("all");
  const [busy, setBusy] = useState<string | null>(null);
  const filtered = sites.filter((site) => {
    const matchesSearch = site.domain.includes(search.trim().toLowerCase());
    const openFindings = findings.filter((finding) => finding.site_id === site.id && finding.status === "open");
    const healthKey =
      site.status === "pending"
        ? "pending"
        : site.status === "paused"
          ? "paused"
          : openFindings.some((finding) => finding.severity === "critical" || finding.severity === "high")
            ? "at-risk"
            : openFindings.length > 0
              ? "attention"
              : "healthy";
    const matchesHealth = healthFilter === "all" || healthKey === healthFilter;
    const matchesAutonomy = autonomyFilter === "all" || site.autonomy === autonomyFilter;
    return matchesSearch && matchesHealth && matchesAutonomy;
  });

  const act = async (id: string, fn: () => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn();
      onChanged();
    } catch (err) {
      window.alert((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const remove = (site: SiteRow) => {
    if (!window.confirm(`Delete ${site.domain}? Its scan history and findings are removed too.`)) {
      return;
    }
    void act(site.id, () => deleteSite(site.id));
  };

  return (
    <>
      <PageTitle
        title="Sites"
        subtitle="Your projects, protected around the clock."
        action={
          sites.length > 0 ? (
            <Button dark onClick={openModal}>+ Add site</Button>
          ) : undefined
        }
      />
      {sites.length === 0 ? (
        <div className="card empty-state sites-empty-state">
          <div className="empty-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <h2>Protect your first site</h2>
          <p>Add a domain you control, verify ownership with a DNS record or meta tag, and Bulwark will begin monitoring it.</p>
          <Button dark onClick={openModal}>+ Add your first site</Button>
          <span className="empty-state-note">Only domains you own or are authorized to manage can be monitored.</span>
        </div>
      ) : (
        <>
          <div className="filters">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search domains..."
              aria-label="Search domains"
            />
            <select className="filter-select" value={healthFilter} onChange={(e) => setHealthFilter(e.target.value)} aria-label="Filter sites by health">
              <option value="all">Health: all</option>
              <option value="healthy">Healthy</option>
              <option value="attention">Needs attention</option>
              <option value="at-risk">At risk</option>
              <option value="pending">Awaiting verification</option>
              <option value="paused">Paused</option>
            </select>
            <select className="filter-select" value={autonomyFilter} onChange={(e) => setAutonomyFilter(e.target.value)} aria-label="Filter sites by autonomy">
              <option value="all">Autonomy: all</option>
              <option value="suggest">Suggest only</option>
              <option value="auto_fix">Auto-fix</option>
            </select>
            <span>
              {sites.length} site{sites.length === 1 ? "" : "s"} ·{" "}
              {findings.filter((f) => f.status === "open").length} open threat
              {findings.filter((f) => f.status === "open").length === 1 ? "" : "s"}
            </span>
          </div>
          <div className="card data-table sites-table">
            <div className="site-row table-head">
              <span>Domain</span>
              <span>Health</span>
              <span>Last scan</span>
              <span>Threats</span>
              <span>Autonomy</span>
              <span>Actions</span>
            </div>
            {filtered.map((s) => {
              const health = siteHealth(s, findings);
              return (
                <div className="site-row" key={s.id}>
                  <code className="table-domain" title={s.domain}>{s.domain}</code>
                  <span>
                    <Dot tone={health.tone} />
                    {health.label}
                  </span>
                  <code>{relTime(s.last_scan_at)}</code>
                  <span>{findings.filter((f) => f.site_id === s.id && f.status === "open").length}</span>
                  <span className="tag">{s.autonomy === "auto_fix" ? "Auto-fix" : "Suggest only"}</span>
                  <span className="site-actions">
                    {s.status === "verified" && (
                      <button disabled={busy === s.id} onClick={() => onScan(s.id)}>
                        {busy === s.id ? "Working…" : "Scan"}
                      </button>
                    )}
                    {s.status === "verified" && (
                      <button disabled={busy === s.id} onClick={() => act(s.id, () => setSiteStatus(s.id, "pause"))}>
                        Pause
                      </button>
                    )}
                    {s.status === "paused" && (
                      <button disabled={busy === s.id} onClick={() => act(s.id, () => setSiteStatus(s.id, "resume"))}>
                        Resume
                      </button>
                    )}
                    {s.status === "pending" && (
                      <button disabled={busy === s.id} onClick={() => onVerify(s)}>
                        Verify
                      </button>
                    )}
                    <button className="danger" disabled={busy === s.id} onClick={() => remove(s)}>
                      Delete
                    </button>
                  </span>
                </div>
              );
            })}
            {filtered.length === 0 && (
              <div className="site-row empty-row">
                <span>No sites match these filters. Adjust the search or clear a filter.</span>
              </div>
            )}
            <div className="table-footer">
              <span>{sites.length} of {PLAN_SITE_LIMIT} site slots used</span>
              <span>{filtered.length} shown</span>
            </div>
          </div>
          <section className="card activity">
            <h3>Latest scans</h3>
            {sites.map((s) => (
              <div key={s.id}>
                <code>{relTime(s.last_scan_at)}</code>
                <span>
                  <strong title={s.domain}>{s.domain}</strong>
                  <code>
                    {s.status === "verified"
                      ? `${intervalLabel(s.scan_interval_minutes)} · next ${relTime(s.next_scan_at)}`
                      : s.status === "paused"
                        ? "paused"
                        : "awaiting verification"}
                  </code>
                </span>
              </div>
            ))}
          </section>
        </>
      )}
      <p className="page-note">
        Monitoring runs independently of your AI provider. Explanations use your connected key.
      </p>
    </>
  );
}

function Threats({
  onOpen,
  findings,
  sites,
}: {
  onOpen: (finding: FindingRow) => void;
  findings: FindingRow[];
  sites: SiteRow[];
}) {
  const [tab, setTab] = useState("All threats");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [siteFilter, setSiteFilter] = useState("all");

  const counts = {
    "All threats": findings.length,
    Open: findings.filter((f) => f.status === "open").length,
    Acknowledged: findings.filter((f) => f.status === "acknowledged").length,
    Resolved: findings.filter((f) => f.status === "resolved").length,
    Ignored: findings.filter((f) => f.status === "ignored").length,
  };

  const filtered = useMemo(
    () =>
      findings.filter((f) => {
        if (tab === "Open" && f.status !== "open") return false;
        if (tab === "Acknowledged" && f.status !== "acknowledged") return false;
        if (tab === "Resolved" && f.status !== "resolved") return false;
        if (tab === "Ignored" && f.status !== "ignored") return false;
        if (severity !== "all" && f.severity !== severity) return false;
        if (siteFilter !== "all" && f.site_id !== siteFilter) return false;
        const site = sites.find((s) => s.id === f.site_id)?.domain ?? "";
        const haystack = `${f.title} ${f.check_key} ${site}`.toLowerCase();
        return haystack.includes(query.toLowerCase());
      }),
    [findings, sites, tab, severity, siteFilter, query],
  );

  const exportCsv = () => {
    downloadCsv(
      `bulwark-threats-${new Date().toISOString().slice(0, 10)}.csv`,
      ["Title", "Site", "Severity", "Status", "Check", "First seen", "Last seen", "URL", "Evidence"],
      filtered.map((f) => [
        f.title,
        sites.find((s) => s.id === f.site_id)?.domain ?? "",
        f.severity,
        f.status,
        f.check_key,
        f.first_seen_at,
        f.last_seen_at,
        f.url ?? "",
        f.evidence ?? "",
      ]),
    );
  };

  return (
    <>
      <PageTitle
        title="Threats"
        subtitle="Know what matters. Understand what to do next."
        action={<Button onClick={exportCsv} download>Export CSV</Button>}
      />
      <div className="tabs">
        {(["All threats", "Open", "Acknowledged", "Resolved", "Ignored"] as const).map((label) => (
          <button
            className={tab === label ? "selected" : ""}
            key={label}
            onClick={() => setTab(label)}
          >
            {label} <small>{counts[label]}</small>
          </button>
        ))}
      </div>
      <div className="filters threat-filters">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search threats..."
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="all">Severity: all</option>
          {SEVERITY_ORDER.map((s) => (
            <option value={s} key={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <select value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)} aria-label="Site">
          <option value="all">Site: all</option>
          {sites.map((s) => (
            <option value={s.id} key={s.id}>
              {s.domain}
            </option>
          ))}
        </select>
        <span className="date-filter">{filtered.length} shown</span>
      </div>
      <div className="card data-table threat-table">
        <div className="threat-row table-head">
          <span>Threat</span>
          <span>Site</span>
          <span>Severity</span>
          <span>Status</span>
          <span>Detected</span>
          <span />
        </div>
        {filtered.map((f) => (
          <button className="threat-row" key={f.id} onClick={() => onOpen(f)}>
            <strong className="table-title" title={f.title}>{f.title}</strong>
            <code className="table-domain" title={sites.find((s) => s.id === f.site_id)?.domain ?? "—"}>{sites.find((s) => s.id === f.site_id)?.domain ?? "—"}</code>
            <span>
              <Dot tone={f.severity} />
              {f.severity}
            </span>
            <span className={`tag status-tag status-${f.status}`}>{f.status}</span>
            <code>{relTime(f.last_seen_at)}</code>
            <span>View threat →</span>
          </button>
        ))}
        {filtered.length === 0 && (
          <div className="threat-row empty-row">
            <span>No threats found. That is a good sign.</span>
          </div>
        )}
        <div className="table-footer">
          <span>{filtered.length} results</span>
          <span>Live from your latest scans</span>
        </div>
      </div>
      {counts.Open > 0 && (
        <div className="card priority">
          <div>
            <h2>Start with the highest severity.</h2>
            <p>
              Each finding includes a plain-English explanation you can generate with your own AI
              key, plus the exact evidence Bulwark saw.
            </p>
            <small>ORDERED BY SEVERITY · THEN MOST RECENT</small>
          </div>
          <Button
            dark
            onClick={() => {
              const worst = findings
                .filter((f) => f.status === "open")
                .sort(
                  (a, b) =>
                    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
                )[0];
              if (worst) onOpen(worst);
            }}
          >
            Review highest-priority threat →
          </Button>
        </div>
      )}
    </>
  );
}

function ThreatDetail({
  finding,
  site,
  back,
  onStatus,
  onRefresh,
}: {
  finding: FindingRow;
  site?: SiteRow;
  back: () => void;
  onStatus: (status: FindingStatus) => Promise<void>;
  onRefresh: () => void;
}) {
  const [explanation, setExplanation] = useState(finding.explanation ?? "");
  const [model, setModel] = useState(finding.explanation_model ?? "");
  const [cached, setCached] = useState(Boolean(finding.explanation));
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setExplanation(finding.explanation ?? "");
    setModel(finding.explanation_model ?? "");
    setCached(Boolean(finding.explanation));
    setError(null);
  }, [finding.id, finding.explanation, finding.explanation_model]);

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const explain = (refresh = false) =>
    run("explain", async () => {
      const res = await explainFinding(finding.id, refresh);
      setExplanation(res.explanation);
      setModel(res.model);
      setCached(res.cached);
      onRefresh();
    });

  return (
    <div className="detail-layout">
      <div className="threat-detail">
        <button className="back" onClick={back}>
          ← All threats
        </button>
        <h1>{finding.title}</h1>
        <div className="threat-id">
          <code>
            THR-{finding.id.slice(0, 8).toUpperCase()}　/　{site?.domain ?? "unknown site"}
          </code>
        </div>
        <div className="detail-meta">
          <span className="tag">
            <Dot tone={finding.severity} />
            {finding.severity}
          </span>
          <span className="tag">{finding.status}</span>
          <span>
            First seen {shortDate(finding.first_seen_at)} · last seen {relTime(finding.last_seen_at)}
          </span>
        </div>

        <section className="card meaning">
          <small>WHAT BULWARK FOUND</small>
          <h2>{site ? `On ${site.domain}` : "Finding detail"}</h2>
          <p>{finding.detail ?? "No extra detail was recorded for this finding."}</p>
          {finding.url && (
            <p className="detail-url">
              Affected URL:{" "}
              <a href={finding.url} target="_blank" rel="noreferrer">
                {finding.url}
              </a>
            </p>
          )}
        </section>

        {(finding.what_it_does_not_prove || finding.remediation) && (
          <section className="card meaning">
            <small>READ THIS CAREFULLY</small>
            <div className="finding-context">
              {finding.what_it_does_not_prove && (
                <div>
                  <h3>What this does not prove</h3>
                  <p>{finding.what_it_does_not_prove}</p>
                </div>
              )}
              {finding.remediation && (
                <div>
                  <h3>Suggested remediation</h3>
                  <p>{finding.remediation}</p>
                </div>
              )}
            </div>
          </section>
        )}

        {finding.evidence && (
          <CodeCard
            title="Evidence"
            label={finding.check_key}
            code={finding.evidence}
            footer={`Recorded by a scan on ${site?.domain ?? "this site"}`}
          />
        )}

        <section className="card meaning ai-explanation">
          <div className="ai-head">
            <small>WHAT THIS MEANS</small>
            {model && <code>{model}</code>}
          </div>
          {explanation ? (
            <pre className="explanation">{explanation}</pre>
          ) : (
            <p>
              Generate a plain-English explanation of this finding using your own OpenAI or
              Anthropic key. It is cached, so you only pay for it once.
            </p>
          )}
          <div className="ai-actions">
            <Button dark onClick={() => explain(!explanation)}>
              {busy === "explain"
                ? "Thinking…"
                : explanation
                  ? "Regenerate explanation"
                  : "Explain with AI"}
            </Button>
            {cached && <span>Loaded from cache · no tokens spent</span>}
          </div>
        </section>

        <div className="detail-buttons">
          {finding.status !== "acknowledged" && (
            <Button onClick={() => run("ack", () => onStatus("acknowledged"))}>
              {busy === "ack" ? "Saving…" : "Acknowledge"}
            </Button>
          )}
          {finding.status !== "resolved" && (
            <Button dark onClick={() => run("resolve", () => onStatus("resolved"))}>
              {busy === "resolve" ? "Saving…" : "Mark resolved"}
            </Button>
          )}
          {finding.status !== "ignored" && (
            <Button onClick={() => run("ignore", () => onStatus("ignored"))}>
              {busy === "ignore" ? "Saving…" : "Ignore"}
            </Button>
          )}
          {finding.status !== "open" && (
            <Button onClick={() => run("reopen", () => onStatus("open"))}>Reopen</Button>
          )}
          {finding.check_key === "content_replaced" && site && (
            <Button
              onClick={() =>
                run("baseline", async () => {
                  await acceptBaseline(site.id);
                  await onStatus("resolved");
                  onRefresh();
                })
              }
            >
              {busy === "baseline" ? "Capturing…" : "Accept current page as baseline"}
            </Button>
          )}
        </div>
        {error && <p className="modal-error">{error}</p>}
      </div>

      <aside className="copilot-panel">
        <div className="copilot-head">
          <h2>Finding facts</h2>
          <span>{finding.severity}</span>
        </div>
        <small>CONTEXT · THR-{finding.id.slice(0, 8).toUpperCase()}</small>
        <dl className="fact-list">
          <dt>Check</dt>
          <dd>
            <code>{finding.check_key}</code>
          </dd>
          <dt>Site</dt>
          <dd>{site?.domain ?? "—"}</dd>
          <dt>Status</dt>
          <dd>{finding.status}</dd>
          <dt>Confidence</dt>
          <dd>{finding.confidence ?? "—"}</dd>
          {finding.affected_resource && (
            <>
              <dt>Affected</dt>
              <dd>{finding.affected_resource}</dd>
            </>
          )}
          <dt>First seen</dt>
          <dd>{shortDate(finding.first_seen_at)}</dd>
          <dt>Last seen</dt>
          <dd>{shortDate(finding.last_seen_at)}</dd>
          <dt>Evidence</dt>
          <dd>{finding.evidence ?? "—"}</dd>
        </dl>
        <div className="copilot-copy">
          <h3>How to use this</h3>
          <p>
            Fix the issue on your site, then click <strong>Mark resolved</strong>. If the next scan
            still sees it, Bulwark reopens the finding automatically.
          </p>
          <p>
            Explanations are generated by the AI provider you connected under API Keys. Your key
            never leaves the server.
          </p>
        </div>
        <small>AI can make mistakes. Verify before you change production.</small>
      </aside>
    </div>
  );
}

function CodeCard({
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

function ApiKeys({
  openModal,
  keys,
  loading,
  error,
  onRemove,
}: {
  openModal: () => void;
  keys: ApiKeyRow[];
  loading: boolean;
  error: string | null;
  onRemove: (id: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const remove = async (id: string) => {
    if (!window.confirm("Remove this key? Explanations will stop working until you add another.")) return;
    setBusy(id);
    setLocalError(null);
    try {
      await onRemove(id);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <PageTitle
        title="API keys"
        subtitle="Bring your own intelligence. Keep control of your spend."
        action={
          <Button dark onClick={openModal}>
            + Add API key
          </Button>
        }
      />
      <div className="notice card">
        <strong>Encrypted at rest</strong>
        <span>
          Keys are encrypted with AES-256-GCM before they reach the database. The browser only ever
          sees a masked preview.
        </span>
      </div>
      {(error || localError) && <p className="modal-error">{localError ?? error}</p>}
      <div className="api-grid">
        <div>
          <section className="card provider-card">
            <div className="card-heading">
              <h3>Connected providers</h3>
              <span>
                {keys.length} active key{keys.length === 1 ? "" : "s"}
              </span>
            </div>
            {loading ? (
              <p className="muted pad">Loading keys…</p>
            ) : keys.length === 0 ? (
              <div className="key-empty">
                <p>
                  No AI key yet. Add an OpenAI or Anthropic key to unlock plain-English explanations.
                </p>
                <span className="key-empty-hint">Add a key using the button above to unlock explanations.</span>
              </div>
            ) : (
              keys.map((k) => (
                <div className="key-row" key={k.id}>
                  <div className="key-body">
                    <div className="provider-name">
                      <div>
                        <h3>{k.providerLabel}</h3>
                        <p>
                          {k.label ?? "Key"} · {k.model}
                        </p>
                      </div>
                      <span>
                        <Dot />
                        Connected
                      </span>
                    </div>
                    <div className="key-field">
                      <code>{k.preview}</code>
                      <span className="muted">Added {shortDate(k.createdAt)}</span>
                      <span className="muted">Last used {relTime(k.lastUsedAt)}</span>
                    </div>
                  </div>
                  <Button onClick={() => remove(k.id)}>
                    {busy === k.id ? "Removing…" : "Remove"}
                  </Button>
                </div>
              ))
            )}
          </section>
          <section className="card preferences">
            <h3>How Bulwark uses your key</h3>
            <p>Only to explain findings you explicitly ask about. Nothing is generated automatically.</p>
            <hr />
            <div>
              <span>
                <strong>Explanation model</strong>
                <small>Chosen when the key is added</small>
              </span>
              <code>{keys[0]?.model ?? "—"}</code>
            </div>
            <div>
              <span>
                <strong>Cost</strong>
                <small>Billed directly by your provider</small>
              </span>
              <code>$0 markup</code>
            </div>
          </section>
        </div>
        <div>
          <section className="card spend">
            <h3>Spend</h3>
            <small>BILLED BY YOUR PROVIDER</small>
            <strong>$0</strong>
            <span>of markup. You pay your provider directly.</span>
            <div>
              <span>Keys connected</span>
              <code>{keys.length}</code>
            </div>
            <div>
              <span>Explanations</span>
              <code>cached per finding</code>
            </div>
            <small>Regenerating a cached explanation costs nothing.</small>
          </section>
          <section className="card activity api-activity">
            <h3>Provider status</h3>
            {["OpenAI", "Anthropic"].map((name) => {
              const key = keys.find((x) => x.providerLabel === name);
              return (
                <div key={name}>
                  <code>{name}</code>
                  <span>
                    <strong>{key ? "Connected" : "Not connected"}</strong>
                    <code>{key ? key.model : "—"}</code>
                  </span>
                </div>
              );
            })}
          </section>
        </div>
      </div>
    </>
  );
}

function Toggle({
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
      aria-label={disabled ? "Add a Slack webhook to enable alerts" : value ? "Disable" : "Enable"}
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

function Settings({
  settings,
  sites,
  email,
  onSave,
  onChanged,
  goIntegrations,
}: {
  settings: Settings | null;
  sites: SiteRow[];
  email?: string | null;
  onSave: (patch: Partial<Settings>) => Promise<Settings>;
  onChanged: () => void;
  goIntegrations: () => void;
}) {
  const [interval, setIntervalMinutes] = useState(settings?.scanIntervalMinutes ?? 60);
  const [autonomy, setAutonomy] = useState<Settings["autonomy"]>(settings?.autonomy ?? "suggest");
  const [applyAll, setApplyAll] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!settings) return;
    setIntervalMinutes(settings.scanIntervalMinutes);
    setAutonomy(settings.autonomy);
  }, [settings]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await onSave({ scanIntervalMinutes: interval, autonomy });
      if (applyAll && sites.length) {
        await Promise.all(sites.map((s) => setSiteInterval(s.id, interval)));
        onChanged();
      }
      setMessage("Saved. New scans pick this up on the next cycle.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageTitle
        title="Settings"
        subtitle="Set boundaries. Let Bulwark handle the watching."
        action={
          <Button dark onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </Button>
        }
      />
      <div className="settings-grid">
        <div>
          <section className="card setting-list">
            <div className="setting-title">
              <h3>Monitoring</h3>
              <p>Applies to every site in this workspace unless noted.</p>
            </div>
            <div className="setting-row">
              <span>
                <strong>Scan interval</strong>
                <small>How often Bulwark re-checks each verified site.</small>
              </span>
              <select
                className="inline-select"
                value={interval}
                onChange={(e) => setIntervalMinutes(Number(e.target.value))}
              >
                {INTERVAL_OPTIONS.map((o) => (
                  <option value={o.value} key={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="setting-row">
              <span>
                <strong>Apply to existing sites</strong>
                <small>Update all {sites.length} monitored site(s) now.</small>
              </span>
              <Toggle checked={applyAll} onChange={setApplyAll} />
            </div>
            <div className="setting-row">
              <span>
                <strong>Autonomy</strong>
                <small>Bulwark only makes production changes when Auto-fix is selected. Suggest only keeps every change under your control.</small>
              </span>
              <select
                className="inline-select"
                value={autonomy}
                onChange={(e) => setAutonomy(e.target.value as Settings["autonomy"])}
              >
                <option value="suggest">Suggest only</option>
                <option value="auto_fix">Auto-fix</option>
              </select>
            </div>
            {error && <p className="modal-error" role="alert">{error}</p>}
            {message && <p className="save-note" role="status" aria-live="polite">{message}</p>}
          </section>

          <section className="card setting-list alerts">
            <div className="setting-title">
              <h3>Notifications</h3>
              <p>One Slack message per new finding above your threshold.</p>
            </div>
            <div className="setting-row">
              <span>
                <strong>Slack</strong>
                <code>{settings?.slackWebhookUrl ? "Webhook configured" : "Not configured"}</code>
              </span>
              <button onClick={goIntegrations}>Edit →</button>
              <Toggle checked={Boolean(settings?.slackWebhookUrl && settings?.alertsEnabled)} />
            </div>
            <div className="setting-row">
              <span>
                <strong>Minimum severity</strong>
                <small>Lower severities stay in the app only.</small>
              </span>
              <code>{settings?.slackMinSeverity ?? "high"}</code>
            </div>
            <div className="setting-row">
              <span>
                <strong>Email</strong>
                <small>Email alerts are not available yet.</small>
              </span>
              <span className="tag">Coming later</span>
            </div>
          </section>
        </div>
        <div>
          <section className="card side-setting">
            <h3>Workspace</h3>
            <label>Signed in as</label>
            <code>{email ?? "—"}</code>
            <div>
              <span>Sites monitored</span>
              <code>{sites.length}</code>
            </div>
            <div>
              <span>Plan</span>
              <code>Free · {sites.length} of {PLAN_SITE_LIMIT}</code>
            </div>
            <p>Billing and team seats are not part of this build yet.</p>
          </section>
          <section className="card side-setting">
            <h3>Scan coverage</h3>
            <label>Every scan checks</label>
            <ul className="coverage-list">
              <li>Uptime, HTTP status and TLS expiry</li>
              <li>Security headers, weak CSP, CORS and cookie flags</li>
              <li>Exposed .env, .git, backups and phpinfo</li>
              <li>Leaked API keys in HTML and JS bundles</li>
              <li>Domain expiry, nameservers and mail records</li>
              <li>Defacement, robots.txt, sitemap and security.txt</li>
            </ul>
            <p>{sites.filter((s) => s.status === "verified").length} site(s) actively scanning.</p>
          </section>
        </div>
      </div>
      <div className="settings-foot">
        <span>Changes apply to this workspace only.</span>
        <span>{settings ? `Interval: ${intervalLabel(settings.scanIntervalMinutes)}` : "Loading…"}</span>
      </div>
    </>
  );
}

function Scans({
  scans,
  sites,
  onChanged,
}: {
  scans: ScanRow[];
  sites: SiteRow[];
  onChanged: () => void;
}) {
  const [siteFilter, setSiteFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const filtered = scans.filter((s) => {
    if (siteFilter !== "all" && s.site_id !== siteFilter) return false;
    if (statusFilter !== "all" && s.status !== statusFilter) return false;
    return true;
  });

  const exportCsv = () => {
    downloadCsv(
      `bulwark-scans-${new Date().toISOString().slice(0, 10)}.csv`,
      [
        "Started",
        "Site",
        "Scan state",
        "HTTP",
        "Response ms",
        "Checks total",
        "Passed",
        "Findings",
        "Not checked",
        "Errors",
        "Outcome detail",
        "Scan error",
      ],
      filtered.map((s) => {
        const summary = scanOutcomeSummary(s);
        return [
          s.started_at,
          sites.find((x) => x.id === s.site_id)?.domain ?? "",
          scanState(s, summary).label,
          s.http_status ?? "",
          s.response_ms ?? "",
          summary.detailed ? summary.total : s.checks_total,
          summary.detailed ? summary.passed : "",
          summary.detailed ? summary.finding : "",
          summary.detailed ? summary.not_checked : "",
          summary.detailed ? summary.error : "",
          summary.detailed
            ? `${summary.completed}/${summary.total} checks completed`
            : "Not recorded for this scan",
          s.error ?? "",
        ];
      }),
    );
  };

  return (
    <>
      <PageTitle
        title="Scans"
        subtitle="What each external posture scan completed, observed, or could not check."
        action={<Button onClick={exportCsv} download>Export CSV</Button>}
      />
      <div className="filters">
        <select value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)} aria-label="Site">
          <option value="all">Site: all</option>
          {sites.map((s) => (
            <option value={s.id} key={s.id}>
              {s.domain}
            </option>
          ))}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Status">
          <option value="all">Status: all</option>
          <option value="completed">Completed</option>
          <option value="partial">Partial</option>
          <option value="failed">Failed</option>
        </select>
        <span>
          {filtered.length} scan{filtered.length === 1 ? "" : "s"} shown
        </span>
        <button className="link-button refresh-button" onClick={onChanged}>
          ↻ Refresh
        </button>
      </div>
      <div className="card data-table scans-table">
        <div className="scan-row table-head">
          <span>Started</span>
          <span>Site</span>
          <span>Scan state</span>
          <span>Coverage</span>
          <span>Check outcomes</span>
        </div>
        {filtered.map((s) => {
          const summary = scanOutcomeSummary(s);
          const state = scanState(s, summary);
          const incompleteReason = [
            summary.not_checked ? outcomeText("not_checked", summary.not_checked) : null,
            summary.error ? outcomeText("error", summary.error) : null,
          ]
            .filter(Boolean)
            .join(" · ");

          return (
            <div className="scan-row" key={s.id}>
              <code>{shortDate(s.started_at)}</code>
              <code>{sites.find((x) => x.id === s.site_id)?.domain ?? "—"}</code>
              <span className={`scan-state ${state.tone}`}>
                <Dot tone={state.tone} />
                {state.label}
              </span>
              <span className="scan-coverage">
                {summary.detailed ? (
                  <>
                    <strong>
                      {summary.completed}/{summary.total} checked
                    </strong>
                    {incompleteReason && <small>{incompleteReason}</small>}
                  </>
                ) : (
                  <>
                    <strong>Outcome detail unavailable</strong>
                    <small>This older scan did not record check-level results.</small>
                  </>
                )}
              </span>
              <span
                className={`scan-outcomes ${summary.detailed ? "" : "unavailable"}`}
                aria-label={
                  summary.detailed
                    ? CHECK_OUTCOME_ORDER.map((outcome) => outcomeText(outcome, summary[outcome])).join(", ")
                    : "Check-level outcomes were not recorded for this scan"
                }
              >
                {summary.detailed ? (
                  CHECK_OUTCOME_ORDER.map((outcome) => (
                    <span className={`check-outcome ${outcome}`} key={outcome}>
                      <b>{summary[outcome]}</b> {CHECK_OUTCOME_LABEL[outcome]}
                    </span>
                  ))
                ) : (
                  <span className="check-outcome not_checked">Not recorded</span>
                )}
              </span>
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="scan-row empty-row">
            <span>No scans yet. Verified sites are scanned automatically.</span>
          </div>
        )}
        <div className="table-footer">
          <span>{filtered.length} results</span>
          <span>Newest first</span>
        </div>
      </div>
    </>
  );
}

function escapeHtml(value: unknown) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function printReport({
  sites,
  findings,
  scans,
  rangeLabel,
}: {
  sites: SiteRow[];
  findings: FindingRow[];
  scans: ScanRow[];
  rangeLabel: string;
}) {
  const win = window.open("", "_blank");
  if (!win) {
    window.alert("Allow pop-ups to download the PDF report.");
    return;
  }

  const open = findings.filter((f) => f.status === "open").length;
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const siteName = (id: string) => sites.find((s) => s.id === id)?.domain ?? "—";

  const rows = findings
    .map(
      (f) => `<tr>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(siteName(f.site_id))}</td>
        <td>${escapeHtml(f.severity)}</td>
        <td>${escapeHtml(f.status)}</td>
        <td>${escapeHtml(new Date(f.first_seen_at).toLocaleString())}</td>
      </tr>`,
    )
    .join("");

  win.document.write(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Bulwark security report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: Inter, -apple-system, Segoe UI, sans-serif; color: #171717; margin: 40px; font-size: 12px; }
  h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.5px; }
  .muted { color: #737373; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #ddd; padding-bottom: 16px; margin-bottom: 20px; }
  .stats { display: flex; gap: 28px; margin: 18px 0 24px; }
  .stats div { display: flex; flex-direction: column; gap: 2px; }
  .stats strong { font-size: 20px; }
  .stats span { color: #737373; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #eee; font-size: 10.5px; vertical-align: top; }
  th { color: #737373; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; font-size: 9px; }
  h2 { font-size: 13px; margin: 22px 0 4px; }
  footer { margin-top: 28px; padding-top: 12px; border-top: 1px solid #ddd; color: #737373; font-size: 10px; }
  @media print { body { margin: 18mm; } }
</style>
</head>
<body>
  <div class="head">
    <div>
      <h1>Bulwark security report</h1>
      <div class="muted">${escapeHtml(rangeLabel)} · generated ${escapeHtml(new Date().toLocaleString())}</div>
    </div>
    <strong>bulwark</strong>
  </div>
  <div class="stats">
    <div><span>Sites</span><strong>${sites.length}</strong></div>
    <div><span>Open findings</span><strong>${open}</strong></div>
    <div><span>Critical</span><strong>${critical}</strong></div>
    <div><span>High</span><strong>${high}</strong></div>
    <div><span>Scans</span><strong>${scans.length}</strong></div>
  </div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Finding</th><th>Site</th><th>Severity</th><th>Status</th><th>First seen</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5">No findings in this period.</td></tr>'}</tbody>
  </table>
  <h2>Sites</h2>
  <table>
    <thead><tr><th>Domain</th><th>Status</th><th>Interval</th><th>Last scan</th></tr></thead>
    <tbody>${sites
      .map(
        (s) => `<tr>
          <td>${escapeHtml(s.domain)}</td>
          <td>${escapeHtml(s.status)}</td>
          <td>${escapeHtml(intervalLabel(s.scan_interval_minutes))}</td>
          <td>${escapeHtml(s.last_scan_at ? new Date(s.last_scan_at).toLocaleString() : "never")}</td>
        </tr>`,
      )
      .join("") || '<tr><td colspan="4">No sites.</td></tr>'}</tbody>
  </table>
  <footer>Generated by Bulwark. Findings are based on automated checks and should be reviewed by a human.</footer>
  <script>window.onload = function(){ setTimeout(function(){ window.print(); }, 250); };</script>
</body>
</html>`);
  win.document.close();
}

function Reports({
  sites,
  findings,
  scans,
}: {
  sites: SiteRow[];
  findings: FindingRow[];
  scans: ScanRow[];
}) {
  const [days, setDays] = useState(30);
  const cutoff = Date.now() - days * 86_400_000;
  const inRange = findings.filter((f) => new Date(f.last_seen_at).getTime() >= cutoff);
  const open = inRange.filter((f) => f.status === "open");
  const critical = inRange.filter((f) => f.severity === "critical").length;
  const high = inRange.filter((f) => f.severity === "high").length;
  const rangeLabel = `Last ${days} days`;

  const exportCsv = () => {
    downloadCsv(
      `bulwark-report-${days}d-${new Date().toISOString().slice(0, 10)}.csv`,
      ["Title", "Site", "Severity", "Status", "Check", "First seen", "Last seen", "URL", "Explanation"],
      inRange.map((f) => [
        f.title,
        sites.find((s) => s.id === f.site_id)?.domain ?? "",
        f.severity,
        f.status,
        f.check_key,
        f.first_seen_at,
        f.last_seen_at,
        f.url ?? "",
        f.explanation ?? "",
      ]),
    );
  };

  return (
    <>
      <PageTitle
        title="Reports"
        subtitle="A clean record you can hand to a client or a reviewer."
        action={
          <div className="title-actions">
            <Button onClick={exportCsv} download>Export CSV</Button>
            <Button dark onClick={() => printReport({ sites, findings: inRange, scans, rangeLabel })}>
              Print / Save PDF
            </Button>
          </div>
        }
      />
      <div className="filters">
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Range">
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
        <span>
          {inRange.length} finding{inRange.length === 1 ? "" : "s"} in the selected range
        </span>
      </div>
      <section className="stats">
        <Stat label="Sites in report" value={String(sites.length)} note={`${sites.filter((s) => s.status === "verified").length} actively scanning`} />
        <Stat label="Open findings" value={String(open.length)} note={`${critical} critical · ${high} high`} />
        <Stat label="Scans recorded" value={String(scans.length)} note={`Across ${sites.length} site(s)`} />
        <Stat label="Period" value={`${days}d`} note={rangeLabel} />
      </section>
      <div className="card data-table threat-table report-preview">
        <div className="threat-row table-head">
          <span>Finding</span>
          <span>Site</span>
          <span>Severity</span>
          <span>Status</span>
          <span>First seen</span>
          <span>Explained</span>
        </div>
        {inRange.slice(0, 25).map((f) => (
          <div className="threat-row" key={f.id}>
            <strong>{f.title}</strong>
            <code>{sites.find((s) => s.id === f.site_id)?.domain ?? "—"}</code>
            <span>
              <Dot tone={f.severity} />
              {f.severity}
            </span>
            <span className={`tag status-tag status-${f.status}`}>{f.status}</span>
            <code>{shortDate(f.first_seen_at)}</code>
            <span>{f.explanation ? "Yes" : "—"}</span>
          </div>
        ))}
        {inRange.length === 0 && (
          <div className="threat-row empty-row">
            <span>No findings in this period. Generate a scan to populate the report.</span>
          </div>
        )}
        <div className="table-footer">
          <span>Showing {Math.min(25, inRange.length)} of {inRange.length}</span>
          <span>CSV and PDF include everything in range</span>
        </div>
      </div>
      <p className="page-note">
        The PDF opens a print-ready page in a new tab. Choose “Save as PDF” in the print dialog.
      </p>
    </>
  );
}

function ConnectionsSection({
  connections,
  loading,
  error,
  onAdd,
  onRemove,
  onScan,
  onSetWebhookSecret,
}: {
  connections: ConnectionRow[];
  loading: boolean;
  error: string | null;
  onAdd: (input: Parameters<typeof addConnection>[0]) => Promise<void>;
  onRemove: (id: string, type: ConnectionType) => Promise<void>;
  onScan: (id: string, type: ConnectionType, repo?: { owner: string; repo: string }) => Promise<void>;
  onSetWebhookSecret: (id: string, secret: string) => Promise<void>;
}) {
  const [addType, setAddType] = useState<ConnectionType | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanType, setScanType] = useState<ConnectionType | null>(null);
  const [githubOwner, setGithubOwner] = useState("");
  const [githubRepo, setGithubRepo] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [webhookId, setWebhookId] = useState<string | null>(null);
  const [webhookSecret, setWebhookSecretState] = useState("");
  const [repos, setRepos] = useState<{ full_name: string; owner: string; name: string; private: boolean }[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposConnectionId, setReposConnectionId] = useState<string | null>(null);

  const addConnection = async () => {
    setLocalError(null);
    try {
      if (addType === "github") {
        await onAdd({ type: "github", githubUsername: githubOwner, token: githubRepo });
      } else {
        await onAdd({
          type: "supabase",
          projectRef: githubOwner,
          projectName: githubRepo,
          projectUrl: `https://${githubOwner}.supabase.co`,
          apiKey: githubRepo,
        });
      }
      setAddType(null);
      setGithubOwner("");
      setGithubRepo("");
    } catch (err) {
      setLocalError((err as Error).message);
    }
  };

  const removeConnection = async (id: string, type: ConnectionType) => {
    if (!window.confirm("Remove this connection? Scans using it will stop working.")) return;
    setBusy(id);
    setLocalError(null);
    try {
      await onRemove(id, type);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const scanConnection = async (id: string, type: ConnectionType, repo?: { owner: string; repo: string }) => {
    setBusy(id);
    setLocalError(null);
    try {
      if (type === "github") {
        await onScan(id, type, repo);
      } else {
        await onScan(id, type);
      }
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const setWebhookSecret = async (id: string, secret: string) => {
    setLocalError(null);
    try {
      await onSetWebhookSecret(id, secret);
      setWebhookId(null);
      setWebhookSecretState("");
    } catch (err) {
      setLocalError((err as Error).message);
    }
  };

  const modalStyle = {
    position: "fixed",
    top: 0,
    left: 0,
    width: "100%",
    height: "100%",
    background: "rgba(0,0,0,0.5)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 50,
  } as React.CSSProperties;

  const modalCardStyle = {
    background: "#1a1a1a",
    border: "1px solid #333",
    borderRadius: "8px",
    padding: "24px",
    width: "min(500px, 90vw)",
    maxHeight: "90vh",
    overflow: "auto",
  } as React.CSSProperties;

  return (
    <>
      <section className="card setting-list">
        <div className="setting-title">
          <h3>Connected platforms</h3>
          <p>
            Read-only connections to GitHub and Supabase. Bulwark never writes to your
            repositories or projects.
          </p>
          <button
            className="button dark"
            onClick={() => setAddType("github")}
            disabled={addType !== null || busy !== null}
          >
            + Connect GitHub
          </button>
          <button
            className="button dark"
            onClick={() => setAddType("supabase")}
            disabled={addType !== null || busy !== null}
          >
            + Connect Supabase
          </button>
        </div>
        {(error || localError) && <p className="modal-error">{localError ?? error}</p>}
        {loading ? (
          <p className="muted pad">Loading connections…</p>
        ) : connections.length === 0 ? (
          <div className="key-empty">
            <p>No platform connections yet.</p>
            <span className="key-empty-hint">Connect GitHub or Supabase to scan your repositories and projects.</span>
          </div>
        ) : (
          connections.map((c) => (
            <div className="key-row" key={c.id}>
              <div className="key-body">
                <div className="provider-name">
                  <div>
                    <h3>{c.type === "github" ? "GitHub" : "Supabase"}</h3>
                    <p>
                      {c.label ?? c.type === "github" ? c.githubUsername ?? "GitHub" : c.projectName ?? "Supabase"}{" "}
                      · {c.preview}
                    </p>
                  </div>
                  <span>
                    <Dot />
                    Connected
                  </span>
                </div>
                <div className="key-field">
                  <code>{c.lastCheckedAt ? `Last checked: ${shortDate(c.lastCheckedAt)}` : "Never scanned"}</code>
                  <span className="muted">Added {shortDate(c.createdAt)}</span>
                </div>
              </div>
              <div className="key-actions">
                {c.type === "github" && (
                  <div className="key-field">
                    <span className="muted">Webhook URL:</span><br />
                    <code style={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
                      {`${window.location.origin}/api/webhooks/github`}
                    </code>
                  </div>
                )}
                <button
                  className="button dark"
                  onClick={() => {
                    setReposConnectionId(c.id);
                    setReposLoading(true);
                    apiGet<{ repos: { full_name: string; owner: string; name: string; private: boolean }[] }>(`/api/connections/github/${c.id}/repos`)
                      .then((d) => setRepos(d.repos ?? []))
                      .catch(() => setRepos([]))
                      .finally(() => setReposLoading(false));
                  }}
                  disabled={busy !== null}
                >
                  {busy === c.id ? "Scanning…" : "Scan now"}
                </button>
                {c.type === "github" && (
                  <button
                    className="button"
                    onClick={() => {
                      setWebhookId(c.id);
                      setWebhookSecretState("");
                    }}
                    disabled={busy !== null}
                  >
                    Webhook secret
                  </button>
                )}
                <Button onClick={() => removeConnection(c.id, c.type)}>
                  {busy === c.id ? "Removing…" : "Remove"}
                </Button>
              </div>
            </div>
          ))
        )}
      </section>

      {/* Repos to scan (shown after GitHub connection) */}
      {repos.length > 0 && (
        <section className="card setting-list">
          <div className="setting-title">
            <h3>GitHub repositories to scan</h3>
            <p>Select repositories to scan for secrets, exposed config, and dependencies.</p>
            {reposLoading && <p className="muted pad">Loading repositories…</p>}
          </div>
{repos.map((repo) => (
              <div className="key-row" key={repo.full_name}>
                <div className="key-body">
                  <div className="provider-name">
                    <div>
                      <h3>{repo.name}</h3>
                      <p>{repo.owner}/{repo.name} · {repo.private ? "Private" : "Public"}</p>
                    </div>
                  </div>
                  <div className="key-actions">
                    <button
                      className="button dark"
                      onClick={() => {
                        const [owner, name] = repo.full_name.split("/");
                        void onScan(reposConnectionId!, "github", { owner, repo: name });
                      }}
                      disabled={busy !== null}
                    >
                      Scan
                    </button>
                  </div>
                </div>
              </div>
            ))}
        </section>
      )}

      {addType === "github" && (
        <div style={modalStyle}>
          <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
            <h3>Connect GitHub</h3>
            <p>
              Bulwark will scan your repositories for hardcoded secrets, exposed config files,
              and unpinned dependencies. The token is encrypted at rest and used read-only.
            </p>
            <div className="field-block">
              <label>GitHub username or org</label>
              <input
                autoComplete="off"
                value={githubOwner}
                onChange={(e) => setGithubOwner(e.target.value)}
                placeholder="octocat"
              />
            </div>
            <div className="field-block">
              <label>Personal access token (read-only repo scope)</label>
              <input
                type="password"
                autoComplete="off"
                value={githubRepo}
                onChange={(e) => setGithubRepo(e.target.value)}
                placeholder="ghp_..."
              />
            </div>
            <div className="modal-actions">
              <button className="button" onClick={() => setAddType(null)}>Cancel</button>
              <button className="button dark" onClick={addConnection} disabled={busy !== null}>
                {busy !== null ? "Adding…" : "Connect"}
              </button>
            </div>
          </div>
        </div>
      )}

      {addType === "supabase" && (
        <div style={modalStyle}>
          <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
            <h3>Connect Supabase</h3>
            <p>
              Bulwark will check your storage buckets for public access and verify API
              connectivity. Credentials are encrypted at rest and used read-only.
            </p>
            <div className="field-block">
              <label>Project ref</label>
              <input
                autoComplete="off"
                value={githubOwner}
                onChange={(e) => setGithubOwner(e.target.value)}
                placeholder="abcdefghijklmnop"
              />
            </div>
            <div className="field-block">
              <label>Project name (optional)</label>
              <input
                autoComplete="off"
                value={githubRepo}
                onChange={(e) => setGithubRepo(e.target.value)}
                placeholder="My Project"
              />
            </div>
            <div className="field-block">
              <label>Anon API key</label>
              <input
                type="password"
                autoComplete="off"
                value={githubRepo}
                onChange={(e) => setGithubRepo(e.target.value)}
                placeholder="eyJ..."
              />
            </div>
            <div className="modal-actions">
              <button className="button" onClick={() => setAddType(null)}>Cancel</button>
              <button className="button dark" onClick={addConnection} disabled={busy !== null}>
                {busy !== null ? "Adding…" : "Connect"}
              </button>
            </div>
          </div>
        </div>
      )}

      {scanId && scanType === "supabase" && (
        <div style={modalStyle}>
          <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
            <h3>Scan Supabase</h3>
            <p>
              Scanning will analyze your project for security issues including public
              storage buckets and API connectivity issues.
            </p>
            <div className="modal-actions">
              <button className="button" onClick={() => setScanId(null)}>Cancel</button>
              <button
                className="button dark"
                onClick={() => {
                  void onScan(scanId!, "supabase");
                  setScanId(null);
                  setScanType(null);
                }}
                disabled={busy !== null}
              >
                {busy !== null ? "Scanning…" : "Run scan"}
              </button>
            </div>
          </div>
        </div>
      )}

      {webhookId && (
        <div style={modalStyle}>
          <div style={modalCardStyle} onClick={(e) => e.stopPropagation()}>
            <h3>GitHub Webhook Secret</h3>
            <p>
              Set a secret to validate incoming GitHub webhooks. Go to your repository settings →
              Webhooks → Add webhook, use the URL above, and paste this secret.
            </p>
            <div className="field-block">
              <label>Webhook secret</label>
              <input
                type="password"
                autoComplete="off"
                value={webhookSecret}
                onChange={(e) => setWebhookSecretState(e.target.value)}
                placeholder="Enter a random secret string"
              />
            </div>
            {localError && <p className="modal-error">{localError}</p>}
            <div className="modal-actions">
              <button className="button" onClick={() => setWebhookId(null)}>Cancel</button>
              <button
                className="button dark"
                onClick={() => setWebhookSecret(webhookId!, webhookSecret)}
                disabled={busy !== null || !webhookSecret.trim()}
              >
                {busy !== null ? "Saving…" : "Save secret"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function PlatformFindingsSection({
  findings,
  loading,
  onSetStatus,
}: {
  findings: FindingRow[];
  loading: boolean;
  onSetStatus: (id: string, status: FindingStatus) => Promise<void>;
}) {
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());

  const githubFindings = findings.filter((f) =>
    (f.check_key ?? "").startsWith("secret_") ||
    (f.check_key ?? "").startsWith("dep_") ||
    (f.check_key ?? "").startsWith("exposed_") ||
    (f.check_key ?? "").startsWith("dockerfile_") ||
    (f.check_key ?? "").startsWith("compose_") ||
    (f.check_key ?? "").startsWith("workflow_"),
  );
  const supabaseFindings = findings.filter(
    (f) => !githubFindings.some((g) => g.id === f.id),
  );

  const setStatus = async (id: string, status: FindingStatus) => {
    setBusyIds((prev) => new Set([...prev, id]));
    try {
      await onSetStatus(id, status);
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const renderFinding = (f: FindingRow) => (
    <div className="key-row" key={f.id}>
      <div className="key-body">
        <div className="provider-name">
          <div>
            <h3>{f.title}</h3>
            <p>
              {f.check_key} · {f.severity}{" "}
              <span>
                <Dot tone={f.severity === "critical" || f.severity === "high" ? "critical" : "healthy"} />
                {f.status}
              </span>
            </p>
          </div>
          <div className="key-field">
            <code>{f.evidence ?? "—"}</code>
            <span className="muted">{f.detail ?? ""}</span>
          </div>
        </div>
      </div>
      <div className="key-actions">
        <select
          value={f.status}
          onChange={(e) => setStatus(f.id, e.target.value as FindingStatus)}
          disabled={busyIds.has(f.id)}
          className="status-select"
        >
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="ignored">Ignored</option>
        </select>
        {f.url && (
          <a href={f.url} target="_blank" rel="noopener noreferrer" className="button dark" style={{ fontSize: "0.85rem", padding: "4px 10px" }}>
            View
          </a>
        )}
      </div>
    </div>
  );

  return (
    <>
      <section className="card setting-list">
        <div className="setting-title">
          <h3>Platform findings</h3>
          <p>
            Findings from connected GitHub repositories and Supabase projects.
            These are separate from website scan findings.
          </p>
        </div>
        {loading ? (
          <p className="muted pad">Loading platform findings…</p>
        ) : findings.length === 0 ? (
          <div className="key-empty">
            <p>No platform findings yet.</p>
            <span className="key-empty-hint">Connect and scan a GitHub repo or Supabase project to see findings here.</span>
          </div>
        ) : (
          <>
            {githubFindings.length > 0 && (
              <>
                <div className="setting-title" style={{ marginTop: "1rem" }}>
                  <h3>GitHub</h3>
                  <p>Repository scan findings (secrets, dependencies, configuration).</p>
                </div>
                {githubFindings.map(renderFinding)}
              </>
            )}
            {supabaseFindings.length > 0 && (
              <>
                <div className="setting-title" style={{ marginTop: "1rem" }}>
                  <h3>Supabase</h3>
                  <p>Project scan findings (public storage, RLS coverage).</p>
                </div>
                {supabaseFindings.map(renderFinding)}
              </>
            )}
          </>
        )}
      </section>
    </>
  );
}

function Integrations({
  settings,
  onSave,
  onChanged,
  email,
  connections,
  loading,
  error,
  onAddConnection,
  onRemoveConnection,
  onScanConnection,
  platformFindings,
  platformFindingsLoading,
  onSetPlatformFindingStatus,
  onSetWebhookSecret,
}: {
  settings: Settings | null;
  onSave: (patch: Partial<Settings>) => Promise<Settings>;
  onChanged: () => void;
  email?: string | null;
  connections: ConnectionRow[];
  loading: boolean;
  error: string | null;
  onAddConnection: (input: Parameters<typeof addConnection>[0]) => Promise<void>;
  onRemoveConnection: (id: string, type: ConnectionType) => Promise<void>;
  onScanConnection: (id: string, type: ConnectionType, repo?: { owner: string; repo: string }) => Promise<void>;
  platformFindings: FindingRow[];
  platformFindingsLoading: boolean;
  onSetPlatformFindingStatus: (id: string, status: FindingStatus) => Promise<void>;
  onSetWebhookSecret: (id: string, secret: string) => Promise<void>;
}) {
  const [webhook, setWebhook] = useState(settings?.slackWebhookUrl ?? "");
  const [showWebhook, setShowWebhook] = useState(false);
  const [severity, setSeverity] = useState<Severity>(settings?.slackMinSeverity ?? "high");
  const [enabled, setEnabled] = useState(Boolean(settings?.slackWebhookUrl && settings?.alertsEnabled));
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [slackError, setSlackError] = useState<string | null>(null);

  useEffect(() => {
    if (!settings) return;
    setWebhook(settings.slackWebhookUrl ?? "");
    setSeverity(settings.slackMinSeverity);
    setEnabled(Boolean(settings.slackWebhookUrl && settings.alertsEnabled));
  }, [settings]);

  const save = async (label: string) => {
    setBusy(label);
    setSlackError(null);
    setMessage(null);
    try {
      await onSave({
        slackWebhookUrl: webhook,
        slackMinSeverity: severity,
        alertsEnabled: enabled && Boolean(webhook.trim()),
      });
      onChanged();
      setMessage("Saved.");
    } catch (err) {
      setSlackError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy("test");
    setSlackError(null);
    setMessage(null);
    try {
      if (!webhook.trim()) throw new Error("Add a Slack webhook URL before sending a test message.");
      await apiPost("/api/alerts/test", { webhookUrl: webhook });
      setMessage("Test message sent. Save changes separately to keep this configuration.");
    } catch (err) {
      setSlackError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const configured = Boolean(webhook.trim());

  return (
    <>
      <PageTitle
        title="Integrations"
        subtitle="Send the signal where you already work."
        action={
          <Button dark onClick={() => save("save")} disabled={busy !== null}>
            {busy === "save" ? "Saving…" : "Save changes"}
          </Button>
        }
      />
      <div className="api-grid">
        <div>
          <section className="card setting-list">
            <div className="setting-title">
              <h3>Slack</h3>
              <p>
                Create an incoming webhook in Slack, then paste the URL here. Bulwark posts one
                message per new finding.
              </p>
            </div>
            <div className="field-block">
              <label>Incoming webhook URL</label>
              <div className="webhook-input-row">
                <input
                  type={showWebhook ? "text" : "password"}
                  autoComplete="off"
                  spellCheck={false}
                  value={webhook}
                  onChange={(e) => setWebhook(e.target.value)}
                  placeholder="https://hooks.slack.com/services/T000/B000/xxxx"
                  aria-label="Slack incoming webhook URL"
                />
                <button
                  type="button"
                  className="field-reveal"
                  onClick={() => setShowWebhook((visible) => !visible)}
                  aria-pressed={showWebhook}
                >
                  {showWebhook ? "Hide" : "Show"}
                </button>
              </div>
              <small className="field-help">The webhook is hidden while you are not editing it.</small>
            </div>
            <div className="setting-row">
              <span>
                <strong>Send alerts</strong>
                <small>Off pauses delivery without deleting the webhook.</small>
              </span>
              <Toggle
                checked={enabled && configured}
                onChange={setEnabled}
                disabled={!configured}
                title={configured ? "Enable or pause Slack alert delivery" : "Add a webhook URL before enabling alerts"}
              />
            </div>
            <div className="setting-row">
              <span>
                <strong>Minimum severity</strong>
                <small>Lower severities are still recorded in the app.</small>
              </span>
              <select
                className="inline-select"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
              >
                {SEVERITY_ORDER.map((s) => (
                  <option value={s} key={s}>
                    {s[0].toUpperCase() + s.slice(1)} and above
                  </option>
                ))}
              </select>
            </div>
            <div className="modal-actions">
              <Button onClick={test} disabled={!configured || busy !== null}>{busy === "test" ? "Sending…" : "Send test message"}</Button>
            </div>
            {slackError && <p className="modal-error" role="alert">{slackError}</p>}
            {message && <p className="save-note" role="status" aria-live="polite">{message}</p>}
          </section>
        </div>
        <div>
          <section className="card side-setting">
            <h3>Status</h3>
            <div>
              <span>Slack</span>
              <code>{configured ? "Connected" : "Not configured"}</code>
            </div>
            <div>
              <span>Alerts</span>
              <code>{configured ? (enabled ? "Enabled" : "Paused") : "Waiting for webhook"}</code>
            </div>
            <div>
              <span>Threshold</span>
              <code>{severity}</code>
            </div>
            <p>Workspace: {email ?? "—"}</p>
          </section>
          <section className="card side-setting">
            <h3>What gets sent</h3>
            <pre className="slack-preview">{`:red_circle: *CRITICAL* on *example.com*
> Supabase service_role key exposed
> The service_role key bypasses Row Level Security.
_Open Bulwark for the fix_`}</pre>
            <p>One message per scan that finds something new above your threshold.</p>
          </section>
        </div>
      </div>

      <ConnectionsSection
        connections={connections}
        loading={loading}
        error={error}
        onAdd={onAddConnection}
        onRemove={onRemoveConnection}
        onScan={onScanConnection}
        onSetWebhookSecret={(id, secret) => onSetWebhookSecret(id, secret)}
      />

      <PlatformFindingsSection
        findings={platformFindings}
        loading={platformFindingsLoading}
        onSetStatus={onSetPlatformFindingStatus}
      />
    </>
  );
}

function AiCopilot({
  findings,
  sites,
  keys,
  onOpen,
  onGoKeys,
}: {
  findings: FindingRow[];
  sites: SiteRow[];
  keys: ApiKeyRow[];
  onOpen: (finding: FindingRow) => void;
  onGoKeys: () => void;
}) {
  const explained = findings.filter((f) => f.explanation).length;
  const open = findings.filter((f) => f.status === "open");
  const ready = keys.length > 0;

  return (
    <>
      <PageTitle
        title="AI Copilot"
        subtitle="Plain-English explanations, generated with your own key."
        action={
          <Button dark onClick={onGoKeys}>
            {ready ? "Manage keys" : "Add an API key"}
          </Button>
        }
      />
      <div className="notice card">
        <strong>{ready ? `${keys[0].providerLabel} connected` : "No AI key connected"}</strong>
        <span>
          {ready
            ? `Explanations use ${keys[0].model}. Nothing is generated until you ask for it.`
            : "Add an OpenAI or Anthropic key to explain any finding in one click."}
        </span>
      </div>
      <section className="stats">
        <Stat label="Explained findings" value={String(explained)} note="Cached on each finding" />
        <Stat label="Open findings" value={String(open.length)} note={ready ? "Ready to explain" : "Add a key to explain"} />
        <Stat label="Provider" value={ready ? keys[0].providerLabel : "Not set"} note={ready ? keys[0].model ?? "" : "Connect an API key"} />
        <Stat label="Token markup" value="$0" note="You pay your provider directly" />
      </section>
      <div className="split-content">
        <section className="card setting-list">
          <div className="setting-title">
            <h3>Open findings</h3>
            <p>Pick one to see the evidence and generate an explanation.</p>
          </div>
          {open.slice(0, 8).map((f) => (
            <div className="setting-row" key={f.id}>
              <span>
                <strong>
                  <Dot tone={f.severity} /> {f.title}
                </strong>
                <small>
                  {sites.find((s) => s.id === f.site_id)?.domain ?? "—"} · {f.severity} ·{" "}
                  {f.explanation ? "explained" : "not explained"}
                </small>
              </span>
              <button
                onClick={() => onOpen(f)}
                disabled={!ready && !f.explanation}
                title={!ready && !f.explanation ? "Connect an AI API key to explain this finding." : undefined}
                aria-label={
                  !ready && !f.explanation
                    ? `Connect an AI API key to explain ${f.title}`
                    : f.explanation ? `View explanation for ${f.title}` : `Explain ${f.title}`
                }
              >
                {f.explanation ? "View →" : ready ? "Explain →" : "Add key to explain"}
              </button>
            </div>
          ))}
          {open.length === 0 && <p className="muted pad">No open findings. Nothing to explain.</p>}
        </section>
        <section className="card side-setting">
          <h3>What the copilot does</h3>
          <ul className="coverage-list">
            <li>Explains what a finding means in plain language</li>
            <li>Explains the realistic risk for a small product</li>
            <li>Gives concrete fix steps</li>
            <li>Caches the answer so you never pay twice</li>
          </ul>
          <p>No chat, no code changes, no automatic fixes. Explanations only.</p>
        </section>
      </div>
    </>
  );
}

function GenericPage({ page }: { page: Page }) {
  return (
    <>
      <PageTitle title={page} subtitle={`${page} is not part of this build.`} />
      <div className="card empty-state">
        <div className="empty-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <h2>{page}</h2>
        <p>This section has no implementation yet. Use the sidebar to return to monitoring.</p>
      </div>
    </>
  );
}

function Modal({
  type,
  close,
  onChanged,
  onAddKey,
  initialSite,
}: {
  type: "site" | "key" | "connection";
  close: () => void;
  onChanged: () => void;
  onAddKey?: (input: { provider: string; key: string; label?: string; model?: string }) => Promise<unknown>;
  initialSite?: SiteRow | null;
}) {
  const [step, setStep] = useState<"form" | "verify" | "done">(initialSite ? "verify" : "form");
  const [domain, setDomain] = useState("");
  const [site, setSite] = useState<SiteRow | null>(initialSite ?? null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [provider, setProvider] = useState<keyof typeof KEY_PROVIDERS>("openai");
  const [keyValue, setKeyValue] = useState("");
  const [keyLabel, setKeyLabel] = useState("");
  const [keyModel, setKeyModel] = useState<string>(KEY_PROVIDERS.openai.model);

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setError("Could not access the clipboard. Select the value and copy manually.");
    }
  };

  if (type === "key") {
    const submitKey = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!onAddKey || busy) return;
      setBusy(true);
      setError(null);
      try {
        await onAddKey({
          provider,
          key: keyValue,
          label: keyLabel.trim() || undefined,
          model: keyModel.trim() || undefined,
        });
        onChanged();
        close();
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setBusy(false);
      }
    };

    return (
      <div className="modal-wrap">
        <button className="modal-scrim" onClick={close} aria-label="Close" />
        <div className="modal card">
          <div className="modal-head">
            <div>
              <h2>Add an API key</h2>
              <p>Keys are encrypted server-side and never returned to the browser.</p>
            </div>
            <button className="modal-close" onClick={close} aria-label="Close">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/></svg>
            </button>
          </div>
          <form onSubmit={submitKey}>
            <label>Provider</label>
            <select
              value={provider}
              onChange={(e) => {
                const next = e.target.value as keyof typeof KEY_PROVIDERS;
                setProvider(next);
                setKeyModel(KEY_PROVIDERS[next].model);
              }}
            >
              {Object.entries(KEY_PROVIDERS).map(([id, info]) => (
                <option value={id} key={id}>
                  {info.label}
                </option>
              ))}
            </select>
            <label>Secret key</label>
            <input
              type="password"
              value={keyValue}
              onChange={(e) => setKeyValue(e.target.value)}
              placeholder={KEY_PROVIDERS[provider].placeholder}
              autoComplete="off"
              autoFocus
            />
            <label>Label (optional)</label>
            <input
              value={keyLabel}
              onChange={(e) => setKeyLabel(e.target.value)}
              placeholder="Production"
            />
            <label>Model</label>
            <input value={keyModel} onChange={(e) => setKeyModel(e.target.value)} />
            {error && <p className="modal-error">{error}</p>}
            <Button dark>{busy ? "Saving…" : "Save key"}</Button>
            <p className="modal-note">
              Used only for explanations you request. Bulwark cannot read the key back — it can only
              decrypt it on the server to call your provider.
            </p>
          </form>
        </div>
      </div>
    );
  }

  const submitDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createSite(domain);
      setSite(created);
      setStep("verify");
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (!site || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await verifySite(site.id);
      setMethod(res.method);
      setStep("done");
      onChanged();
      scanSiteNow(site.id).then(onChanged).catch(() => undefined);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-wrap">
      <button className="modal-scrim" onClick={close} aria-label="Close" />
      <div className="modal card">
        <div className="modal-head">
          <div>
            <h2>{step === "form" ? "Add a site" : step === "verify" ? "Prove you own it" : "Site connected"}</h2>
            <p>
              {step === "form"
                ? "Connect a domain to begin monitoring."
                : step === "verify"
                  ? "Add one of these records, then verify."
                  : "Bulwark will scan it within a minute."}
            </p>
          </div>
          <button className="modal-close" onClick={close} aria-label="Close">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/></svg>
          </button>
        </div>

        {step === "form" && (
          <form onSubmit={submitDomain}>
            <label>Domain</label>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoFocus
            />
            {error && <p className="modal-error">{error}</p>}
            <Button dark>{busy ? "Adding…" : "Continue"}</Button>
            <p className="modal-note">
              Only add sites you control. Bulwark refuses to scan a domain you have not verified.
            </p>
          </form>
        )}

        {step === "verify" && site && (
          <>
            <p className="modal-note">DNS is the fastest option. Records can take a few minutes.</p>
            <div className="verify-box">
              <small>DNS TXT RECORD</small>
              <div className="code-line">
                <code>_bulwark.{site.domain}</code>
                <button type="button" onClick={() => copy("dns", `_bulwark.${site.domain}`)}>
                  {copied === "dns" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="code-line">
                <code className="token">{site.verify_token}</code>
                <button type="button" onClick={() => copy("token", site.verify_token)}>
                  {copied === "token" ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
            <div className="verify-box">
              <small>OR HTML META TAG — HOMEPAGE &lt;HEAD&gt;</small>
              <div className="code-line">
                <code className="token">{`<meta name="bulwark-verify" content="${site.verify_token}" />`}</code>
                <button
                  type="button"
                  onClick={() =>
                    copy("meta", `<meta name="bulwark-verify" content="${site.verify_token}" />`)
                  }
                >
                  {copied === "meta" ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
            {error && <p className="modal-error">{error}</p>}
            <div className="modal-actions">
              <Button dark onClick={verify}>
                {busy ? "Checking…" : "Verify now"}
              </Button>
              <Button onClick={close}>Later</Button>
            </div>
          </>
        )}

        {step === "done" && (
          <div className="success">
            <Dot />
            <h2>Verified via {method === "dns" ? "DNS TXT" : "meta tag"}</h2>
            <p>Monitoring has started. The first scan is running now.</p>
            <Button dark onClick={close}>
              Done
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const { configured, loading, session } = useAuth();
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return window.localStorage.getItem("bulwark-theme") === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem("bulwark-theme", theme);
    } catch {
      // Theme still works for this session when storage is unavailable.
    }
  }, [theme]);

  useEffect(() => {
    let active = true;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const error = params.get("error");
    const errorDescription = params.get("error_description");

    if (active && !session && code && supabase) {
      void supabase.auth.exchangeCodeForSession(code).then(() => {
        if (active) {
          // Clean up the callback URL from the address bar.
          window.history.replaceState({}, document.title, window.location.pathname);
        }
      });
    }
    if (active && error) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    return () => { active = false; };
  }, []);

  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");
  const shellProps = { theme, onToggleTheme: toggleTheme };

  // Demo mode: no Supabase env configured, keep the original mock UI.
  if (!configured) return <AppShell {...shellProps} />;
  if (loading) return <div className="boot">Loading Bulwark…</div>;
  if (!session) return <AuthScreen />;
  return <AppShell {...shellProps} />;
}

function AppShell({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const { user, signOut } = useAuth();
  const { sites, findings, scans, scanCount, refresh } = useWorkspace();
  const activeSiteCount = sites.filter((site) => site.status === "verified").length;
  const pendingSiteCount = sites.filter((site) => site.status === "pending").length;
  const monitoringState: "active" | "setup" | "paused" =
    activeSiteCount > 0 ? "active" : pendingSiteCount > 0 || sites.length === 0 ? "setup" : "paused";
  const monitoringLabel =
    monitoringState === "active" ? "Monitoring active" :
    monitoringState === "paused" ? "Monitoring paused" : "Setup required";
  const settingsState = useSettings();
  const keysState = useApiKeys();
  const connectionsState = useConnections();
  const [platformFindings, setPlatformFindings] = useState<FindingRow[]>([]);
  const [platformFindingsLoading, setPlatformFindingsLoading] = useState(false);

  const reloadPlatformFindings = useCallback(async () => {
    setPlatformFindingsLoading(true);
    try {
      const data = await listPlatformFindings();
      setPlatformFindings(data);
    } catch {
      setPlatformFindings([]);
    } finally {
      setPlatformFindingsLoading(false);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      setPlatformFindingsLoading(true);
      try {
        const data = await listPlatformFindings();
        if (mounted) setPlatformFindings(data);
      } catch {
        if (mounted) setPlatformFindings([]);
      } finally {
        if (mounted) setPlatformFindingsLoading(false);
      }
    };
    void load();
    return () => { mounted = false; };
  }, []);

  const [page, setPage] = useState<Page>("Overview");
  const [activeFindingId, setActiveFindingId] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [modal, setModal] = useState<"site" | "key" | "connection" | null>(null);
  const [siteToVerify, setSiteToVerify] = useState<SiteRow | null>(null);

  useEffect(() => {
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const activeFinding = findings.find((f) => f.id === activeFindingId) ?? null;
  const activeSite = sites.find((s) => s.id === activeFinding?.site_id);

  const onScan = (id: string) => {
    scanSiteNow(id)
      .then(() => refresh())
      .catch((err: Error) => window.alert(err.message));
  };

  const changeFindingStatus = async (status: FindingStatus) => {
    if (!activeFindingId) return;
    await setFindingStatus(activeFindingId, status);
    await refresh();
  };

  const go = (next: Page) => {
    setPage(next);
    setActiveFindingId(null);
  };

  const openSiteModal = (site?: SiteRow) => {
    setSiteToVerify(site ?? null);
    setModal("site");
  };

  const closeModal = () => {
    setModal(null);
    setSiteToVerify(null);
  };

  const content = activeFinding ? (
    <ThreatDetail
      finding={activeFinding}
      site={activeSite}
      back={() => setActiveFindingId(null)}
      onStatus={changeFindingStatus}
      onRefresh={refresh}
    />
  ) : page === "Overview" ? (
    <Overview
      go={(p) => go(p)}
      openModal={() => openSiteModal()}
      sites={sites}
      findings={findings}
      scanCount={scanCount}
    />
  ) : page === "Sites" ? (
    <Sites
      openModal={() => openSiteModal()}
      onVerify={openSiteModal}
      sites={sites}
      findings={findings}
      onScan={onScan}
      onChanged={refresh}
    />
  ) : page === "Threats" ? (
    <Threats
      onOpen={(f) => setActiveFindingId(f.id)}
      findings={findings}
      sites={sites}
    />
  ) : page === "Scans" ? (
    <Scans scans={scans} sites={sites} onChanged={refresh} />
  ) : page === "Reports" ? (
    <Reports sites={sites} findings={findings} scans={scans} />
  ) : page === "Integrations" ? (
    <Integrations
      settings={settingsState.settings}
      onSave={settingsState.save}
      onChanged={() => {
        void refresh();
        void settingsState.reload();
      }}
      email={user?.email}
      connections={connectionsState.connections}
      loading={connectionsState.loading}
      error={connectionsState.error}
      onAddConnection={(input) => connectionsState.add(input).then(() => {})}
      onRemoveConnection={connectionsState.remove}
      onScanConnection={(id, type, repo) => connectionsState.scan(id, type, repo).then(() => {})}
      platformFindings={platformFindings}
      platformFindingsLoading={platformFindingsLoading}
      onSetPlatformFindingStatus={(id, status) => setFindingStatus(id, status).then(() => void reloadPlatformFindings())}
      onSetWebhookSecret={(id, secret) => setWebhookSecret(id, secret)}
    />
  ) : page === "AI Copilot" ? (
    <AiCopilot
      findings={findings}
      sites={sites}
      keys={keysState.keys}
      onOpen={(f) => {
        setPage("Threats");
        setActiveFindingId(f.id);
      }}
      onGoKeys={() => go("API Keys")}
    />
  ) : page === "API Keys" ? (
    <ApiKeys
      openModal={() => setModal("key")}
      keys={keysState.keys}
      loading={keysState.loading}
      error={keysState.error}
      onRemove={keysState.remove}
    />
  ) : page === "Settings" ? (
    <Settings
      settings={settingsState.settings}
      sites={sites}
      email={user?.email}
      onSave={settingsState.save}
      onChanged={refresh}
      goIntegrations={() => go("Integrations")}
    />
  ) : (
    <GenericPage page={page} />
  );

  return (
    <div className="app-shell">
      <Sidebar
        page={page}
        setPage={go}
        open={mobileNav}
        close={() => setMobileNav(false)}
        threatCount={findings.filter((f) => f.status === "open").length}
        siteCount={sites.length}
      />
      <div className="main-shell">
        <Header
          page={activeFinding ? "Threats" : page}
          onMenu={() => setMobileNav(true)}
          email={user?.email}
          onSignOut={signOut}
          onGoKeys={() => go("API Keys")}
          monitoringState={monitoringState}
          monitoringLabel={monitoringLabel}
          onGoSites={() => go("Sites")}
          theme={theme}
          onToggleTheme={onToggleTheme}
        />
        <main className={activeFinding ? "detail-main" : ""}>{content}</main>
      </div>
      {modal && (
        <Modal
          type={modal}
          close={closeModal}
          onChanged={() => {
            void refresh();
            void keysState.reload();
          }}
          onAddKey={keysState.add}
          initialSite={modal === "site" ? siteToVerify : null}
        />
      )}
    </div>
  );
}
