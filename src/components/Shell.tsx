import { useState } from "react";
import type { Page } from "@/lib/router";
import { PLAN_SITE_LIMIT } from "@/lib/workspace";
import { Dot, NavIcon, PageTitle } from "./Ui";

export type Theme = "dark" | "light";

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

export function Header({
  page,
  onMenu,
  email,
  onSignOut,
  theme,
  onToggleTheme,
}: {
  page: Page;
  onMenu: () => void;
  email?: string | null;
  onSignOut?: () => void;
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

export function Sidebar({
  page,
  setPage,
  open,
  close,
  threatCount,
  siteCount,
  monitoringState,
  monitoringLabel,
}: {
  page: Page;
  setPage: (p: Page) => void;
  open: boolean;
  close: () => void;
  threatCount: number;
  siteCount: number;
  monitoringState: "active" | "setup" | "paused";
  monitoringLabel: string;
}) {
  const groups: { label: string; items: Page[] }[] = [
    { label: "Monitor", items: ["Overview", "Sites", "Threats", "Scans"] },
    { label: "Insights", items: ["AI Copilot", "Reports"] },
    { label: "Workspace", items: ["Integrations", "API Keys", "Settings"] },
  ];
  return (
    <>
      {open && <button className="scrim" onClick={close} aria-label="Close navigation" />}
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <img src="/bulwark-icon.svg" alt="" className="brand-logo" />
          <div className="brand-text">
            <span className="brand-name">Bulwark</span>
            <span className="brand-meta" aria-label="Current workspace">
              Indie workspace
            </span>
          </div>
        </div>
        <nav aria-label="Main navigation">
          {groups.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              {group.items.map((item) => (
                <button
                  key={item}
                  type="button"
                  className={page === item ? "active" : ""}
                  aria-current={page === item ? "page" : undefined}
                  onClick={() => {
                    setPage(item);
                    close();
                  }}
                >
                  <span className="nav-label">
                    {NAV_ICONS[item] && <NavIcon path={NAV_ICONS[item]} />}
                    {item}
                  </span>
                  {item === "Threats" && threatCount > 0 && (
                    <span className="nav-badge">{threatCount}</span>
                  )}
                </button>
              ))}
            </div>
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
          <span className={`monitor-line ${monitoringState}`}>
            <Dot
              tone={
                monitoringState === "active"
                  ? "healthy"
                  : monitoringState === "setup"
                    ? "medium"
                    : "low"
              }
            />
            {monitoringLabel}
          </span>
          <a href="https://docs.bulwarksecure.app" target="_blank" rel="noreferrer">Documentation ↗</a>
        </div>
      </aside>
    </>
  );
}

export function GenericPage({ page }: { page: Page }) {
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
