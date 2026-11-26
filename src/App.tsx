import { Suspense, lazy, useCallback, useEffect, useState } from "react";
import { GenericPage, Header, Sidebar, type Theme } from "@/components/Shell";
import { Button } from "@/components/Ui";
import { useAuth } from "@/lib/auth";
import { buildPath, parseLocation, type IntegrationTab, type Page } from "@/lib/router";
import { supabase } from "@/lib/supabase";
import {
  listPlatformFindings,
  scanSiteNow,
  setFindingStatus,
  setWebhookSecret,
  useApiKeys,
  useConnections,
  useSettings,
  useWorkspace,
  type FindingRow,
  type FindingStatus,
  type SiteRow,
} from "@/lib/workspace";

const Modal = lazy(() => import("@/components/Modal").then((m) => ({ default: m.Modal })));
const AiCopilot = lazy(() => import("@/pages/AiCopilot").then((m) => ({ default: m.AiCopilot })));
const ApiKeys = lazy(() => import("@/pages/ApiKeys").then((m) => ({ default: m.ApiKeys })));
const Integrations = lazy(() =>
  import("@/pages/Integrations").then((m) => ({ default: m.Integrations })),
);
const Overview = lazy(() => import("@/pages/Overview").then((m) => ({ default: m.Overview })));
const Reports = lazy(() => import("@/pages/Reports").then((m) => ({ default: m.Reports })));
const Scans = lazy(() => import("@/pages/Scans").then((m) => ({ default: m.Scans })));
const Settings = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Settings })));
const Sites = lazy(() => import("@/pages/Sites").then((m) => ({ default: m.Sites })));
const ThreatDetail = lazy(() =>
  import("@/pages/ThreatDetail").then((m) => ({ default: m.ThreatDetail })),
);
const Threats = lazy(() => import("@/pages/Threats").then((m) => ({ default: m.Threats })));
const AuthScreen = lazy(() => import("@/screens/AuthScreen"));

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

    if (active && !session && code && supabase) {
      void supabase.auth.exchangeCodeForSession(code).then(() => {
        if (active) {
          window.history.replaceState({}, document.title, window.location.pathname);
        }
      });
    }
    if (active && error) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    return () => {
      active = false;
    };
  }, []);

  const toggleTheme = () => setTheme((current) => (current === "dark" ? "light" : "dark"));
  const shellProps = { theme, onToggleTheme: toggleTheme };

  // Demo mode: no Supabase env configured, keep the original mock UI.
  if (!configured) return <AppShell {...shellProps} />;
  if (loading) return <div className="boot">Loading Bulwark…</div>;
  if (!session) {
    return (
      <Suspense fallback={<div className="boot">Loading Bulwark…</div>}>
        <AuthScreen />
      </Suspense>
    );
  }
  return <AppShell {...shellProps} />;
}

function AppShell({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const { user, signOut } = useAuth();
  const { sites, findings, scans, scanCount, loading: workspaceLoading, refresh } = useWorkspace();
  const activeSiteCount = sites.filter((site) => site.status === "verified").length;
  const pendingSiteCount = sites.filter((site) => site.status === "pending").length;
  const monitoringState: "active" | "setup" | "paused" =
    activeSiteCount > 0 ? "active" : pendingSiteCount > 0 || sites.length === 0 ? "setup" : "paused";
  const monitoringLabel =
    monitoringState === "active"
      ? "Monitoring active"
      : monitoringState === "paused"
        ? "Monitoring paused"
        : "Setup required";
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
    return () => {
      mounted = false;
    };
  }, []);

  const [route, setRoute] = useState(() =>
    parseLocation(window.location.pathname, window.location.search),
  );
  const [mobileNav, setMobileNav] = useState(false);
  const [modal, setModal] = useState<"site" | "key" | null>(null);
  const [siteToVerify, setSiteToVerify] = useState<SiteRow | null>(null);

  useEffect(() => {
    const onPopState = () => {
      setRoute(parseLocation(window.location.pathname, window.location.search));
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback(
    (
      next: { page: Page; findingId?: string | null; integrationTab?: IntegrationTab },
      { replace = false }: { replace?: boolean } = {},
    ) => {
      const resolved = {
        page: next.page,
        findingId: next.findingId ?? null,
        integrationTab: next.integrationTab ?? "alerts",
      };
      setRoute(resolved);
      const nextUrl = buildPath(resolved);
      const currentUrl = `${window.location.pathname}${window.location.search}`;
      if (currentUrl !== nextUrl) {
        if (replace) window.history.replaceState({}, "", nextUrl);
        else window.history.pushState({}, "", nextUrl);
      }
    },
    [],
  );

  useEffect(() => {
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const page = route.page;
  const activeFindingId = route.findingId;
  const activeFinding =
    (activeFindingId
      ? findings.find((f) => f.id === activeFindingId) ??
        platformFindings.find((f) => f.id === activeFindingId)
      : null) ?? null;
  const activeSite = sites.find((s) => s.id === activeFinding?.site_id);

  const onScan = async (id: string) => {
    await scanSiteNow(id);
    await refresh();
  };

  const changeFindingStatus = async (status: FindingStatus) => {
    if (!activeFindingId) return;
    await setFindingStatus(activeFindingId, status);
    await Promise.all([refresh(), reloadPlatformFindings()]);
  };

  const go = (next: Page, integrationTab?: IntegrationTab) => {
    navigate({ page: next, findingId: null, integrationTab });
  };

  const openFindingById = (id: string) => {
    navigate({ page: "Threats", findingId: id });
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
      back={() => go("Threats")}
      onStatus={changeFindingStatus}
      onRefresh={() => {
        void refresh();
        void reloadPlatformFindings();
      }}
    />
  ) : activeFindingId ? (
    workspaceLoading || platformFindingsLoading ? (
      <div className="card empty-state">
        <h2>Loading finding…</h2>
        <p>Fetching the finding details for this link.</p>
      </div>
    ) : (
      <div className="card empty-state">
        <h2>Finding not found</h2>
        <p>This finding no longer exists or belongs to another workspace.</p>
        <Button dark onClick={() => go("Threats")}>
          ← Back to threats
        </Button>
      </div>
    )
  ) : page === "Overview" ? (
    <Overview
      go={(p, tab) => go(p, tab)}
      openModal={() => openSiteModal()}
      sites={sites}
      connectionCount={connectionsState.connections.length}
      findings={findings}
      scans={scans}
      scanCount={scanCount}
      onOpenFinding={(id) => openFindingById(id)}
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
    <Threats onOpen={(f) => openFindingById(f.id)} findings={findings} sites={sites} />
  ) : page === "Scans" ? (
    <Scans scans={scans} sites={sites} onChanged={refresh} />
  ) : page === "Reports" ? (
    <Reports sites={sites} findings={findings} scans={scans} />
  ) : page === "Integrations" ? (
    <Integrations
      activeTab={route.integrationTab}
      onTabChange={(nextTab) => go("Integrations", nextTab)}
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
      onScanConnection={async (id, type, repo) => {
        const result = await connectionsState.scan(id, type, repo);
        await Promise.all([connectionsState.reload(), reloadPlatformFindings()]);
        return result;
      }}
      onUpdateSupabaseSchedule={async (id, input) => {
        await connectionsState.updateSchedule(id, input);
      }}
      platformFindings={platformFindings}
      platformFindingsLoading={platformFindingsLoading}
      onSetPlatformFindingStatus={(id, status) =>
        setFindingStatus(id, status).then(() => {
          void reloadPlatformFindings();
          void refresh();
        })
      }
      onOpenFinding={(f) => openFindingById(f.id)}
      onSetWebhookSecret={(id, secret) => setWebhookSecret(id, secret)}
    />
  ) : page === "AI Copilot" ? (
    <AiCopilot
      findings={findings}
      sites={sites}
      keys={keysState.keys}
      onOpen={(f) => openFindingById(f.id)}
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
      goIntegrations={() => go("Integrations", "alerts")}
      onAccountDeleted={() => void signOut()}
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
        monitoringState={monitoringState}
        monitoringLabel={monitoringLabel}
      />
      <div className="main-shell">
        <Header
          page={activeFinding ? "Threats" : page}
          onMenu={() => setMobileNav(true)}
          email={user?.email}
          onSignOut={signOut}
          theme={theme}
          onToggleTheme={onToggleTheme}
        />
        <main className={activeFinding ? "detail-main" : ""}>
          <Suspense fallback={<div className="page-loading">Loading view…</div>}>{content}</Suspense>
        </main>
      </div>
      {modal && (
        <Suspense fallback={null}>
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
        </Suspense>
      )}
    </div>
  );
}
