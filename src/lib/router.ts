export type Page =
  | "Overview"
  | "Sites"
  | "Threats"
  | "Scans"
  | "AI Copilot"
  | "Reports"
  | "Integrations"
  | "API Keys"
  | "Settings";

export type IntegrationTab = "alerts" | "platforms" | "findings";

export type RouteState = {
  page: Page;
  findingId: string | null;
  integrationTab: IntegrationTab;
};

const PAGE_TO_PATH: Record<Page, string> = {
  Overview: "/",
  Sites: "/sites",
  Threats: "/threats",
  Scans: "/scans",
  "AI Copilot": "/copilot",
  Reports: "/reports",
  Integrations: "/integrations",
  "API Keys": "/api-keys",
  Settings: "/settings",
};

const PATH_TO_PAGE = new Map<string, Page>(
  Object.entries(PAGE_TO_PATH).map(([page, path]) => [path, page as Page]),
);

const VALID_INTEGRATION_TABS = new Set<IntegrationTab>(["alerts", "platforms", "findings"]);

function normalizePathname(pathname: string): string {
  const trimmed = String(pathname || "/").trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.replace(/\/+$/, "") || "/";
}

export function parseLocation(pathname: string, search = ""): RouteState {
  const cleanPath = normalizePathname(pathname);
  const params = new URLSearchParams(search);
  const rawTab = params.get("tab") as IntegrationTab | null;
  const integrationTab: IntegrationTab =
    rawTab && VALID_INTEGRATION_TABS.has(rawTab) ? rawTab : "alerts";

  const threatMatch = cleanPath.match(/^\/threats\/([^/]+)$/);
  if (threatMatch) {
    let findingId: string;
    try {
      findingId = decodeURIComponent(threatMatch[1]);
    } catch {
      findingId = threatMatch[1];
    }
    return { page: "Threats", findingId: findingId || null, integrationTab: "alerts" };
  }

  const page = PATH_TO_PAGE.get(cleanPath) ?? "Overview";
  return {
    page,
    findingId: null,
    integrationTab: page === "Integrations" ? integrationTab : "alerts",
  };
}

export function buildPath(route: {
  page: Page;
  findingId?: string | null;
  integrationTab?: IntegrationTab;
}): string {
  if (route.findingId) {
    return `/threats/${encodeURIComponent(route.findingId)}`;
  }
  const base = PAGE_TO_PATH[route.page] ?? "/";
  if (route.page === "Integrations" && route.integrationTab && route.integrationTab !== "alerts") {
    return `${base}?tab=${encodeURIComponent(route.integrationTab)}`;
  }
  return base;
}
