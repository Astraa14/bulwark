import type {
  FindingRow,
  ScanCheckResult,
  ScanRow,
  Severity,
  SiteRow,
  SiteStack,
} from "./workspace.ts";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const INTERVAL_OPTIONS = [
  { value: 15, label: "Every 15 minutes" },
  { value: 30, label: "Every 30 minutes" },
  { value: 60, label: "Every hour" },
  { value: 180, label: "Every 3 hours" },
  { value: 360, label: "Every 6 hours" },
  { value: 1440, label: "Once a day" },
];

export const SUPABASE_INTERVAL_OPTIONS = [
  { value: 60, label: "Every hour" },
  { value: 180, label: "Every 3 hours" },
  { value: 360, label: "Every 6 hours" },
  { value: 720, label: "Every 12 hours" },
  { value: 1440, label: "Once a day" },
  { value: 10080, label: "Once a week" },
];

export const GITHUB_INTERVAL_OPTIONS = [
  { value: 360, label: "Every 6 hours" },
  { value: 720, label: "Every 12 hours" },
  { value: 1440, label: "Once a day" },
  { value: 10080, label: "Once a week" },
];

export const STACK_OPTIONS: { value: SiteStack; label: string }[] = [
  { value: "nextjs-vercel", label: "Next.js / Vercel" },
  { value: "vite-render", label: "Vite / Render" },
  { value: "cloudflare", label: "Cloudflare" },
  { value: "nginx", label: "Nginx" },
  { value: "express", label: "Node / Express" },
  { value: "supabase", label: "Supabase" },
  { value: "other", label: "Other" },
];

export const KEY_PROVIDERS = {
  openai: { label: "OpenAI", model: "gpt-4.1-mini", placeholder: "sk-..." },
  anthropic: { label: "Anthropic", model: "claude-haiku-4-5", placeholder: "sk-ant-..." },
  gemini: { label: "Google Gemini", model: "gemini-2.5-flash", placeholder: "AIza..." },
} as const;

export function intervalLabel(minutes: number) {
  return INTERVAL_OPTIONS.find((o) => o.value === minutes)?.label ?? `Every ${minutes} minutes`;
}

export function supabaseIntervalLabel(minutes: number) {
  return (
    SUPABASE_INTERVAL_OPTIONS.find((o) => o.value === minutes)?.label ??
    `Every ${minutes} minutes`
  );
}

export function githubIntervalLabel(minutes: number) {
  return (
    GITHUB_INTERVAL_OPTIONS.find((o) => o.value === minutes)?.label ??
    `Every ${minutes} minutes`
  );
}

export function stackLabel(stack?: SiteStack | null) {
  if (!stack) return "Not set";
  return STACK_OPTIONS.find((o) => o.value === stack)?.label ?? stack;
}

export function csvCell(value: unknown) {
  let text = String(value ?? "");
  // Spreadsheet formula injection: a leading =, +, -, @, tab or CR makes
  // Excel/Sheets evaluate the cell. Prefix with an apostrophe, then quote.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

/** Only http(s) links may be rendered as hrefs; anything else is ignored. */
export function safeExternalUrl(value: string | null | undefined) {
  if (!value) return null;
  try {
    const url = new URL(value, window.location.origin);
    return url.protocol === "http:" || url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

export function downloadCsv(name: string, header: string[], rows: unknown[][]) {
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

export function escapeHtml(value: unknown) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Website findings show their domain; platform findings show their resource. */
export function siteLabel(sites: SiteRow[], finding: FindingRow) {
  return sites.find((site) => site.id === finding.site_id)?.domain ?? finding.resource ?? "—";
}

export function findingSourceKind(finding: FindingRow): "website" | "github" | "supabase" {
  if (finding.platform === "github") return "github";
  if (finding.platform === "supabase") return "supabase";
  return "website";
}

export function scanSourceKind(scan: ScanRow): "website" | "github" | "supabase" {
  if (scan.platform === "github") return "github";
  if (scan.platform === "supabase") return "supabase";
  return "website";
}

const EXTRA_SHIP_BLOCKER_KEYS = new Set([
  "stripe_test_key_in_production",
  "webhook_missing_signature_verification",
  "ai_route_without_auth",
  "supabase_anon_readable_table",
  "site_supabase_anon_exposure",
  "supabase_function_unverified_jwt",
]);

/**
 * Distinguishes launch-stopping exposures ("Ship-blockers") from lower-urgency
 * defense-in-depth polish ("Polish later") so non-security builders know
 * whether it is safe to share their link publicly right now.
 */
export function isShipBlocker(finding: FindingRow): boolean {
  if (finding.severity === "critical" || finding.severity === "high") return true;
  return EXTRA_SHIP_BLOCKER_KEYS.has(finding.check_key);
}

export function findingImpactSummary(finding: FindingRow): string {
  const key = finding.check_key;
  if (
    key.startsWith("secret_") ||
    key.startsWith("history_secret_") ||
    key === "client_exposed_secret_env" ||
    key === "exposed_env" ||
    key === "exposed_config_file"
  ) {
    return "Anyone who sees your bundle or repo can copy this credential and access your account or backend.";
  }
  if (
    key === "supabase_anon_readable_table" ||
    key === "site_supabase_anon_exposure" ||
    key === "supabase_table_no_rls" ||
    key === "supabase_migration_missing_rls"
  ) {
    return "Unauthenticated visitors can query rows directly using your public Supabase anon key.";
  }
  if (key === "supabase_public_storage") {
    return "Anyone with the bucket URL can list and download files stored in this bucket.";
  }
  if (key === "ai_route_without_auth") {
    return "Bots can loop requests to this endpoint and drain your paid AI/API balance.";
  }
  if (key === "webhook_missing_signature_verification") {
    return "Anyone can POST a forged webhook payload to spoof payments or upgrade accounts for free.";
  }
  if (key === "supabase_function_unverified_jwt" || key === "supabase_anon_rpc_exposed") {
    return "Unauthenticated callers can invoke this backend function directly with the anon key.";
  }
  if (key === "stripe_test_key_in_production") {
    return "Live visitors hit Stripe test mode — checkouts fail or accept fake test cards without charging.";
  }
  if (key === "gitignore_missing_env") {
    return "A single `git add .` can accidentally commit live `.env` secrets into git history.";
  }
  if (key.startsWith("dep_vuln_")) {
    return "A locked package version has a published security advisory in OSV.";
  }
  if (
    key === "exposed_source_map" ||
    key === "exposed_git" ||
    key === "exposed_sql" ||
    key === "exposed_api_docs" ||
    key === "graphql_introspection_enabled"
  ) {
    return "Visitors can download internal source code, git metadata, database dumps, or API schemas.";
  }
  if (key === "cors_wildcard_credentials" || key === "vercel_wildcard_cors_credentials" || key === "cors_reflects_origin") {
    return "Malicious sites can read authenticated API responses from logged-in users' browsers.";
  }
  if (key.startsWith("tls_") || key === "site_unreachable" || key.startsWith("http_")) {
    return "Visitors may hit browser security warnings or a broken landing page.";
  }
  if (key.startsWith("workflow_")) {
    return "Untrusted pull requests or upstream action updates could gain CI write permissions.";
  }
  if (isShipBlocker(finding)) {
    return "High-impact exposure — fix before sharing this app publicly.";
  }
  return "Defense-in-depth hardening — safe to polish after your initial launch.";
}

export function sortFindingsByPriority(items: FindingRow[]): FindingRow[] {
  return [...items].sort((a, b) => {
    const blockerDiff = Number(isShipBlocker(b)) - Number(isShipBlocker(a));
    if (blockerDiff !== 0) return blockerDiff;
    const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime();
  });
}

export function healthKey(site: SiteRow, findings: FindingRow[]) {
  if (site.status === "pending") return "pending";
  if (site.status === "paused") return "paused";
  const open = findings.filter((f) => f.site_id === site.id && f.status === "open");
  if (open.some((f) => f.severity === "critical" || f.severity === "high")) return "at-risk";
  if (open.length) return "attention";
  return "healthy";
}

export function siteHealth(site: SiteRow, findings: FindingRow[]) {
  const key = healthKey(site, findings);
  if (key === "pending") return { label: "Awaiting verification", tone: "medium" };
  if (key === "paused") return { label: "Paused", tone: "low" };
  if (key === "at-risk") return { label: "At risk", tone: "critical" };
  if (key === "attention") return { label: "Needs attention", tone: "high" };
  return { label: "Healthy", tone: "healthy" };
}

export type CheckOutcome = "passed" | "finding" | "not_checked" | "error";

export type ScanOutcomeSummary = Record<CheckOutcome, number> & {
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

export const CHECK_OUTCOME_ORDER: CheckOutcome[] = ["passed", "finding", "not_checked", "error"];

const CHECK_OUTCOME_PLURAL: Record<CheckOutcome, string> = {
  passed: "passed",
  finding: "findings",
  not_checked: "not checked",
  error: "errors",
};

export function outcomeLabel(outcome: CheckOutcome, count: number) {
  return count === 1 ? CHECK_OUTCOME_LABEL[outcome].toLowerCase() : CHECK_OUTCOME_PLURAL[outcome];
}

export function outcomeText(outcome: CheckOutcome, count: number) {
  return `${count} ${outcomeLabel(outcome, count)}`;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : null;
}

export function checkOutcome(result: ScanCheckResult): CheckOutcome {
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

export function scanOutcomeSummary(scan: ScanRow): ScanOutcomeSummary {
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

export function scanState(scan: ScanRow, summary = scanOutcomeSummary(scan)) {
  if (scan.status === "failed") return { label: "Failed", tone: "critical" };
  if (scan.status === "running") return { label: "Running", tone: "medium" };
  if (scan.status === "partial" || (summary.detailed && (summary.error || summary.not_checked))) {
    return { label: "Partial", tone: "medium" };
  }
  return { label: "Complete", tone: "healthy" };
}
