import type {
  FindingRow,
  ScanCheckResult,
  ScanRow,
  Severity,
  SiteRow,
  SiteStack,
} from "./workspace";

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
