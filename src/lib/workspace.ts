import { useCallback, useEffect, useState } from "react";
import { apiDelete, apiGet, apiPost, apiPut } from "./api";
import { supabase } from "./supabase";

export type SiteStatus = "pending" | "verified" | "paused";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "resolved" | "ignored";

export type SiteRow = {
  id: string;
  user_id: string;
  domain: string;
  display_name: string | null;
  status: SiteStatus;
  verify_token: string;
  scan_interval_minutes: number;
  autonomy: "suggest" | "auto_fix";
  last_scan_at: string | null;
  next_scan_at: string;
  page_sample?: string | null;
  page_sample_at?: string | null;
  created_at: string;
};

export type FindingRow = {
  id: string;
  site_id: string;
  scan_id: string;
  check_key: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  detail: string | null;
  evidence: string | null;
  url: string | null;
  /** Scanner confidence in the observation: high, medium, or low. */
  confidence?: "high" | "medium" | "low" | null;
  /** What this observation does not prove, so it is not over-read. */
  what_it_does_not_prove?: string | null;
  /** Concrete, safe step to remediate the observation. */
  remediation?: string | null;
  affected_resource?: string | null;
  explanation: string | null;
  explanation_model: string | null;
  explained_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
};

export type ScanStatus = "running" | "completed" | "partial" | "failed";

/** A check-level result recorded by the scanner. */
export type ScanCheckResult = {
  key: string;
  label: string;
  /** `passed`, `finding`, `not_checked`, or `error` for new scans. */
  status: string;
  /** A check can explicitly report that it did not finish. */
  complete?: boolean | null;
  /** A safe, user-facing reason when the check could not run. */
  error?: string | null;
};

export type ScanRow = {
  id: string;
  site_id: string;
  started_at: string;
  finished_at: string | null;
  status: ScanStatus;
  http_status: number | null;
  response_ms: number | null;
  checks_total: number;
  checks_passed: number;
  /** Number of checks that ended with an execution error. */
  checks_errored?: number | null;
  /** Number of checks intentionally skipped or not run. */
  checks_skipped?: number | null;
  /** Per-check outcomes for scans created after outcome tracking was enabled. */
  check_results?: ScanCheckResult[] | null;
  error: string | null;
};

export type Settings = {
  scanIntervalMinutes: number;
  autonomy: "suggest" | "auto_fix";
  slackWebhookUrl: string | null;
  slackMinSeverity: Severity;
  alertsEnabled: boolean;
};

export type ApiKeyRow = {
  id: string;
  provider: "openai" | "anthropic";
  providerLabel: string;
  label: string | null;
  model: string | null;
  preview: string;
  monthlyLimitUsd: number;
  lastUsedAt: string | null;
  createdAt: string;
};

export function normalizeDomain(input: string) {
  return input
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
}

export function relTime(iso: string | null) {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.round(diff / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function shortDate(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export async function createSite(domain: string): Promise<SiteRow> {
  if (!supabase) throw new Error("Supabase is not configured.");
  const clean = normalizeDomain(domain);
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean)) throw new Error("Enter a valid domain, e.g. example.com");

  const { data: userData } = await supabase.auth.getUser();
  if (!userData.user) throw new Error("You are signed out.");

  const { data, error } = await supabase
    .from("sites")
    .insert({ user_id: userData.user.id, domain: clean })
    .select("*")
    .single();

  if (error) {
    if (error.code === "23505") throw new Error("That site is already in your workspace.");
    throw new Error(error.message);
  }
  return data as SiteRow;
}

export function verifySite(siteId: string) {
  return apiPost<{ ok: boolean; method: string }>("/api/verify", { siteId });
}

export function scanSiteNow(siteId: string) {
  return apiPost<{ ok: boolean; findings: number; newFindings: number; scanId: string }>("/api/scan", {
    siteId,
  });
}

export function acceptBaseline(siteId: string) {
  return apiPost<{ ok: boolean }>("/api/site/baseline", { siteId });
}

export function setSiteStatus(siteId: string, action: "pause" | "resume") {
  return apiPost<{ ok: boolean; status: SiteStatus }>("/api/site/status", { siteId, action });
}

export async function deleteSite(siteId: string) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase.from("sites").delete().eq("id", siteId);
  if (error) throw new Error(error.message);
}

export async function setSiteInterval(siteId: string, minutes: number) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase
    .from("sites")
    .update({ scan_interval_minutes: minutes })
    .eq("id", siteId);
  if (error) throw new Error(error.message);
}

export async function setFindingStatus(findingId: string, status: FindingStatus) {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { error } = await supabase.from("findings").update({ status }).eq("id", findingId);
  if (error) throw new Error(error.message);
}

export function explainFinding(findingId: string, refresh = false) {
  return apiPost<{
    explanation: string;
    model: string;
    cached: boolean;
    explainedAt: string;
  }>("/api/explain", { findingId, refresh });
}

export function useWorkspace() {
  const [sites, setSites] = useState<SiteRow[]>([]);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scanCount, setScanCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }

    const [sitesRes, findingsRes, scansRes, countRes] = await Promise.all([
      supabase.from("sites").select("*").order("created_at", { ascending: true }),
      supabase
        .from("findings")
        .select("*")
        .order("last_seen_at", { ascending: false })
        .limit(400),
      supabase.from("scans").select("*").order("started_at", { ascending: false }).limit(120),
      supabase.from("scans").select("id", { count: "exact", head: true }),
    ]);

    if (sitesRes.error) setError(sitesRes.error.message);
    else setError(null);

    setSites((sitesRes.data ?? []) as SiteRow[]);
    setFindings((findingsRes.data ?? []) as FindingRow[]);
    setScans((scansRes.data ?? []) as ScanRow[]);
    setScanCount(countRes.count ?? 0);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { sites, findings, scans, scanCount, loading, error, refresh };
}

export function useSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    try {
      const res = await apiGet<{ settings: Settings }>("/api/settings");
      setSettings(res.settings);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(async (patch: Partial<Settings>) => {
    const res = await apiPut<{ settings: Settings }>("/api/settings", patch);
    setSettings(res.settings);
    return res.settings;
  }, []);

  return { settings, loading, error, save, reload: load };
}

export function useApiKeys() {
  const [keys, setKeys] = useState<ApiKeyRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    try {
      const res = await apiGet<{ keys: ApiKeyRow[] }>("/api/keys");
      setKeys(res.keys);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const add = useCallback(
    async (input: { provider: string; key: string; label?: string; model?: string }) => {
      const res = await apiPost<{ key: ApiKeyRow }>("/api/keys", input);
      await load();
      return res.key;
    },
    [load],
  );

  const remove = useCallback(
    async (id: string) => {
      await apiDelete(`/api/keys/${id}`);
      await load();
    },
    [load],
  );

  return { keys, loading, error, add, remove, reload: load };
}
