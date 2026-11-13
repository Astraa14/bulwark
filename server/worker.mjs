import { alertNewFindings } from "./alerts.mjs";
import { adminClient } from "./lib.mjs";

// In-memory map of active scans to prevent overlapping scans
const activeScans = new Map(); // site_id -> Promise

// Rate limiting: track last scan time per user and per site
const userLastScan = new Map(); // user_id -> timestamp
const siteLastScan = new Map(); // site_id -> timestamp

const USER_SCAN_COOLDOWN_MS = 30_000; // 30 seconds between manual scans per user
const SITE_SCAN_COOLDOWN_MS = 60_000; // 60 seconds between scans per site

/**
 * Acquires a scan lock for a site. Returns true if lock acquired, false if already scanning.
 */
function acquireScanLock(siteId) {
  if (activeScans.has(siteId)) {
    return false;
  }
  activeScans.set(siteId, Promise.resolve());
  return true;
}

/**
 * Releases a scan lock for a site.
 */
function releaseScanLock(siteId) {
  activeScans.delete(siteId);
}

/**
 * Checks if a user can scan (rate limiting).
 */
function canUserScan(userId) {
  const lastScan = userLastScan.get(userId) ?? 0;
  const now = Date.now();
  if (now - lastScan < USER_SCAN_COOLDOWN_MS) {
    return false;
  }
  return true;
}

/**
 * Checks if a site can be scanned (rate limiting).
 */
function canSiteScan(siteId) {
  const lastScan = siteLastScan.get(siteId) ?? 0;
  const now = Date.now();
  if (now - lastScan < SITE_SCAN_COOLDOWN_MS) {
    return false;
  }
  return true;
}

/**
 * Records that a user/site has been scanned.
 */
function recordScan(userId, siteId) {
  const now = Date.now();
  if (userId) userLastScan.set(userId, now);
  if (siteId) siteLastScan.set(siteId, now);
}

const CHECK_STATUS_MAP = {
  pass: "passed",
  passed: "passed",
  finding: "finding",
  error: "error",
  skipped: "not_checked",
  not_checked: "not_checked",
  unavailable: "not_checked",
};

const CHECK_ACRONYMS = new Set([
  "api", "cors", "csp", "dns", "hsts", "http", "https", "mx", "ns", "php", "sql", "ssl", "tls", "url",
]);

function humanizeCheckKey(key) {
  return String(key ?? "")
    .replace(/[_-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => CHECK_ACRONYMS.has(word.toLowerCase())
      ? word.toUpperCase()
      : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

/**
 * Turns the scanner's `checkOutcomes` map into the row shape the UI reads.
 * Returns null when the scanner did not report check-level outcomes.
 */
export function buildCheckResults(result) {
  const outcomes = result?.checkOutcomes;
  if (!outcomes || typeof outcomes !== "object") return null;

  return Object.entries(outcomes).map(([key, outcome]) => {
    const raw = typeof outcome === "string" ? outcome : outcome?.status;
    const status = CHECK_STATUS_MAP[String(raw ?? "").toLowerCase()] ?? "not_checked";
    return {
      key: outcome?.checkKey ?? key,
      label: humanizeCheckKey(outcome?.checkKey ?? key),
      status,
      complete: status === "passed" || status === "finding" ? true : status === "error" ? false : null,
      ...(status === "error" && result?.error ? { error: result.error } : {}),
    };
  });
}

function scanStatusFor(result, checkResults) {
  if (result.status === "failed") return "failed";
  if (result.status === "running") return "running";
  if (result.status === "partial") return "partial";
  const incomplete = (checkResults ?? []).some(
    (r) => r.status === "error" || r.status === "not_checked",
  );
  return incomplete ? "partial" : "completed";
}

/** Writes one scan + its findings and reschedules the site. */
export async function scanSite(db, site, { userId = null, manual = false } = {}) {
  // Check rate limits for manual scans
  if (manual) {
    if (userId && !canUserScan(userId)) {
      throw new Error("Rate limit exceeded: Please wait before scanning again.");
    }
    if (!canSiteScan(site.id)) {
      throw new Error("Site was recently scanned. Please wait before scanning again.");
    }
  }

  // Acquire scan lock to prevent overlapping scans
  if (!acquireScanLock(site.id)) {
    if (manual) {
      throw new Error("A scan is already in progress for this site.");
    }
    // For worker, skip this site and let it be picked up next tick
    return { scanId: null, findings: 0, newFindings: 0, skipped: true };
  }

  try {
    recordScan(userId, site.id);

    const { runChecks } = await import("./checks.mjs");
    const result = await runChecks(site.domain, { baseline: site.page_sample ?? null });

    const checkResults = buildCheckResults(result);
    const checksErrored = checkResults
      ? checkResults.filter((r) => r.status === "error").length
      : null;
    const checksSkipped = checkResults
      ? checkResults.filter((r) => r.status === "not_checked").length
      : null;

    const scanRow = {
      site_id: site.id,
      status: scanStatusFor(result, checkResults),
      http_status: result.httpStatus,
      response_ms: result.responseMs,
      checks_total: result.checksTotal,
      checks_passed: result.checksPassed,
      check_results: checkResults,
      checks_errored: checksErrored,
      checks_skipped: checksSkipped,
      error: result.error ?? null,
      finished_at: new Date().toISOString(),
    };

    let { data: scan, error: scanError } = await db
      .from("scans")
      .insert(scanRow)
      .select("id")
      .single();

    // Pre-migration fallback: the outcome columns and the "partial" status do
    // not exist until the scan-outcomes migration is applied.
    if (scanError?.message?.match(/check_results|checks_errored|checks_skipped|scans_status_check/)) {
      const fallback = { ...scanRow };
      delete fallback.check_results;
      delete fallback.checks_errored;
      delete fallback.checks_skipped;
      if (fallback.status === "partial") fallback.status = "completed";
      const retry = await db.from("scans").insert(fallback).select("id").single();
      scan = retry.data;
      scanError = retry.error;
    }

    if (scanError) throw new Error(`insert scan: ${scanError.message}`);

    const { data: existing } = await db
      .from("findings")
      .select("id, check_key, status")
      .eq("site_id", site.id);

    const byKey = new Map((existing ?? []).map((f) => [f.check_key, f]));
    const seenKeys = new Set(result.findings.map((f) => f.check_key));
    const checkOutcomes = result.checkOutcomes ?? {};

    const toInsert = [];
    const toTouch = [];
    const toReopen = [];

    // Keep the rich finding context current on later scans, so findings created
    // before this metadata existed pick it up without being re-created.
    const contextPatch = (f) => ({
      title: f.title,
      severity: f.severity,
      detail: f.detail ?? null,
      evidence: f.evidence ?? null,
      url: f.url ?? null,
      confidence: f.confidence ?? "medium",
      what_it_does_not_prove: f.what_it_does_not_prove ?? null,
      remediation: f.remediation ?? null,
      affected_resource: f.affected_resource ?? null,
    });

    for (const f of result.findings) {
      const prior = byKey.get(f.check_key);
      if (!prior) {
        toInsert.push({
          scan_id: scan.id,
          site_id: site.id,
          check_key: f.check_key,
          ...contextPatch(f),
        });
        continue;
      }
      // Respect an explicit ignore: do not resurrect it on every scan.
      if (prior.status === "ignored") continue;
      // A manually resolved issue that is still present reopens the same row.
      if (prior.status === "resolved") toReopen.push(prior.id);
      toTouch.push({ id: prior.id, patch: contextPatch(f) });
    }

    if (toInsert.length) {
      const { error } = await db.from("findings").insert(toInsert);
      if (error?.message?.match(/confidence|what_it_does_not_prove|remediation|affected_resource/)) {
        // Pre-migration fallback: keep recording findings without the new context.
        const minimal = toInsert.map((f) => {
          const row = { ...f };
          delete row.confidence;
          delete row.what_it_does_not_prove;
          delete row.remediation;
          delete row.affected_resource;
          return row;
        });
        const retry = await db.from("findings").insert(minimal);
        if (retry.error) throw new Error(`insert findings: ${retry.error.message}`);
      } else if (error) {
        throw new Error(`insert findings: ${error.message}`);
      }
    }

    if (toReopen.length) {
      await db
        .from("findings")
        .update({ status: "open", last_seen_at: new Date().toISOString() })
        .in("id", toReopen);
    }

    if (toTouch.length) {
      const seenAt = new Date().toISOString();
      const updates = await Promise.all(
        toTouch.map(({ id, patch }) =>
          db
            .from("findings")
            .update({ ...patch, last_seen_at: seenAt })
            .eq("id", id)
            .then(({ error }) => error?.message ?? null),
        ),
      );

      // Pre-migration fallback: record at least the last-seen time when the
      // context columns do not exist yet.
      if (updates.some((message) => /confidence|what_it_does_not_prove|remediation|affected_resource/.test(message ?? ""))) {
        await db
          .from("findings")
          .update({ last_seen_at: seenAt })
          .in("id", toTouch.map((f) => f.id));
      }
    }

    // Only auto-resolve findings when the check completed successfully (status: 'pass')
    // and the finding is no longer present. Never resolve on error or incomplete checks.
    const staleIds = (existing ?? [])
      .filter((f) => {
        if (f.status !== "open") return false;
        if (seenKeys.has(f.check_key)) return false;
        // Check if the check completed successfully
        const outcome = checkOutcomes[f.check_key];
        return outcome && outcome.status === 'pass';
      })
      .map((f) => f.id);
    if (staleIds.length) {
      await db.from("findings").update({ status: "resolved" }).in("id", staleIds);
    }

    const interval = site.scan_interval_minutes ?? 60;
    const update = {
      last_scan_at: new Date().toISOString(),
      next_scan_at: new Date(Date.now() + interval * 60_000).toISOString(),
    };

    // Keep a defacement baseline. Accept normal drift, keep the old baseline when
    // the page changed drastically so the finding keeps firing until it is fixed.
    const similarity = result.defacementSimilarity ?? 1;
    if (!site.page_sample || similarity >= 0.55) {
      update.page_sample = result.pageSample;
      update.page_sample_at = new Date().toISOString();
    }

    const { error: siteError } = await db.from("sites").update(update).eq("id", site.id);
    // Pre-migration fallback: retry without the defacement columns if they do not exist.
    if (siteError?.message?.includes("page_sample")) {
      delete update.page_sample;
      delete update.page_sample_at;
      await db.from("sites").update(update).eq("id", site.id);
    }

    if (toInsert.length && site.user_id) {
      try {
        await alertNewFindings(db, {
          site,
          findings: toInsert,
          userId: site.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        // An alert failure must never fail the scan.
        console.error(`slack alert failed for ${site.domain}: ${err.message}`);
      }
    }

    return { scanId: scan.id, findings: result.findings.length, newFindings: toInsert.length };
  } finally {
    // Always release the scan lock
    releaseScanLock(site.id);
  }
}

/** One pass over every verified site that is due. */
export async function runDueScans(db, limit = 10) {
  const runQuery = (columns) =>
    db
      .from("sites")
      .select(columns)
      .eq("status", "verified")
      .lte("next_scan_at", new Date().toISOString())
      .order("next_scan_at", { ascending: true })
      .limit(limit);

  let { data: due, error } = await runQuery(
    "id, user_id, domain, scan_interval_minutes, page_sample",
  );

  // Pre-migration fallback when the defacement columns do not exist yet.
  if (error?.message?.includes("page_sample")) {
    const retry = await runQuery("id, user_id, domain, scan_interval_minutes");
    due = retry.data;
    error = retry.error;
  }

  if (error) throw new Error(`load due sites: ${error.message}`);

  const results = [];
  for (const site of due ?? []) {
    try {
      results.push({ domain: site.domain, ok: true, ...(await scanSite(db, site)) });
    } catch (err) {
      results.push({ domain: site.domain, ok: false, error: err.message });
      // Back off so a broken site does not spin the worker.
      await db
        .from("sites")
        .update({ next_scan_at: new Date(Date.now() + 15 * 60_000).toISOString() })
        .eq("id", site.id);
    }
  }
  return results;
}

if (process.argv[1]?.endsWith("worker.mjs")) {
  const db = adminClient();
  const intervalSeconds = Number(process.env.SCAN_POLL_SECONDS ?? 60);
  let tickInProgress = false;

  const tick = async () => {
    if (tickInProgress) {
      console.log("Worker tick already in progress, skipping this interval");
      return;
    }

    tickInProgress = true;
    try {
      const results = await runDueScans(db);
      for (const r of results) {
        console.log(
          r.ok
            ? `scanned ${r.domain}: ${r.findings} finding(s), ${r.newFindings} new`
            : `failed ${r.domain}: ${r.error}`,
        );
      }
    } catch (err) {
      console.error("worker tick failed:", err.message);
    } finally {
      tickInProgress = false;
    }
  };

  console.log(`Bulwark scan worker started (poll ${intervalSeconds}s)`);
  await tick();
  setInterval(tick, intervalSeconds * 1000);
}
