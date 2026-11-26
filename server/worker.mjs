import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { alertNewFindings, processAlertDeliveries, runDueWeeklyDigests } from "./alerts.mjs";
import { resolvePartialScanFindings } from "./check-groups.mjs";
import { adminClient } from "./lib.mjs";
import {
  enqueueDueGitHubScans,
  enqueueDueSupabaseScans,
  runPlatformScanJobs,
} from "./platform-scans.mjs";
import { websiteScanIdentity } from "./scan-id.mjs";

const WORKER_HEARTBEAT_PATH = path.join(os.tmpdir(), "bulwark-worker-heartbeat.json");

export async function writeWorkerHeartbeat(summary = {}) {
  try {
    await writeFile(
      WORKER_HEARTBEAT_PATH,
      JSON.stringify({ at: new Date().toISOString(), pid: process.pid, ...summary }),
      "utf8",
    );
  } catch {
    // Heartbeat file is best-effort diagnostics only.
  }
}

export async function readWorkerHeartbeat() {
  try {
    const raw = await readFile(WORKER_HEARTBEAT_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * A scan lease is stored in the database so API and worker processes (and
 * multiple deployed instances) cannot scan the same site concurrently.
 */
async function claimSiteScan(db, siteId) {
  const token = randomUUID();
  const { data, error } = await db.rpc("claim_site_scan", {
    p_site_id: siteId,
    p_claim_token: token,
    p_lease_seconds: 900,
  });
  if (error) throw new Error(`claim scan: ${error.message}`);
  if (data !== true) {
    const err = new Error("Scan already in progress for this site.");
    err.code = "SCAN_ALREADY_RUNNING";
    throw err;
  }
  return token;
}

async function releaseSiteScan(db, siteId, token) {
  const { error } = await db.rpc("release_site_scan", {
    p_site_id: siteId,
    p_claim_token: token,
  });
  if (error) throw new Error(`release scan claim: ${error.message}`);
}

/**
 * Loads findings created or reopened by this scan. `persist_scan_result` sets
 * `first_seen_at` only on newly inserted rows, while reopened rows (previously
 * `resolved` or expired `ignored_until`) transition back to `open` with
 * `scan_id = scanId`. Active `open`/`acknowledged` rows that merely recur are
 * excluded so scheduled scans never spam duplicate alerts.
 */
async function alertableFindingsForScan(db, scanId, finishedAt, previouslyInactiveKeys) {
  const { data, error } = await db
    .from("findings")
    .select("id, title, severity, detail, url, check_key, affected_resource, status, first_seen_at")
    .eq("scan_id", scanId);
  if (error) throw new Error(`load new findings: ${error.message}`);

  const newFindings = [];
  const reopenedFindings = [];
  for (const row of data ?? []) {
    if (row.status && row.status !== "open") continue;
    const identity = `${row.check_key}\u0000${row.affected_resource ?? ""}`;
    if (row.first_seen_at && String(row.first_seen_at) >= finishedAt) {
      newFindings.push(row);
    } else if (previouslyInactiveKeys.has(identity)) {
      reopenedFindings.push(row);
    }
  }
  return { newFindings, reopenedFindings };
}

/** Writes one scan + its findings and reschedules the site atomically. */
export async function scanSite(db, site, { runChecks: runChecksImpl, manual = false } = {}) {
  const claimToken = await claimSiteScan(db, site.id);
  // Scheduled sweeps reuse deterministic slot UUIDs for retry idempotency.
  // Manual scans and 1-click re-checks are always distinct scans with fresh UUIDs.
  let scanId;
  let idempotencyKey;
  if (manual) {
    scanId = randomUUID();
    idempotencyKey = randomUUID();
  } else {
    const slot = site.next_scan_at ?? new Date().toISOString();
    ({ scanId, idempotencyKey } = websiteScanIdentity({ siteId: site.id, slot }));
  }

  try {
    const runChecks = runChecksImpl ?? (await import("./checks.mjs")).runChecks;
    const result = await runChecks(site.domain, { baseline: site.page_sample ?? null });

    const now = new Date().toISOString();
    const interval = site.scan_interval_minutes ?? 60;
    const similarity = result.defacementSimilarity ?? 1;
    const shouldUpdateSample =
      result.status === "completed" && (!site.page_sample || similarity >= 0.55);
    const resolveStale = result.status === "completed";

    const previouslyInactiveKeys = new Set();
    if (result.status !== "failed" && site.user_id) {
      try {
        const { data: priorRows } = await db
          .from("findings")
          .select("check_key, affected_resource, status, ignored_until")
          .eq("site_id", site.id)
          .eq("user_id", site.user_id);
        for (const prior of priorRows ?? []) {
          const isSnoozeExpired =
            prior.status === "ignored" &&
            Boolean(prior.ignored_until) &&
            String(prior.ignored_until) <= now;
          if (prior.status === "resolved" || isSnoozeExpired) {
            previouslyInactiveKeys.add(`${prior.check_key}\u0000${prior.affected_resource ?? ""}`);
          }
        }
      } catch {
        // Best-effort snapshot for reopened alert detection.
      }
    }

    // Persist scan record + finding changes + site schedule atomically.
    const { data: persistedScanId, error: persistError } = await db.rpc("persist_scan_result", {
      p_scan_id: scanId,
      p_idempotency_key: idempotencyKey,
      p_site_id: site.id,
      p_status: result.status,
      p_http_status: result.httpStatus,
      p_response_ms: result.responseMs,
      p_checks_total: result.checksTotal,
      p_checks_passed: result.checksPassed,
      p_checks_errored: result.checksErrored ?? 0,
      p_checks_skipped: result.checksSkipped ?? 0,
      p_check_results: result.checkResultsList ?? result.checkResults ?? {},
      p_error: result.error ?? null,
      p_started_at: now,
      p_finished_at: now,
      p_interval_minutes: interval,
      p_page_sample: shouldUpdateSample ? result.pageSample : null,
      p_page_sample_at: shouldUpdateSample ? now : null,
      p_should_update_sample: shouldUpdateSample,
      p_findings: result.findings ?? [],
      p_resolve_stale: resolveStale,
    });

    if (persistError) throw new Error(`persist scan: ${persistError.message}`);
    const effectiveScanId = typeof persistedScanId === "string" ? persistedScanId : scanId;

    if (result.status === "partial" && site.user_id) {
      try {
        await resolvePartialScanFindings(db, {
          userId: site.user_id,
          siteId: site.id,
          checkResults: result.checkResultsList ?? result.checkResults ?? {},
          coverage: result.coverage ?? null,
          findings: result.findings ?? [],
        });
      } catch (err) {
        console.error(`partial resolution failed for ${site.domain}: ${err.message}`);
      }
    }

    let newFindings = [];
    let reopenedFindings = [];
    if (result.status !== "failed" && site.user_id) {
      try {
        ({ newFindings, reopenedFindings } = await alertableFindingsForScan(
          db,
          effectiveScanId,
          now,
          previouslyInactiveKeys,
        ));
      } catch (err) {
        console.error(`load alertable findings for ${site.domain}: ${err.message}`);
      }
    }

    const actionableFindings = [...newFindings, ...reopenedFindings];
    if (actionableFindings.length && site.user_id) {
      try {
        await alertNewFindings(db, {
          site,
          findings: actionableFindings,
          userId: site.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        console.error(`slack alert failed for ${site.domain}: ${err.message}`);
      }
    }

    return {
      scanId: effectiveScanId,
      findings: result.findings.length,
      newFindings: newFindings.length,
      reopenedFindings: reopenedFindings.length,
      status: result.status,
      coverage: result.coverage,
      error: result.error,
    };
  } finally {
    await releaseSiteScan(db, site.id, claimToken);
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
    "id, user_id, domain, scan_interval_minutes, next_scan_at, page_sample",
  );

  if (error?.message?.includes("page_sample")) {
    const retry = await runQuery("id, user_id, domain, scan_interval_minutes, next_scan_at");
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
      // A claim conflict means another process is already working on it; do not
      // move its schedule. Other failures get a bounded retry delay.
      if (err.code !== "SCAN_ALREADY_RUNNING") {
        await db
          .from("sites")
          .update({ next_scan_at: new Date(Date.now() + 15 * 60_000).toISOString() })
          .eq("id", site.id);
      }
    }
  }
  return results;
}

/** One worker sweep: due websites, scheduled Supabase/GitHub scans, platform jobs, outbox retries, and weekly digests. */
export async function runWorkerTick(db, { logger = console, ...opts } = {}) {
  const siteResults = await runDueScans(db);
  for (const result of siteResults) {
    logger.log?.(
      result.ok
        ? `scanned ${result.domain}: ${result.findings} finding(s), ${result.newFindings} new, ${result.reopenedFindings} reopened (${result.status})`
        : `failed ${result.domain}: ${result.error}`,
    );
  }

  let scheduledSupabase = [];
  try {
    scheduledSupabase = await enqueueDueSupabaseScans(db);
    if (scheduledSupabase.length) {
      logger.log?.(`enqueued ${scheduledSupabase.length} scheduled Supabase scan(s)`);
    }
  } catch (err) {
    logger.error?.("scheduled Supabase enqueue failed:", err.message);
  }

  let scheduledGitHub = [];
  try {
    scheduledGitHub = await enqueueDueGitHubScans(db);
    if (scheduledGitHub.length) {
      logger.log?.(`enqueued ${scheduledGitHub.length} scheduled GitHub scan(s)`);
    }
  } catch (err) {
    logger.error?.("scheduled GitHub enqueue failed:", err.message);
  }

  let jobs = [];
  try {
    jobs = await runPlatformScanJobs(db, { logger, ...opts });
  } catch (err) {
    logger.error?.("platform jobs tick failed:", err.message);
  }
  for (const job of jobs) {
    logger.log?.(
      job.ok
        ? `platform job ${job.jobId}: ${job.status}, ${job.newFindings ?? 0} new finding(s)`
        : `platform job ${job.jobId} failed: ${job.error}`,
    );
  }

  let retriedAlerts = [];
  try {
    retriedAlerts = await processAlertDeliveries(db, opts);
  } catch (err) {
    logger.error?.("alert outbox tick failed:", err.message);
  }

  let digests = [];
  try {
    digests = await runDueWeeklyDigests(db, {
      appUrl: opts.appUrl ?? process.env.BULWARK_APP_URL ?? "http://localhost:8443",
      fetchImpl: opts.fetchImpl,
      env: opts.env,
      logger,
    });
  } catch (err) {
    logger.error?.("weekly digest tick failed:", err.message);
  }

  await writeWorkerHeartbeat({
    sitesScanned: siteResults.length,
    jobsProcessed: jobs.length,
  });

  return { siteResults, scheduledSupabase, scheduledGitHub, jobs, retriedAlerts, digests };
}

if (process.argv[1]?.endsWith("worker.mjs")) {
  const db = adminClient();
  const intervalSeconds = Number(process.env.SCAN_POLL_SECONDS ?? 60);
  let activeTick = null;
  let stopping = false;

  const tick = async () => {
    if (activeTick || stopping) return;
    activeTick = (async () => {
      try {
        await runWorkerTick(db);
      } catch (err) {
        console.error("worker tick failed:", err.message);
      } finally {
        activeTick = null;
      }
    })();
    await activeTick;
  };

  console.log(`Bulwark scan worker started (poll ${intervalSeconds}s)`);
  const timer = setInterval(tick, intervalSeconds * 1000);

  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    const forceTimer = setTimeout(() => process.exit(0), 10_000);
    forceTimer.unref();
    if (activeTick) {
      await activeTick.catch(() => {});
    }
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown());
  process.on("SIGINT", () => void shutdown());
  await tick();
}