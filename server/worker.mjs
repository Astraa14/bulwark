import { randomUUID } from "node:crypto";
import { alertNewFindings } from "./alerts.mjs";
import { adminClient } from "./lib.mjs";
import { runPlatformScanJobs } from "./platform-scans.mjs";
import { websiteScanIdentity } from "./scan-id.mjs";

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
 * Findings that were actually created by this scan. The RPC sets
 * `first_seen_at` only for new rows, while existing findings keep their
 * original timestamp. This is what keeps hourly scans from re-alerting every
 * finding they still see.
 */
async function newFindingsForScan(db, scanId, finishedAt) {
  const { data, error } = await db
    .from("findings")
    .select("id, title, severity, detail, url, check_key, affected_resource")
    .eq("scan_id", scanId)
    .gte("first_seen_at", finishedAt);
  if (error) throw new Error(`load new findings: ${error.message}`);
  return data ?? [];
}

/** Writes one scan + its findings and reschedules the site atomically. */
export async function scanSite(db, site, { runChecks: runChecksImpl } = {}) {
  const claimToken = await claimSiteScan(db, site.id);
  // One logical scan per claimed slot. Retries of this slot reuse both values;
  // the next due slot produces a new UUID pair. Never use site.id as the id:
  // scans.id is a uuid and a constant key would suppress every later scan.
  const slot = site.next_scan_at ?? new Date().toISOString();
  const { scanId, idempotencyKey } = websiteScanIdentity({ siteId: site.id, slot });
  try {
    const runChecks = runChecksImpl ?? (await import("./checks.mjs")).runChecks;
    const result = await runChecks(site.domain, { baseline: site.page_sample ?? null });

    const now = new Date().toISOString();
    const interval = site.scan_interval_minutes ?? 60;
    const similarity = result.defacementSimilarity ?? 1;
    const shouldUpdateSample =
      result.status === "completed" && (!site.page_sample || similarity >= 0.55);
    const resolveStale = result.status === "completed";

    // Persist scan record + finding changes + site schedule atomically.
    const { error: persistError } = await db.rpc("persist_scan_result", {
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
      p_check_results: result.checkResults ?? {},
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

    let newFindings = [];
    if (result.status !== "failed" && site.user_id) {
      try {
        newFindings = await newFindingsForScan(db, scanId, now);
      } catch (err) {
        console.error(`load alertable findings for ${site.domain}: ${err.message}`);
      }
    }

    if (newFindings.length && site.user_id) {
      try {
        await alertNewFindings(db, {
          site,
          findings: newFindings,
          userId: site.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        console.error(`slack alert failed for ${site.domain}: ${err.message}`);
      }
    }

    return {
      scanId,
      findings: result.findings.length,
      newFindings: newFindings.length,
      reopenedFindings: 0,
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
    "id, user_id, domain, scan_interval_minutes, page_sample",
  );

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

if (process.argv[1]?.endsWith("worker.mjs")) {
  const db = adminClient();
  const intervalSeconds = Number(process.env.SCAN_POLL_SECONDS ?? 60);
  let tickRunning = false;

  const tick = async () => {
    if (tickRunning) return;
    tickRunning = true;
    try {
      const results = await runDueScans(db);
      for (const result of results) {
        console.log(
          result.ok
            ? `scanned ${result.domain}: ${result.findings} finding(s), ${result.newFindings} new, ${result.reopenedFindings} reopened (${result.status})`
            : `failed ${result.domain}: ${result.error}`,
        );
      }

      let jobs = [];
      try {
        jobs = await runPlatformScanJobs(db);
      } catch (err) {
        // The jobs table may not exist until the platform migration runs.
        console.error("platform jobs tick failed:", err.message);
      }
      for (const job of jobs) {
        console.log(
          job.ok
            ? `platform job ${job.jobId}: ${job.status}, ${job.newFindings ?? 0} new finding(s)`
            : `platform job ${job.jobId} failed: ${job.error}`,
        );
      }
    } catch (err) {
      console.error("worker tick failed:", err.message);
    } finally {
      tickRunning = false;
    }
  };

  console.log(`Bulwark scan worker started (poll ${intervalSeconds}s)`);
  await tick();
  setInterval(tick, intervalSeconds * 1000);
}