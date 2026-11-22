import { randomUUID } from "node:crypto";
import { alertNewFindings } from "./alerts.mjs";
import { resolveConnection } from "./connections.mjs";
import { scanGitHubRepo } from "./github.mjs";
import { assertScanId } from "./scan-id.mjs";
import { scanSupabaseProject } from "./supabase.mjs";

const MAX_JOB_ATTEMPTS = 5;

function tableFor(platform) {
  if (platform === "github") return "github_connections";
  if (platform === "supabase") return "supabase_connections";
  throw new Error(`Unsupported platform: ${platform}`);
}

function normalisePersistResult(data) {
  const value = Array.isArray(data) ? data[0] : data;
  if (!value || typeof value !== "object") {
    throw new Error("Platform persistence returned no result.");
  }
  return {
    scanId: value.scanId ?? value.scan_id ?? null,
    duplicate: value.duplicate === true,
    newFindings: Array.isArray(value.newFindings) ? value.newFindings : [],
    reopenedFindings: Array.isArray(value.reopenedFindings) ? value.reopenedFindings : [],
  };
}

async function persistPlatformScan(db, params) {
  assertScanId(params.p_scan_id);
  const { data, error } = await db.rpc("persist_platform_scan_result", params);
  if (error) throw new Error(`persist platform scan: ${error.message}`);
  return normalisePersistResult(data);
}

async function sendAlerts(db, { userId, resource, persisted, appUrl, logger }) {
  const actionable = [...persisted.newFindings, ...persisted.reopenedFindings];
  if (persisted.duplicate || actionable.length === 0) {
    return { sent: false, reason: persisted.duplicate ? "duplicate" : "no new findings" };
  }

  try {
    return await alertNewFindings(db, {
      site: { id: null, domain: resource, user_id: userId },
      findings: actionable,
      userId,
      appUrl,
    });
  } catch (err) {
    // Alert delivery is best effort. Failing the scan job would retry the
    // persistence, which correctly reports a duplicate and would not re-alert,
    // so log instead of turning this into a failed scan.
    logger?.error?.(`slack alert failed for ${resource}: ${err.message}`);
    return { sent: false, reason: err.message };
  }
}

function baseParams({
  scanId,
  userId,
  platform,
  connectionId,
  resource,
  ref,
  commitSha,
  startedAt,
  finishedAt,
  result,
  deliveryId,
}) {
  return {
    p_scan_id: scanId,
    p_user_id: userId,
    p_platform: platform,
    p_connection_id: connectionId,
    p_resource: resource,
    p_ref: ref ?? result.ref ?? null,
    p_commit_sha: commitSha ?? result.commitSha ?? null,
    p_status: result.status ?? (result.error ? "failed" : "completed"),
    p_checks_total: result.checksTotal ?? 0,
    p_checks_passed: result.checksPassed ?? 0,
    p_checks_errored: result.checksErrored ?? 0,
    p_checks_skipped: result.checksSkipped ?? 0,
    p_check_results: result.checkResults ?? [],
    p_coverage: result.coverage ?? null,
    p_error: result.error ?? null,
    p_started_at: startedAt,
    p_finished_at: finishedAt,
    p_findings: result.findings ?? [],
    p_resolve_stale: result.status === "completed",
    p_delivery_id: deliveryId ?? null,
  };
}

export async function scanGitHubConnection({
  db,
  userId,
  connection,
  owner,
  repo,
  sha = null,
  ref = null,
  deliveryId = null,
  scanId = null,
  fetchImpl = fetch,
  osvFetchImpl = fetch,
  appUrl = process.env.BULWARK_APP_URL ?? "http://localhost:8443",
  logger = console,
}) {
  const resource = `${owner}/${repo}`;
  const startedAt = new Date().toISOString();

  // A manual scan is a new scan: a fresh UUID per request. Webhook/worker
  // retries pass the job's stable UUID in `scanId`.
  if (!scanId) scanId = randomUUID();
  assertScanId(scanId);

  const result = await scanGitHubRepo(connection.token, owner, repo, {
    fetchImpl,
    osvFetchImpl,
    sha,
    ref,
  });
  const finishedAt = new Date().toISOString();

  const persisted = await persistPlatformScan(
    db,
    baseParams({
      scanId,
      userId,
      platform: "github",
      connectionId: connection.id,
      resource,
      ref,
      commitSha: result.commitSha,
      startedAt,
      finishedAt,
      result,
      deliveryId,
    }),
  );

  if (result.status !== "failed") {
    await sendAlerts(db, { userId, resource, persisted, appUrl, logger });
  }

  return {
    scanId: persisted.scanId,
    duplicate: persisted.duplicate,
    status: result.status,
    findings: result.findings.length,
    newFindings: persisted.newFindings.length,
    reopenedFindings: persisted.reopenedFindings.length,
    coverage: result.coverage,
    error: result.error,
  };
}

export async function scanSupabaseConnection({
  db,
  userId,
  connection,
  deliveryId = null,
  scanId = null,
  fetchImpl = fetch,
  lookup,
  appUrl = process.env.BULWARK_APP_URL ?? "http://localhost:8443",
  logger = console,
}) {
  const resource =
    connection.projectRef ??
    new URL(connection.projectUrl).hostname.split(".")[0];
  const startedAt = new Date().toISOString();

  // A manual scan is a new scan: a fresh UUID per request.
  if (!scanId) scanId = randomUUID();
  assertScanId(scanId);

  const result = await scanSupabaseProject(connection.projectUrl, connection.apiKey, {
    fetchImpl,
    lookup,
  });
  const finishedAt = new Date().toISOString();

  const persisted = await persistPlatformScan(
    db,
    baseParams({
      scanId,
      userId,
      platform: "supabase",
      connectionId: connection.id,
      resource,
      ref: null,
      commitSha: null,
      startedAt,
      finishedAt,
      result,
      deliveryId,
    }),
  );

  if (result.status !== "failed") {
    await sendAlerts(db, { userId, resource, persisted, appUrl, logger });
  }

  return {
    scanId: persisted.scanId,
    duplicate: persisted.duplicate,
    status: result.status,
    findings: result.findings.length,
    newFindings: persisted.newFindings.length,
    reopenedFindings: persisted.reopenedFindings.length,
    coverage: result.coverage,
    error: result.error,
  };
}

/**
 * Queue a platform scan instead of running it inside a webhook request. The
 * unique (connection_id, delivery_id) index makes a repeated GitHub delivery
 * a no-op rather than a second scan.
 */
export async function enqueuePlatformScan(db, input) {
  const scanId = input.scanId ?? randomUUID();
  assertScanId(scanId);
  const { data, error } = await db
    .from("platform_scan_jobs")
    .insert({
      scan_id: scanId,
      user_id: input.userId,
      platform: input.platform,
      connection_id: input.connectionId,
      resource: input.resource,
      ref: input.ref ?? null,
      commit_sha: input.commitSha ?? null,
      delivery_id: input.deliveryId ?? null,
      status: "queued",
    })
    .select("id, scan_id")
    .single();

  if (error) {
    if (error.code === "23505") return { duplicate: true, jobId: null, scanId: null };
    throw new Error(`enqueue platform scan: ${error.message}`);
  }

  return { duplicate: false, jobId: data?.id ?? null, scanId: data?.scan_id ?? scanId };
}

async function finishJob(db, job, patch) {
  const { error } = await db
    .from("platform_scan_jobs")
    .update(patch)
    .eq("id", job.id);
  if (error) throw new Error(`update platform job: ${error.message}`);
}

export async function processPlatformScanJob(db, job, opts = {}) {
  const { logger = console, appUrl, fetchImpl = fetch, osvFetchImpl = fetch } = opts;

  let connection;
  try {
    connection = await resolveConnection(
      db,
      job.user_id,
      job.connection_id,
      tableFor(job.platform),
    );
  } catch (err) {
    await finishJob(db, job, {
      status: "failed",
      last_error: err.message,
      finished_at: new Date().toISOString(),
    });
    return { jobId: job.id, ok: false, error: err.message };
  }

  if (!connection) {
    const message = "The connection for this job no longer exists.";
    await finishJob(db, job, {
      status: "failed",
      last_error: message,
      finished_at: new Date().toISOString(),
    });
    return { jobId: job.id, ok: false, error: message };
  }

  try {
    let out;
    if (job.platform === "github") {
      const [owner, repo] = String(job.resource).split("/");
      out = await scanGitHubConnection({
        db,
        userId: job.user_id,
        connection,
        owner,
        repo,
        sha: job.commit_sha ?? null,
        ref: job.ref ?? null,
        deliveryId: job.delivery_id ?? null,
        scanId: job.scan_id,
        fetchImpl,
        osvFetchImpl,
        appUrl,
        logger,
      });
    } else {
      out = await scanSupabaseConnection({
        db,
        userId: job.user_id,
        connection,
        deliveryId: job.delivery_id ?? null,
        scanId: job.scan_id,
        fetchImpl,
        appUrl,
        logger,
      });
    }

    await finishJob(db, job, {
      status: "completed",
      last_error: out.error ?? null,
      finished_at: new Date().toISOString(),
    });
    return { jobId: job.id, ok: true, ...out };
  } catch (err) {
    const attempts = Number(job.attempts ?? 1);
    const exhausted = attempts >= MAX_JOB_ATTEMPTS;
    const retryDelaySeconds = Math.min(15 * 60, attempts * attempts * 30);
    try {
      await finishJob(db, job, {
        status: exhausted ? "failed" : "queued",
        last_error: err.message,
        finished_at: exhausted ? new Date().toISOString() : null,
        run_after: exhausted
          ? job.run_after
          : new Date(Date.now() + retryDelaySeconds * 1000).toISOString(),
      });
    } catch (updateError) {
      logger?.error?.(`failed to update platform job ${job.id}: ${updateError.message}`);
    }
    logger?.error?.(`platform job ${job.id} failed: ${err.message}`);
    return { jobId: job.id, ok: false, error: err.message, exhausted };
  }
}

/** Claim and process one batch of queued platform scan jobs. */
export async function runPlatformScanJobs(db, opts = {}) {
  const { limit = 5 } = opts;
  const { data, error } = await db.rpc("claim_platform_scan_jobs", { p_limit: limit });
  if (error) throw new Error(`claim platform jobs: ${error.message}`);

  const jobs = Array.isArray(data) ? data : [];
  const results = [];
  for (const job of jobs) {
    results.push(await processPlatformScanJob(db, job, opts));
  }
  return results;
}

/** Enqueue scheduled scans for Supabase connections whose next_scan_at is due. */
export async function enqueueDueSupabaseScans(db, { limit = 10 } = {}) {
  const { data, error } = await db.rpc("enqueue_due_supabase_scans", { p_limit: limit });
  if (error) throw new Error(`enqueue due supabase scans: ${error.message}`);
  return Array.isArray(data) ? data : [];
}
