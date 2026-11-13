import { randomUUID } from "node:crypto";
import { alertNewFindings } from "./alerts.mjs";
import { adminClient } from "./lib.mjs";
import { findingIdentity, resourceForFinding } from "./finding-identity.mjs";

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

function pickExisting(existing, identity) {
  const matches = existing.filter((row) => findingIdentity(row) === identity);
  // Prefer a currently active or muted record over older resolved history.
  return matches.find((row) => row.status === "open" || row.status === "acknowledged" || row.status === "ignored")
    ?? matches[0];
}

/** Writes one scan + its findings and reschedules the site. */
export async function scanSite(db, site) {
  const claimToken = await claimSiteScan(db, site.id);
  try {
    const { runChecks } = await import("./checks.mjs");
    const result = await runChecks(site.domain, { baseline: site.page_sample ?? null });

    const { data: scan, error: scanError } = await db
      .from("scans")
      .insert({
        site_id: site.id,
        status: result.status,
        http_status: result.httpStatus,
        response_ms: result.responseMs,
        checks_total: result.checksTotal,
        checks_passed: result.checksPassed,
        checks_errored: result.checksErrored ?? 0,
        checks_skipped: result.checksSkipped ?? 0,
        check_results: result.checkResults ?? {},
        error: result.error ?? null,
        finished_at: new Date().toISOString(),
      })
      .select("id")
      .single();

    if (scanError) throw new Error(`insert scan: ${scanError.message}`);

    const { data: existing, error: existingError } = await db
      .from("findings")
      .select("id, check_key, status, affected_resource")
      .eq("site_id", site.id);
    if (existingError) throw new Error(`load findings: ${existingError.message}`);

    const rows = existing ?? [];
    const seenIdentities = new Set(result.findings.map(findingIdentity));
    const toInsert = [];
    const toTouch = [];
    const toReopen = [];
    const alertFindings = [];

    for (const finding of result.findings) {
      const identity = findingIdentity(finding);
      const prior = pickExisting(rows, identity);
      const resource = resourceForFinding(finding) || null;
      const fields = {
        check_key: finding.check_key,
        affected_resource: resource,
        title: finding.title,
        severity: finding.severity,
        detail: finding.detail ?? null,
        evidence: finding.evidence ?? null,
        url: finding.url ?? null,
        last_seen_at: new Date().toISOString(),
      };

      if (!prior) {
        toInsert.push({ scan_id: scan.id, site_id: site.id, ...fields });
      } else if (prior.status === "ignored") {
        // Respect an explicit ignore for this exact resource.
        continue;
      } else if (prior.status === "resolved") {
        toReopen.push({ id: prior.id, fields: { ...fields, status: "open" }, finding });
        alertFindings.push(finding);
      } else {
        toTouch.push({ id: prior.id, fields });
      }
    }

    if (toInsert.length) {
      const { error } = await db.from("findings").insert(toInsert);
      if (error) throw new Error(`insert findings: ${error.message}`);
      alertFindings.push(...toInsert);
    }

    // Update rows individually so each finding retains the latest evidence and
    // severity instead of only refreshing its last_seen timestamp.
    for (const item of [...toTouch, ...toReopen]) {
      const { error } = await db.from("findings").update(item.fields).eq("id", item.id);
      if (error) throw new Error(`update finding: ${error.message}`);
    }

    // A check that errored or was skipped is not evidence that a previous issue
    // is fixed. Resolve stale rows only after a fully completed scan.
    if (result.status === "completed") {
      const staleRows = rows.filter(
        (row) => row.status === "open" && !seenIdentities.has(findingIdentity(row)),
      );
      for (const row of staleRows) {
        const { error } = await db.from("findings").update({ status: "resolved" }).eq("id", row.id);
        if (error) throw new Error(`resolve finding: ${error.message}`);
      }
    }

    const interval = site.scan_interval_minutes ?? 60;
    const update = {
      last_scan_at: new Date().toISOString(),
      next_scan_at: new Date(Date.now() + interval * 60_000).toISOString(),
    };

    const similarity = result.defacementSimilarity ?? 1;
    if (result.status === "completed" && (!site.page_sample || similarity >= 0.55)) {
      update.page_sample = result.pageSample;
      update.page_sample_at = new Date().toISOString();
    }

    const { error: siteError } = await db.from("sites").update(update).eq("id", site.id);
    if (siteError?.message?.includes("page_sample")) {
      delete update.page_sample;
      delete update.page_sample_at;
      const { error } = await db.from("sites").update(update).eq("id", site.id);
      if (error) throw new Error(`update site schedule: ${error.message}`);
    } else if (siteError) {
      throw new Error(`update site schedule: ${siteError.message}`);
    }

    // Newly created and reopened findings are both actionable state changes.
    if (alertFindings.length && result.status === "completed" && site.user_id) {
      try {
        await alertNewFindings(db, {
          site,
          findings: alertFindings,
          userId: site.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        console.error(`slack alert failed for ${site.domain}: ${err.message}`);
      }
    }

    return {
      scanId: scan.id,
      findings: result.findings.length,
      newFindings: toInsert.length,
      reopenedFindings: toReopen.length,
      status: result.status,
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
