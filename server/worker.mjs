import { alertNewFindings } from "./alerts.mjs";
import { adminClient } from "./lib.mjs";

const activeScans = new Set();

/** Writes one scan + its findings and reschedules the site. */
export async function scanSite(db, site) {
  const siteKey = site.id ?? site.domain;
  if (activeScans.has(siteKey)) {
    throw new Error(`Scan already in progress for ${site.domain}`);
  }

  activeScans.add(siteKey);
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

    const { data: existing } = await db
      .from("findings")
      .select("id, check_key, status")
      .eq("site_id", site.id);

    const byKey = new Map((existing ?? []).map((f) => [f.check_key, f]));
    const seenKeys = new Set(result.findings.map((f) => f.check_key));

    const toInsert = [];
    const toTouch = [];
    const toReopen = [];

    for (const f of result.findings) {
      const prior = byKey.get(f.check_key);
      if (!prior) {
        toInsert.push({
          scan_id: scan.id,
          site_id: site.id,
          check_key: f.check_key,
          title: f.title,
          severity: f.severity,
          detail: f.detail ?? null,
          evidence: f.evidence ?? null,
          url: f.url ?? null,
        });
        continue;
      }
      if (prior.status === "ignored") continue;
      if (prior.status === "resolved") {
        toReopen.push(prior.id);
        continue;
      }
      toTouch.push(prior.id);
    }

    if (toInsert.length) {
      const { error } = await db.from("findings").insert(toInsert);
      if (error) throw new Error(`insert findings: ${error.message}`);
    }

    if (toTouch.length) {
      await db
        .from("findings")
        .update({ last_seen_at: new Date().toISOString() })
        .in("id", toTouch);
    }

    if (toReopen.length) {
      await db
        .from("findings")
        .update({ status: "open", last_seen_at: new Date().toISOString() })
        .in("id", toReopen);
    }

    const shouldResolveStale = result.status === "completed";
    if (shouldResolveStale) {
      const staleIds = (existing ?? [])
        .filter((f) => f.status === "open" && !seenKeys.has(f.check_key))
        .map((f) => f.id);
      if (staleIds.length) {
        await db.from("findings").update({ status: "resolved" }).in("id", staleIds);
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
      await db.from("sites").update(update).eq("id", site.id);
    }

    if (toInsert.length && result.status === "completed" && site.user_id) {
      try {
        await alertNewFindings(db, {
          site,
          findings: toInsert,
          userId: site.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        console.error(`slack alert failed for ${site.domain}: ${err.message}`);
      }
    }

    return { scanId: scan.id, findings: result.findings.length, newFindings: toInsert.length, status: result.status };
  } finally {
    activeScans.delete(siteKey);
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

  const tick = async () => {
    try {
      const results = await runDueScans(db);
      for (const r of results) {
        console.log(
          r.ok
            ? `scanned ${r.domain}: ${r.findings} finding(s), ${r.newFindings} new (${r.status})`
            : `failed ${r.domain}: ${r.error}`,
        );
      }
    } catch (err) {
      console.error("worker tick failed:", err.message);
    }
  };

  console.log(`Bulwark scan worker started (poll ${intervalSeconds}s)`);
  await tick();
  setInterval(tick, intervalSeconds * 1000);
}

