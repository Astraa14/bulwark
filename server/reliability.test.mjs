import test from "node:test";
import assert from "node:assert/strict";

process.env.BULWARK_ENCRYPTION_KEY = process.env.BULWARK_ENCRYPTION_KEY || "bulwark-test-encryption-key";

const { scanSite } = await import("./worker.mjs");
const { createApp } = await import("./app.mjs");
const { completedCheckGroups, resolvePartialScanFindings } = await import("./check-groups.mjs");
const { runChecks, rdapBaseUrl, resetRdapBootstrapCache } = await import("./checks.mjs");
const { scanVibeCodeFootguns } = await import("./github.mjs");
const { normalizeCheckResults, scanOutcomeSummary, isShipBlocker } = await import(
  "../src/lib/scanOutcomes.ts"
);
const { createFakeDb } = await import("./test-support/fake-db.mjs");

const SITE_ID = "77777777-7777-4777-8777-777777777777";
const CTX = { owner: "octo", repo: "app", commitSha: "a".repeat(40) };

function site() {
  return {
    id: SITE_ID,
    user_id: "user-a",
    domain: "example.com",
    scan_interval_minutes: 60,
    page_sample: null,
    next_scan_at: "2026-01-01T00:00:00.000Z",
  };
}

function checksResult(overrides = {}) {
  return {
    status: "completed",
    httpStatus: 200,
    responseMs: 5,
    checksTotal: 1,
    checksPassed: 1,
    checksErrored: 0,
    checksSkipped: 0,
    checkResults: {},
    findings: [],
    coverage: {},
    defacementSimilarity: 1,
    pageSample: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Scan identity: manual scans never collide with scheduled slots
// ---------------------------------------------------------------------------

test("manual scans always get a fresh scan id and idempotency key", async () => {
  const calls = [];
  const db = createFakeDb({
    tables: { findings: [] },
    rpcHandlers: {
      persist_scan_result: (args) => {
        calls.push(args);
        return { data: args.p_scan_id, error: null };
      },
    },
  });
  const runChecksStub = async () => checksResult();

  await scanSite(db, site(), { runChecks: runChecksStub });
  await scanSite(db, site(), { runChecks: runChecksStub, manual: true });
  await scanSite(db, site(), { runChecks: runChecksStub, manual: true });

  const [scheduled, manualA, manualB] = calls;
  assert.notEqual(manualA.p_scan_id, scheduled.p_scan_id);
  assert.notEqual(manualA.p_idempotency_key, scheduled.p_idempotency_key);
  assert.notEqual(manualA.p_scan_id, manualB.p_scan_id);
  assert.notEqual(manualA.p_idempotency_key, manualB.p_idempotency_key);
});

test("website scans persist a structured per-check list when available", async () => {
  const calls = [];
  const db = createFakeDb({
    tables: { findings: [] },
    rpcHandlers: {
      persist_scan_result: (args) => {
        calls.push(args);
        return { data: args.p_scan_id, error: null };
      },
    },
  });
  const list = [{ key: "tls", label: "TLS certificate", status: "pass", complete: true }];
  await scanSite(db, site(), {
    runChecks: async () => checksResult({ checkResults: { tls: "pass" }, checkResultsList: list }),
  });
  assert.deepEqual(calls[0].p_check_results, list);
});

// ---------------------------------------------------------------------------
// Partial scans resolve fixed findings in checks that completed
// ---------------------------------------------------------------------------

test("partial website scan resolves fixed findings only in completed check groups", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        { id: "f-hsts", site_id: SITE_ID, user_id: "user-a", check_key: "header_hsts", affected_resource: null, status: "open" },
        { id: "f-csp", site_id: SITE_ID, user_id: "user-a", check_key: "header_csp", affected_resource: null, status: "open" },
        { id: "f-dns", site_id: SITE_ID, user_id: "user-a", check_key: "dns_no_spf", affected_resource: null, status: "open" },
        { id: "f-other", site_id: "other-site", user_id: "user-a", check_key: "header_hsts", affected_resource: null, status: "open" },
      ],
    },
    rpcHandlers: { persist_scan_result: (args) => ({ data: args.p_scan_id, error: null }) },
  });

  const out = await scanSite(db, site(), {
    runChecks: async () =>
      checksResult({
        status: "partial",
        checksErrored: 1,
        checkResults: { security_headers: "finding", dns: "error" },
        findings: [{ check_key: "header_csp", title: "Missing CSP", severity: "medium" }],
      }),
  });

  assert.equal(out.status, "partial");
  const byId = Object.fromEntries(db.tables.get("findings").map((f) => [f.id, f.status]));
  assert.equal(byId["f-hsts"], "resolved", "fixed HSTS finding resolves (security_headers completed)");
  assert.equal(byId["f-csp"], "open", "still-observed CSP finding stays open");
  assert.equal(byId["f-dns"], "open", "DNS errored, so its finding is untouched");
  assert.equal(byId["f-other"], "open", "other sites are never touched");
});

test("partial Supabase scan resolves a fixed public bucket even when RLS is not checked", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        { id: "b1", user_id: "user-a", platform: "supabase", connection_id: "c1", resource: "proj", check_key: "supabase_public_storage", affected_resource: "storage:avatars", status: "open" },
        { id: "r1", user_id: "user-a", platform: "supabase", connection_id: "c1", resource: "proj", check_key: "supabase_table_no_rls", affected_resource: "table:todos", status: "open" },
      ],
    },
  });
  const resolved = await resolvePartialScanFindings(db, {
    userId: "user-a",
    platform: "supabase",
    connectionId: "c1",
    resource: "proj",
    checkResults: [
      { key: "storage", status: "pass", complete: true },
      { key: "rls", status: "not_checked", complete: false },
    ],
    findings: [],
  });
  assert.equal(resolved, 1);
  const byId = Object.fromEntries(db.tables.get("findings").map((f) => [f.id, f.status]));
  assert.equal(byId.b1, "resolved");
  assert.equal(byId.r1, "open");
});

test("truncated GitHub scans never resolve file-level findings", () => {
  const groups = completedCheckGroups({
    platform: "github",
    checkResults: [
      { key: "secrets", status: "pass", complete: true },
      { key: "commit_history", status: "pass", complete: true },
      { key: "dependencies", status: "pass", complete: true },
    ],
    coverage: { scanTruncated: true },
  });
  assert.deepEqual([...groups], ["commit_history"]);
});

// ---------------------------------------------------------------------------
// Reopened findings alert again
// ---------------------------------------------------------------------------

test("a regressed (previously resolved) website finding is reported as reopened", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "old",
          site_id: SITE_ID,
          user_id: "user-a",
          check_key: "exposed_env",
          affected_resource: null,
          status: "resolved",
          first_seen_at: "2025-01-01T00:00:00.000Z",
        },
      ],
      user_settings: [],
    },
    rpcHandlers: {
      persist_scan_result: (args, fake) => {
        const rows = fake.tables.get("findings");
        const prior = rows.find((r) => r.id === "old");
        Object.assign(prior, { status: "open", scan_id: args.p_scan_id });
        rows.push({
          id: "new",
          site_id: SITE_ID,
          user_id: "user-a",
          check_key: "header_csp",
          affected_resource: null,
          status: "open",
          scan_id: args.p_scan_id,
          first_seen_at: args.p_finished_at,
        });
        return { data: args.p_scan_id, error: null };
      },
    },
  });

  const out = await scanSite(db, site(), {
    runChecks: async () =>
      checksResult({
        findings: [
          { check_key: "exposed_env", title: "Exposed .env", severity: "critical" },
          { check_key: "header_csp", title: "Missing CSP", severity: "medium" },
        ],
      }),
  });
  assert.equal(out.newFindings, 1);
  assert.equal(out.reopenedFindings, 1);
});

// ---------------------------------------------------------------------------
// Website detectors
// ---------------------------------------------------------------------------

test("detects subdomain takeover via dangling CNAME and short HSTS max-age", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://www.example.com/") {
      return new Response("<html><body>404 There isn't a GitHub Pages site here.</body></html>", {
        status: 404,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=0",
          "content-security-policy": "default-src 'self'; frame-ancestors *",
        },
      });
    }
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      const parsed = new URL(url);
      if (parsed.searchParams.get("type") === "CNAME" && parsed.searchParams.get("name") === "www.example.com") {
        return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 5, data: "old-org.github.io." }] }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ Status: 0, Answer: [{ data: "x" }] }), { status: 200 });
    }
    return new Response(null, { status: 404 });
  };
  try {
    const result = await runChecks("www.example.com");
    const keys = result.findings.map((f) => f.check_key);
    const takeover = result.findings.find((f) => f.check_key === "dns_dangling_cname");
    assert.ok(takeover, `expected dns_dangling_cname, got ${keys.join(", ")}`);
    assert.equal(takeover.severity, "critical");
    assert.match(takeover.evidence, /old-org\.github\.io/);
    assert.ok(keys.includes("hsts_short_max_age"));
    assert.ok(keys.includes("csp_frame_ancestors_wildcard"));
    assert.ok(Array.isArray(result.checkResultsList));
    assert.ok(result.checkResultsList.some((c) => c.key === "dns" && c.label));
  } finally {
    global.fetch = originalFetch;
  }
});

test("a live CNAME target is not reported as a takeover", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://www.example.com/") {
      return new Response("<html><body>Docs home</body></html>", { status: 200 });
    }
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 5, data: "live-org.github.io." }] }), {
        status: 200,
      });
    }
    return new Response(null, { status: 404 });
  };
  try {
    const result = await runChecks("www.example.com");
    assert.ok(!result.findings.some((f) => f.check_key === "dns_dangling_cname"));
  } finally {
    global.fetch = originalFetch;
  }
});

test("RDAP bootstrap errors expire after 60s instead of poisoning the process", async () => {
  const originalFetch = global.fetch;
  let healthy = false;
  global.fetch = async (input) => {
    if (String(input) !== "https://data.iana.org/rdap/dns.json") throw new Error("unexpected");
    if (!healthy) throw new Error("ECONNRESET");
    return new Response(JSON.stringify({ services: [[["io"], ["https://rdap.nic.io/"]]] }), {
      status: 200,
    });
  };
  try {
    resetRdapBootstrapCache();
    assert.equal(await rdapBaseUrl("io", 1_000), null);
    healthy = true;
    assert.equal(await rdapBaseUrl("io", 30_000), null, "error stays cached briefly");
    assert.equal(await rdapBaseUrl("io", 62_000), "https://rdap.nic.io/", "recovers after TTL");
  } finally {
    resetRdapBootstrapCache();
    global.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------
// GitHub footguns
// ---------------------------------------------------------------------------

test("flags SSRF routes that fetch a user-supplied URL", () => {
  const route = `export async function GET(req) {
  const target = new URL(req.url).searchParams.get("url");
  const res = await fetch(target);
  return new Response(await res.text());
}`;
  const out = scanVibeCodeFootguns(route, "app/api/proxy/route.ts", CTX);
  const ssrf = out.find((f) => f.check_key === "ssrf_unvalidated_fetch");
  assert.ok(ssrf);
  assert.equal(ssrf.severity, "high");

  const guarded = route.replace(
    "const res = await fetch(target);",
    "if (!allowedHosts.has(new URL(target).hostname)) throw new Error('blocked');\n  const res = await fetch(target);",
  );
  assert.ok(!scanVibeCodeFootguns(guarded, "app/api/proxy/route.ts", CTX).some((f) => f.check_key === "ssrf_unvalidated_fetch"));
});

test("flags jwt.decode without verification but not when verify is present", () => {
  const bad = `import jwt from "jsonwebtoken";
export function currentUser(req) {
  const claims = jwt.decode(req.headers.authorization.slice(7));
  return claims.sub;
}`;
  const out = scanVibeCodeFootguns(bad, "server/auth.ts", CTX);
  assert.ok(out.some((f) => f.check_key === "jwt_decode_without_verify"));

  const good = bad.replace("jwt.decode(", "jwt.verify(") + "\nconst header = jwt.decode(token, { complete: true });";
  assert.ok(!scanVibeCodeFootguns(good, "server/auth.ts", CTX).some((f) => f.check_key === "jwt_decode_without_verify"));
  assert.equal(scanVibeCodeFootguns(bad, "server/auth.test.ts", CTX).length, 0, "test files are skipped");
});

// ---------------------------------------------------------------------------
// Frontend helpers
// ---------------------------------------------------------------------------

test("legacy object check_results render as a per-check breakdown", () => {
  const list = normalizeCheckResults({ tls: "pass", dns: "error", security_headers: "finding" });
  assert.equal(list.length, 3);
  assert.equal(list.find((c) => c.key === "tls").label, "TLS certificate");
  const summary = scanOutcomeSummary({
    status: "partial",
    check_results: { tls: "pass", dns: "error", security_headers: "finding" },
    checks_total: 3,
  });
  assert.equal(summary.passed, 1);
  assert.equal(summary.error, 1);
  assert.equal(summary.finding, 1);
});

test("new high-impact checks are ship-blockers", () => {
  for (const key of ["dns_dangling_cname", "ssrf_unvalidated_fetch", "jwt_decode_without_verify"]) {
    assert.equal(isShipBlocker({ check_key: key, severity: "medium" }), true, key);
  }
});

// ---------------------------------------------------------------------------
// API: health + account deletion
// ---------------------------------------------------------------------------

async function withServer(app, fn) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("GET /api/health reports database and encryption readiness", async () => {
  const db = createFakeDb({ tables: { sites: [] } });
  const app = createApp({ db, serveStatic: false, logger: { log() {}, error() {} } });
  await withServer(app, async (base) => {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    const json = await res.json();
    assert.equal(json.ok, true);
    assert.equal(json.checks.database, "ok");
    assert.equal(json.checks.encryptionKey, "ok");
  });
});

test("DELETE /api/account requires confirmation and only removes the caller's data", async () => {
  const deletedUsers = [];
  const db = createFakeDb({
    tables: {
      sites: [
        { id: "s-a", user_id: "user-a", domain: "a.com" },
        { id: "s-b", user_id: "user-b", domain: "b.com" },
      ],
      findings: [
        { id: "f-a", user_id: "user-a" },
        { id: "f-b", user_id: "user-b" },
      ],
      github_connections: [{ id: "g-a", user_id: "user-a" }],
      api_keys: [{ id: "k-b", user_id: "user-b" }],
      profiles: [{ id: "user-a" }, { id: "user-b" }],
    },
  });
  db.auth.admin = {
    async deleteUser(id) {
      deletedUsers.push(id);
      return { error: null };
    },
  };
  const app = createApp({ db, serveStatic: false, logger: { log() {}, error() {} } });

  await withServer(app, async (base) => {
    const headers = { authorization: "Bearer token-a", "content-type": "application/json" };
    const rejected = await fetch(`${base}/api/account`, { method: "DELETE", headers, body: "{}" });
    assert.equal(rejected.status, 400);
    assert.equal(db.tables.get("sites").length, 2);

    const ok = await fetch(`${base}/api/account`, {
      method: "DELETE",
      headers,
      body: JSON.stringify({ confirm: "DELETE" }),
    });
    assert.equal(ok.status, 200);
  });

  assert.deepEqual(db.tables.get("sites").map((s) => s.id), ["s-b"]);
  assert.deepEqual(db.tables.get("findings").map((f) => f.id), ["f-b"]);
  assert.equal(db.tables.get("github_connections").length, 0);
  assert.deepEqual(db.tables.get("api_keys").map((k) => k.id), ["k-b"]);
  assert.deepEqual(db.tables.get("profiles").map((p) => p.id), ["user-b"]);
  assert.deepEqual(deletedUsers, ["user-a"]);
});
