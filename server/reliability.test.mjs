import test from "node:test";
import assert from "node:assert/strict";

process.env.BULWARK_ENCRYPTION_KEY = process.env.BULWARK_ENCRYPTION_KEY || "bulwark-test-encryption-key";

const { scanSite } = await import("./worker.mjs");
const { createApp } = await import("./app.mjs");
const { encrypt } = await import("./crypto.mjs");
const { reclaimStuckPlatformJobs } = await import("./platform-scans.mjs");
const { completedCheckGroups, resolvePartialScanFindings } = await import("./check-groups.mjs");
const { checkUptime, runChecks, rdapBaseUrl, resetRdapBootstrapCache } = await import("./checks.mjs");
const { fileScanPriority, scanGitHubRepo, scanVibeCodeFootguns } = await import("./github.mjs");
const { normalizeCheckResults, scanOutcomeSummary, isShipBlocker } = await import(
  "../src/lib/scanOutcomes.ts"
);
const { createFakeDb } = await import("./test-support/fake-db.mjs");
const { createGitHubFetch } = await import("./test-support/github-fixtures.mjs");

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

// ---------------------------------------------------------------------------
// Lazy SPA chunks, Firebase exposure, modern secrets & anti-flap uptime
// ---------------------------------------------------------------------------

test("follows lazy-loaded SPA chunks to detect leaked DB URIs, Groq keys, and open Firebase DBs", async () => {
  const originalFetch = global.fetch;
  const fakeLookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const groqKey = ["gsk", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2"].join("_");
  const dbUri = ["postgresql://neondb_owner", "RealPass987654@ep-cool-sky.us-east-2.aws.neon.tech/prod"].join(":");
  const placeholderUri = "postgres://user:password@localhost:5432/mydb";

  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(
        '<!doctype html><html><head><script type="module" src="/assets/entry.js"></script></head><body>App</body></html>',
        { status: 200, headers: { "content-type": "text/html" } },
      );
    }
    if (url === "https://example.com/assets/entry.js") {
      return new Response(
        `export const loadAdmin = () => import("./admin-panel.js"); const docExample = "${placeholderUri}";`,
        { status: 200, headers: { "content-type": "application/javascript" } },
      );
    }
    if (url === "https://example.com/assets/admin-panel.js") {
      return new Response(
        `const fb = { authDomain: "vibe-fb-123.firebaseapp.com", databaseURL: "https://vibe-fb-123-default-rtdb.firebaseio.com" }; const groq = "${groqKey}"; const db = "${dbUri}";`,
        { status: 200, headers: { "content-type": "application/javascript" } },
      );
    }
    if (url === "https://vibe-fb-123-default-rtdb.firebaseio.com/.json?shallow=true") {
      return new Response(JSON.stringify({ users: true, orders: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (
      url ===
      "https://firestore.googleapis.com/v1/projects/vibe-fb-123/databases/(default)/documents/users?pageSize=1&mask.fieldPaths=__name__"
    ) {
      return new Response(
        JSON.stringify({ documents: [{ name: "projects/vibe-fb-123/databases/(default)/documents/users/u1" }] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(null, { status: 404 });
  };

  try {
    const result = await runChecks("example.com", { lookup: fakeLookup });
    const keys = result.findings.map((f) => f.check_key);
    assert.ok(keys.includes("secret_groq"), "should detect Groq key inside lazy chunk");
    assert.ok(keys.includes("secret_database_url"), "should detect real database URI inside lazy chunk");

    const dbFindings = result.findings.filter((f) => f.check_key === "secret_database_url");
    assert.equal(dbFindings.length, 1, "placeholder localhost URI must not trigger a second finding");

    const fbFindings = result.findings.filter((f) => f.check_key === "site_firebase_open_db");
    assert.equal(fbFindings.length, 2, "should flag both open Realtime DB and open Firestore collection");
  } finally {
    global.fetch = originalFetch;
  }
});

test("two-strike uptime check recovers from a single transient failure without false outage", async () => {
  const originalFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    if (calls === 1) throw new Error("ETIMEDOUT");
    return new Response("<html><body>healthy</body></html>", {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  };
  try {
    const out = await checkUptime("example.com", {
      retryDelayMs: 5,
      lookup: async () => [{ address: "93.184.216.34", family: 4 }],
    });
    assert.equal(out.ok, true);
    assert.equal(out.attempts, 2);
    assert.equal(calls, 2);
  } finally {
    global.fetch = originalFetch;
  }
});

test("sends an all-clear recovery alert when a site_unreachable finding clears", async () => {
  const originalFetch = global.fetch;
  const slackPayloads = [];
  const slackUrl = ["https://hooks.slack.com", "services", "T00000000", "B00000000", "XXXXXXXXXXXXXXXXXXXXXXXX"].join("/");

  global.fetch = async (input, init = {}) => {
    if (String(input) === slackUrl) {
      slackPayloads.push(JSON.parse(String(init.body)));
      return new Response("ok", { status: 200 });
    }
    throw new Error(`Unexpected fetch: ${input}`);
  };

  try {
    const db = createFakeDb({
      tables: {
        findings: [
          {
            id: "f-down",
            site_id: SITE_ID,
            user_id: "user-a",
            check_key: "site_unreachable",
            affected_resource: null,
            status: "open",
          },
        ],
        user_settings: [
          {
            user_id: "user-a",
            alerts_enabled: true,
            slack_webhook_encrypted: encrypt(slackUrl),
            slack_min_severity: "high",
          },
        ],
        alert_deliveries: [],
      },
      rpcHandlers: {
        persist_scan_result: (args) => ({ data: args.p_scan_id, error: null }),
      },
    });

    const out = await scanSite(db, site(), {
      runChecks: async () => checksResult({ status: "completed", httpStatus: 200, responseMs: 120 }),
    });
    assert.equal(out.recovered, true);
    assert.equal(slackPayloads.length, 1);
    assert.match(slackPayloads[0].text, /RECOVERED.*example\.com/);
  } finally {
    global.fetch = originalFetch;
  }
});

test("reclaims stale running platform_scan_jobs and fails exhausted ones", async () => {
  const staleIso = new Date(Date.now() - 25 * 60_000).toISOString();
  const freshIso = new Date(Date.now() - 2 * 60_000).toISOString();
  const db = createFakeDb({
    tables: {
      platform_scan_jobs: [
        { id: "j-retry", status: "running", attempts: 2, started_at: staleIso },
        { id: "j-exhausted", status: "running", attempts: 5, started_at: staleIso },
        { id: "j-fresh", status: "running", attempts: 1, started_at: freshIso },
      ],
    },
  });

  const count = await reclaimStuckPlatformJobs(db, { staleMinutes: 15 });
  assert.equal(count, 2);
  const byId = Object.fromEntries(db.tables.get("platform_scan_jobs").map((j) => [j.id, j.status]));
  assert.equal(byId["j-retry"], "queued");
  assert.equal(byId["j-exhausted"], "failed");
  assert.equal(byId["j-fresh"], "running");
});

// ---------------------------------------------------------------------------
// GitHub priority sorting, rate-limit retry, SQL/exec injection & Firestore rules
// ---------------------------------------------------------------------------

test("fileScanPriority ranks critical configs, lockfiles, migrations, and routes ahead of UI and docs", () => {
  const unordered = [
    "docs/setup.md",
    "src/components/Button.tsx",
    "app/api/checkout/route.ts",
    "supabase/migrations/001_init.sql",
    "package-lock.json",
    "firestore.rules",
  ];
  const sorted = [...unordered].sort((a, b) => fileScanPriority(a) - fileScanPriority(b));
  assert.deepEqual(sorted, [
    "firestore.rules",
    "package-lock.json",
    "supabase/migrations/001_init.sql",
    "app/api/checkout/route.ts",
    "src/components/Button.tsx",
    "docs/setup.md",
  ]);
});

test("flags raw SQL interpolation, shell command injection, and open Firestore rules while retrying GitHub 429s", async () => {
  const fixture = createGitHubFetch({
    files: [
      {
        path: "firestore.rules",
        content: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}`,
      },
      {
        path: "app/api/convert/route.ts",
        content: [
          'import { execSync } from "node:child_process";',
          "export async function POST(req: Request) {",
          "  const { file, email } = await req.json();",
          "  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);",
          "  execSync(`ffmpeg -i ${file} out.mp4`);",
          "  return Response.json({ rows });",
          "}",
        ].join("\n"),
      },
    ],
  });

  let saw429 = false;
  const flakyFetch = async (input, init) => {
    if (!saw429 && String(input).includes("/git/trees/")) {
      saw429 = true;
      return new Response("rate limited", {
        status: 429,
        headers: { "retry-after": "0", "x-ratelimit-remaining": "0" },
      });
    }
    return fixture.fetchImpl(input, init);
  };

  const res = await scanGitHubRepo("ghp_faketoken1234567890", "octocat", "Hello-World", {
    fetchImpl: flakyFetch,
    osvFetchImpl: async () => new Response(JSON.stringify({ results: [] }), { status: 200 }),
  });

  assert.equal(saw429, true);
  assert.equal(res.status, "completed");
  const keys = res.findings.map((f) => f.check_key);
  assert.ok(keys.includes("firestore_open_rules"), "should detect open Firestore rules");
  assert.ok(keys.includes("sql_raw_interpolation"), "should detect interpolated raw SQL");
  assert.ok(keys.includes("command_injection_exec"), "should detect shell command injection");
});
