import test from "node:test";
import assert from "node:assert/strict";
import { scanSupabaseProject } from "./supabase.mjs";

const PROJECT_URL = "https://abcdefghijklmnop.supabase.co";

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

const ANON_KEY = `${base64url({ alg: "HS256", typ: "JWT" })}.${base64url({ role: "anon" })}.signature`;
const SERVICE_KEY = `${base64url({ alg: "HS256", typ: "JWT" })}.${base64url({ role: "service_role" })}.signature`;

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

function createSupabaseFetch({
  openapi = {},
  headCounts = {},
  buckets = [],
  bucketsStatus = 200,
  rls = [],
  rlsStatus = 200,
} = {}) {
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    const method = init.method ?? "GET";
    requests.push({ url, method, body: init.body ?? null });

    if (url === `${PROJECT_URL}/rest/v1/`) return json(openapi);
    if (method === "HEAD" && url.startsWith(`${PROJECT_URL}/rest/v1/`)) {
      const table = decodeURIComponent(url.slice(`${PROJECT_URL}/rest/v1/`.length).split("?")[0]);
      const count = headCounts[table] ?? 0;
      return new Response(null, {
        status: 200,
        headers: { "content-range": count > 0 ? `0-0/${count}` : `*/0` },
      });
    }
    if (url === `${PROJECT_URL}/storage/v1/bucket`) {
      return bucketsStatus === 200 ? json(buckets) : json({ message: "denied" }, bucketsStatus);
    }
    if (url === `${PROJECT_URL}/rest/v1/rpc/bulwark_check_rls`) {
      return rlsStatus === 200 ? json(rls) : json({ message: "missing" }, rlsStatus);
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };

  return { fetchImpl, requests };
}

const lookup = async () => [{ address: "93.184.216.34", family: 4 }];

function run(fixture) {
  return scanSupabaseProject(PROJECT_URL, ANON_KEY, {
    fetchImpl: fixture.fetchImpl,
    lookup,
  });
}

test("flags a public storage bucket and a table without RLS", async () => {
  const fixture = createSupabaseFetch({
    buckets: [
      { name: "avatars", public: true },
      { name: "private", public: false },
    ],
    rls: [
      {
        table_name: "todos",
        row_security_enabled: false,
        policy_count: 0,
        has_permissive_policy: false,
      },
    ],
  });

  const result = await run(fixture);

  const storage = result.findings.find((finding) => finding.check_key === "supabase_public_storage");
  assert.ok(storage);
  assert.equal(storage.severity, "high");
  assert.equal(storage.affected_resource, "storage:avatars");
  assert.equal(
    storage.url,
    "https://supabase.com/dashboard/project/abcdefghijklmnop/storage/buckets/avatars",
  );

  const noRls = result.findings.find((finding) => finding.check_key === "supabase_table_no_rls");
  assert.ok(noRls);
  assert.equal(noRls.severity, "high");
  assert.equal(noRls.url, "https://supabase.com/dashboard/project/abcdefghijklmnop/editor");
  assert.match(noRls.what_it_does_not_prove, /does not prove/i);

  assert.equal(result.coverage.storageChecked, true);
  assert.equal(result.coverage.rlsChecked, true);
  assert.equal(result.coverage.policyAnalysis, "heuristic");
  assert.equal(result.status, "completed");
});

test("treats a literal-true policy as a heuristic, not proof of exposure", async () => {
  const fixture = createSupabaseFetch({
    buckets: [],
    rls: [
      {
        table_name: "profiles",
        row_security_enabled: true,
        policy_count: 1,
        has_permissive_policy: true,
      },
    ],
  });

  const result = await run(fixture);

  const finding = result.findings.find(
    (entry) => entry.check_key === "supabase_table_permissive_policy",
  );
  assert.ok(finding);
  assert.equal(finding.severity, "medium");
  assert.equal(finding.confidence, "low");
  assert.match(finding.detail, /heuristic/i);
  assert.match(finding.what_it_does_not_prove, /does not by itself prove/i);
});

test("RLS with no policies is reported as deny-by-default, not exposure", async () => {
  const fixture = createSupabaseFetch({
    buckets: [],
    rls: [
      {
        table_name: "audit_log",
        row_security_enabled: true,
        policy_count: 0,
        has_permissive_policy: false,
      },
    ],
  });

  const result = await run(fixture);

  const finding = result.findings.find(
    (entry) => entry.check_key === "supabase_table_no_policies",
  );
  assert.ok(finding);
  assert.equal(finding.severity, "low");
  assert.match(finding.detail, /deny-by-default/i);
});

test("a clean project has no RLS findings and no false 'safe' claim", async () => {
  const fixture = createSupabaseFetch({
    buckets: [{ name: "private", public: false }],
    rls: [
      {
        table_name: "profiles",
        row_security_enabled: true,
        policy_count: 2,
        has_permissive_policy: false,
      },
    ],
  });

  const result = await run(fixture);

  assert.equal(result.findings.length, 0);
  assert.equal(result.status, "completed");
  assert.ok(result.coverage.notes.some((note) => /heuristic/i.test(note)));
});

test("storage permission denial is visible as not checked", async () => {
  const fixture = createSupabaseFetch({
    bucketsStatus: 403,
    rls: [
      {
        table_name: "profiles",
        row_security_enabled: true,
        policy_count: 1,
        has_permissive_policy: false,
      },
    ],
  });

  const result = await run(fixture);

  const storage = result.checkResults.find((check) => check.key === "storage");
  assert.equal(storage.status, "not_checked");
  assert.match(storage.error, /cannot list storage buckets/i);
  assert.equal(result.coverage.storageChecked, false);
  assert.ok(result.coverage.notes.some((note) => /not checked/i.test(note)));
  assert.equal(result.status, "partial");
});

test("a missing RLS helper says 'not checked', not 'RLS is fine'", async () => {
  const fixture = createSupabaseFetch({
    buckets: [{ name: "private", public: false }],
    rlsStatus: 404,
  });

  const result = await run(fixture);

  const rls = result.checkResults.find((check) => check.key === "rls");
  assert.equal(rls.status, "not_checked");
  const finding = result.findings.find(
    (entry) => entry.check_key === "supabase_rls_not_checked",
  );
  assert.ok(finding);
  assert.equal(finding.severity, "info");
  assert.equal(finding.url, "https://supabase.com/dashboard/project/abcdefghijklmnop/sql/new");
  assert.match(finding.detail, /not checked, not as safe/i);
  assert.equal(result.coverage.rlsChecked, false);
  assert.equal(result.status, "partial");
});

test("rejects a service-role key instead of using it", async () => {
  let called = false;
  const result = await scanSupabaseProject(PROJECT_URL, SERVICE_KEY, {
    fetchImpl: async () => {
      called = true;
      return json({});
    },
    lookup,
  });

  assert.equal(result.status, "failed");
  assert.match(result.error, /service-role key/i);
  assert.equal(called, false);
});

test("rejects sb_secret keys instead of using them", async () => {
  let called = false;
  const result = await scanSupabaseProject(PROJECT_URL, "sb_secret_abcdefghijklmnop", {
    fetchImpl: async () => {
      called = true;
      return json({});
    },
    lookup,
  });

  assert.equal(result.status, "failed");
  assert.equal(called, false);
});

test("rejects an arbitrary project URL before resolving DNS", async () => {
  let lookedUp = false;
  const result = await scanSupabaseProject("https://evil.example.com", ANON_KEY, {
    fetchImpl: async () => json({}),
    lookup: async () => {
      lookedUp = true;
      return [{ address: "93.184.216.34", family: 4 }];
    },
  });

  assert.equal(result.status, "failed");
  assert.match(result.error, /supabase\.co/i);
  assert.equal(lookedUp, false);
});

test("detects anon-readable sensitive tables and exposed RPCs with zero SQL helper installed", async () => {
  const fixture = createSupabaseFetch({
    openapi: {
      swagger: "2.0",
      paths: {
        "/profiles": { get: {}, post: {} },
        "/posts": { get: {} },
        "/rpc/admin_delete_user": { post: {} },
        "/rpc/bulwark_check_rls": { post: {} },
      },
    },
    headCounts: {
      profiles: 42,
      posts: 0,
    },
    bucketsStatus: 403,
    rlsStatus: 404,
  });

  const result = await run(fixture);

  const readable = result.findings.find((f) => f.check_key === "supabase_anon_readable_table");
  assert.ok(readable, "should flag anon-readable profiles table even without SQL helper");
  assert.equal(readable.severity, "critical");
  assert.equal(readable.affected_resource, "anon_table:profiles");
  assert.match(readable.title, /42 rows/);
  assert.ok(
    fixture.requests.some((r) => r.method === "HEAD" && r.url.includes("/rest/v1/profiles?limit=1")),
    "uses zero-row HEAD count probe without reading row data",
  );

  const rpc = result.findings.find((f) => f.check_key === "supabase_anon_rpc_exposed");
  assert.ok(rpc, "should flag exposed custom RPC excluding bulwark_check_rls");
  assert.equal(rpc.severity, "high");
  assert.match(rpc.evidence, /admin_delete_user/);
  assert.doesNotMatch(rpc.evidence, /bulwark_check_rls/);
  assert.equal(result.coverage.anonTablesExposed, 2);
  assert.equal(result.coverage.anonReadableTables, 1);
  assert.equal(result.coverage.anonRpcsExposed, 1);
});
