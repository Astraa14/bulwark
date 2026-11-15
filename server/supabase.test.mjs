import test from "node:test";
import assert from "node:assert/strict";
import { scanSupabaseProject } from "./supabase.mjs";

const PROJECT_URL = "https://abcdefghijklmnop.supabase.co";

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

const ANON_KEY = `${base64url({ alg: "HS256", typ: "JWT" })}.${base64url({ role: "anon" })}.signature`;
const SERVICE_KEY = `${base64url({ alg: "HS256", typ: "JWT" })}.${base64url({ role: "service_role" })}.signature`;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function createSupabaseFetch({ buckets = [], bucketsStatus = 200, rls = [], rlsStatus = 200 } = {}) {
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, method: init.method ?? "GET", body: init.body ?? null });

    if (url === `${PROJECT_URL}/rest/v1/`) return json({});
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

  const noRls = result.findings.find((finding) => finding.check_key === "supabase_table_no_rls");
  assert.ok(noRls);
  assert.equal(noRls.severity, "high");
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
