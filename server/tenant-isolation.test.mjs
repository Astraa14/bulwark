import test from "node:test";
import assert from "node:assert/strict";

import { createApp } from "./app.mjs";
import { processPlatformScanJob } from "./platform-scans.mjs";
import { createFakeDb } from "./test-support/fake-db.mjs";

const CONN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CONN_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

async function withServer(app, fn) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("platform findings are isolated to authenticated user", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "finding-a",
          user_id: "user-a",
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "A finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
        {
          id: "finding-b",
          user_id: "user-b",
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "B finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-02T00:00:00.000Z",
        },
        {
          id: "site-finding-a",
          user_id: "user-a",
          site_id: "site-a",
          platform: null,
          check_key: "missing_hsts",
          title: "Site finding",
          severity: "medium",
          status: "open",
          last_seen_at: "2026-01-03T00:00:00.000Z",
        },
      ],
      sites: [{ id: "site-a", user_id: "user-a", domain: "example.com" }],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const a = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(a.status, 200);
    const aJson = await a.json();
    assert.deepEqual(aJson.findings.map((finding) => finding.id), ["finding-a"]);

    const b = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-b" },
    });
    const bJson = await b.json();
    assert.deepEqual(bJson.findings.map((finding) => finding.id), ["finding-b"]);

    const crossTenant = await fetch(`${base}/api/explain`, {
      method: "POST",
      headers: { authorization: "Bearer token-a", "content-type": "application/json" },
      body: JSON.stringify({ findingId: "finding-b" }),
    });
    assert.equal(crossTenant.status, 404);
  });
});

test("tenant isolation prevents cross-user access to platform findings", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "finding-a",
          user_id: "user-a",
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "A finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      sites: [],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-b" },
    });
    assert.equal(response.status, 200);
    assert.deepEqual((await response.json()).findings, []);
  });
});

test("tenant isolation allows owner to access their platform findings", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "finding-a",
          user_id: "user-a",
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "A finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      sites: [],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.findings.length, 1);
    assert.equal(json.findings[0].id, "finding-a");
  });
});

test("platform findings without user_id are not visible", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "finding-a",
          user_id: "user-a",
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "A finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
        {
          id: "finding-b",
          user_id: null,
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "B finding",
          severity: "critical",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      sites: [],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.findings.length, 1);
    assert.equal(json.findings[0].id, "finding-a");
  });
});

test("tenant isolation includes user_id in platform finding queries", async () => {
  const db = createFakeDb({
    tables: {
      findings: [],
      sites: [],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(response.status, 200);
  });

  const calls = db.calls;
  const platformQuery = calls.find(
    (call) => call.table === "findings" && call.op === "select",
  );
  assert.ok(platformQuery, "expected a findings select");
  assert.ok(
    platformQuery.filters.some(
      (filter) => filter.op === "eq" && filter.column === "user_id" && filter.value === "user-a",
    ),
    "platform findings must be filtered by the authenticated user",
  );
  assert.ok(
    platformQuery.filters.some(
      (filter) => filter.op === "is" && filter.column === "site_id" && filter.value === null,
    ),
    "platform findings must exclude site findings",
  );
});
test("connection listing is scoped to the caller", async () => {
  const db = createFakeDb({
    tables: {
      github_connections: [
        { id: CONN_A, user_id: "user-a", github_username: "octo", token_encrypted: "x" },
        { id: CONN_B, user_id: "user-b", github_username: "other", token_encrypted: "x" },
      ],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/github`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.deepEqual(json.connections.map((connection) => connection.id), [CONN_A]);
  });
});

test("a cross-tenant GitHub scan returns 404 without scanning", async () => {
  const db = createFakeDb({
    tables: {
      github_connections: [
        { id: CONN_A, user_id: "user-a", github_username: "octo", token_encrypted: "x" },
      ],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/github/${CONN_A}/scan`, {
      method: "POST",
      headers: { authorization: "Bearer token-b", "content-type": "application/json" },
      body: JSON.stringify({ owner: "octo", repo: "repo" }),
    });
    assert.equal(response.status, 404);
  });

  assert.equal(db.rpcCalls.length, 0);
});

test("a cross-tenant Supabase scan returns 404", async () => {
  const db = createFakeDb({
    tables: {
      supabase_connections: [
        { id: CONN_A, user_id: "user-a", project_ref: "abcdefghijklmnop", project_url_encrypted: "x", api_key_encrypted: "x" },
      ],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/supabase/${CONN_A}/scan`, {
      method: "POST",
      headers: { authorization: "Bearer token-b", "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(response.status, 404);
  });

  assert.equal(db.rpcCalls.length, 0);
});

test("a cross-tenant delete does not remove another user's connection", async () => {
  const db = createFakeDb({
    tables: {
      github_connections: [
        { id: CONN_A, user_id: "user-a", github_username: "octo", token_encrypted: "x" },
      ],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/github/${CONN_A}`, {
      method: "DELETE",
      headers: { authorization: "Bearer token-b" },
    });
    assert.equal(response.status, 200);
  });

  assert.equal(db.tables.get("github_connections").length, 1);
});

test("a platform job for another tenant's connection fails without scanning", async () => {
  const db = createFakeDb({
    tables: {
      github_connections: [
        { id: CONN_B, user_id: "user-b", github_username: "other", token_encrypted: "x" },
      ],
      platform_scan_jobs: [],
    },
  });

  const result = await processPlatformScanJob(
    db,
    {
      id: "job-1",
      scan_id: "11111111-1111-4111-8111-111111111111",
      user_id: "user-a",
      platform: "github",
      connection_id: CONN_B,
      resource: "octo/repo",
      commit_sha: null,
      ref: null,
      delivery_id: null,
      attempts: 1,
      run_after: new Date().toISOString(),
    },
    { fetchImpl: async () => { throw new Error("must not fetch"); } },
  );

  assert.equal(result.ok, false);
  assert.match(result.error, /no longer exists/i);
});

test("a null-owner finding is not returned to any user and cannot be explained", async () => {
  const db = createFakeDb({
    tables: {
      findings: [
        {
          id: "legacy-1",
          user_id: null,
          site_id: null,
          platform: "github",
          check_key: "secret_stripe",
          title: "Legacy",
          severity: "high",
          status: "open",
          last_seen_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      sites: [],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const list = await fetch(`${base}/api/findings/platform`, {
      headers: { authorization: "Bearer token-a" },
    });
    assert.equal(list.status, 200);
    assert.deepEqual((await list.json()).findings, []);

    const explain = await fetch(`${base}/api/explain`, {
      method: "POST",
      headers: { authorization: "Bearer token-a", "content-type": "application/json" },
      body: JSON.stringify({ findingId: "legacy-1" }),
    });
    assert.equal(explain.status, 404);
  });
});
