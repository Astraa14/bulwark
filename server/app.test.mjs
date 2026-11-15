import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

process.env.BULWARK_ENCRYPTION_KEY = "bulwark-test-encryption-key";

const { createApp } = await import("./app.mjs");
const { encrypt } = await import("./crypto.mjs");
const { createFakeDb } = await import("./test-support/fake-db.mjs");
const { createGitHubFetch, commitSha } = await import("./test-support/github-fixtures.mjs");
const { enqueuePlatformScan } = await import("./platform-scans.mjs");

const SECRET = "a-very-long-webhook-test-secret";
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

function signature(raw, secret = SECRET) {
  return `sha256=${createHmac("sha256", secret).update(raw).digest("hex")}`;
}

function connection(overrides = {}) {
  return {
    id: CONN_A,
    user_id: "user-a",
    github_username: "octo",
    token_encrypted: encrypt("ghp_faketoken1234567890"),
    webhook_secret_encrypted: encrypt(SECRET),
    ...overrides,
  };
}

function pushBody(after = commitSha("push-1"), overrides = {}) {
  return JSON.stringify({
    ref: "refs/heads/main",
    after,
    repository: { name: "repo", owner: { login: "octo" } },
    ...overrides,
  });
}

function repoAccessFetch(status = 200) {
  return async (input) => {
    const url = String(input);
    if (url === "https://api.github.com/repos/octo/repo") {
      return new Response(JSON.stringify({ id: 1 }), {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };
}

function webhookRequest(base, { body, secret = SECRET, event = "push", delivery = "delivery-1", connectionId = CONN_A }) {
  return fetch(`${base}/api/webhooks/github${connectionId ? `/${connectionId}` : ""}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-hub-signature-256": signature(body, secret),
      "x-github-event": event,
      "x-github-delivery": delivery,
    },
    body,
  });
}

test("a signed push queues exactly one job for the exact commit", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = pushBody();

  await withServer(app, async (base) => {
    const response = await webhookRequest(base, { body });
    assert.equal(response.status, 202);
    const json = await response.json();
    assert.equal(json.queued, true);
  });

  const jobs = db.tables.get("platform_scan_jobs");
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].user_id, "user-a");
  assert.equal(jobs[0].platform, "github");
  assert.equal(jobs[0].connection_id, CONN_A);
  assert.equal(jobs[0].resource, "octo/repo");
  assert.equal(jobs[0].ref, "refs/heads/main");
  assert.equal(jobs[0].commit_sha, commitSha("push-1"));
  assert.equal(jobs[0].delivery_id, "delivery-1");
  assert.equal(jobs[0].status, "queued");
  assert.match(
    jobs[0].scan_id,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    "the job scan id must be a UUID",
  );
});

test("enqueuePlatformScan rejects a non-UUID scan id before inserting", async () => {
  const db = createFakeDb({ tables: { platform_scan_jobs: [] } });

  await assert.rejects(
    () =>
      enqueuePlatformScan(db, {
        userId: "user-a",
        platform: "github",
        connectionId: CONN_A,
        resource: "octo/repo",
        scanId: "user-a:octo/repo:abc123",
      }),
    /must be a UUID/,
  );

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("a repeated delivery is a no-op, not a second job", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = pushBody();

  await withServer(app, async (base) => {
    const first = await webhookRequest(base, { body, delivery: "same-delivery" });
    assert.equal(first.status, 202);
    const second = await webhookRequest(base, { body, delivery: "same-delivery" });
    assert.equal(second.status, 200);
    const json = await second.json();
    assert.equal(json.duplicate, true);
    assert.equal(json.queued, false);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 1);
});

test("an invalid signature is rejected before any work is queued", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = pushBody();

  await withServer(app, async (base) => {
    const response = await webhookRequest(base, { body, secret: "wrong-secret" });
    assert.equal(response.status, 401);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("a malformed or unknown connection id in the webhook URL is rejected cleanly", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = pushBody();

  await withServer(app, async (base) => {
    const malformed = await webhookRequest(base, { body, connectionId: "not-a-uuid" });
    assert.equal(malformed.status, 401);

    const unknown = await webhookRequest(base, {
      body,
      connectionId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    });
    assert.equal(unknown.status, 401);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("a signed delivery for a repository this connection cannot read is refused", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(404), serveStatic: false });

  await withServer(app, async (base) => {
    const response = await webhookRequest(base, { body: pushBody() });
    assert.equal(response.status, 403);
    const json = await response.json();
    assert.match(json.error, /not authorized/i);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("branch deletion and non-push events are acknowledged without a job", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });

  await withServer(app, async (base) => {
    const deleted = await webhookRequest(base, {
      body: pushBody("0".repeat(40), { deleted: true }),
      delivery: "delete-1",
    });
    assert.equal(deleted.status, 200);
    assert.equal((await deleted.json()).ignored, true);

    const ping = await webhookRequest(base, {
      body: JSON.stringify({ zen: "hello" }),
      event: "ping",
      delivery: "ping-1",
    });
    assert.equal(ping.status, 200);
    assert.equal((await ping.json()).ping, true);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("oversized webhook bodies are rejected with JSON 413", async () => {
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = `{"padding":"${"x".repeat(1_048_600)}"}`;

  await withServer(app, async (base) => {
    const response = await webhookRequest(base, { body });
    assert.equal(response.status, 413);
    const json = await response.json();
    assert.match(json.error, /too large/i);
  });

  assert.equal(db.tables.get("platform_scan_jobs").length, 0);
});

test("a shared webhook secret is ambiguous and requires the per-connection URL", async () => {
  const db = createFakeDb({
    tables: {
      github_connections: [
        connection(),
        connection({ id: CONN_B, user_id: "user-b", github_username: "other" }),
      ],
      platform_scan_jobs: [],
    },
  });
  const app = createApp({ db, fetchImpl: repoAccessFetch(), serveStatic: false });
  const body = pushBody();

  await withServer(app, async (base) => {
    const ambiguous = await webhookRequest(base, { body, connectionId: null });
    assert.equal(ambiguous.status, 401);

    const precise = await webhookRequest(base, { body, connectionId: CONN_B });
    assert.equal(precise.status, 202);
  });

  const jobs = db.tables.get("platform_scan_jobs");
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].user_id, "user-b");
});

test("platform findings are scoped to the authenticated owner", async () => {
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

test("a manual GitHub scan persists through the owner-scoped RPC, not direct inserts", async () => {
  const fixture = createGitHubFetch({
    owner: "octo",
    repo: "repo",
    files: [{ path: "README.md", content: "# hello" }],
  });
  const rpcCalls = [];
  const db = createFakeDb({
    tables: { github_connections: [connection()], platform_scan_jobs: [] },
    rpcHandlers: {
      persist_platform_scan_result: (args) => {
        rpcCalls.push(args);
        return {
          data: {
            scanId: args.p_scan_id,
            duplicate: false,
            newFindings: [
              {
                id: "new-1",
                check_key: "secret_stripe",
                title: "Stripe key",
                severity: "critical",
                detail: "detail",
                url: "https://example.com",
              },
            ],
            reopenedFindings: [],
          },
          error: null,
        };
      },
    },
  });
  const app = createApp({ db, fetchImpl: fixture.fetchImpl, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/github/${CONN_A}/scan`, {
      method: "POST",
      headers: { authorization: "Bearer token-a", "content-type": "application/json" },
      body: JSON.stringify({ owner: "octo", repo: "repo" }),
    });
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.ok, true);
    assert.equal(json.findings, 0);
    assert.equal(json.newFindings, 1);
  });

  assert.equal(rpcCalls.length, 1);
  assert.equal(rpcCalls[0].p_user_id, "user-a");
  assert.equal(rpcCalls[0].p_platform, "github");
  assert.equal(rpcCalls[0].p_connection_id, CONN_A);
  assert.equal(rpcCalls[0].p_resource, "octo/repo");
  assert.equal(
    db.calls.some((call) => call.table === "findings" && call.op === "insert"),
    false,
    "findings must be written by the scoped RPC",
  );
});

test("a manual scan is refused when the token cannot read the repository", async () => {
  const fixture = createGitHubFetch({ owner: "octo", repo: "repo", repoStatus: 404 });
  const db = createFakeDb({ tables: { github_connections: [connection()] } });
  const app = createApp({ db, fetchImpl: fixture.fetchImpl, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/connections/github/${CONN_A}/scan`, {
      method: "POST",
      headers: { authorization: "Bearer token-a", "content-type": "application/json" },
      body: JSON.stringify({ owner: "octo", repo: "repo" }),
    });
    assert.equal(response.status, 403);
  });

  assert.equal(db.rpcCalls.length, 0);
});
