import test from "node:test";
import assert from "node:assert/strict";

import { ensureSafeFetchUrl, hasUnsafeDns } from "./checks.mjs";
import { sendSlack } from "./alerts.mjs";
import {
  assertSupabaseProjectUrl,
  normalizeSupabaseConnection,
} from "./supabase-config.mjs";
import { createApp } from "./app.mjs";
import { createFakeDb } from "./test-support/fake-db.mjs";

const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];

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

// ---------------------------------------------------------------------------
// Outbound fetch guard
// ---------------------------------------------------------------------------

test("ensureSafeFetchUrl rejects private and loopback literals", async () => {
  await assert.rejects(() => ensureSafeFetchUrl("http://10.0.0.5/", { lookup: publicLookup }), /Blocked/);
  await assert.rejects(() => ensureSafeFetchUrl("http://127.0.0.1/", { lookup: publicLookup }), /Blocked/);
  await assert.rejects(() => ensureSafeFetchUrl("http://[::1]/", { lookup: publicLookup }), /Blocked/);
  await assert.rejects(() => ensureSafeFetchUrl("http://169.254.169.254/", { lookup: publicLookup }), /Blocked/);
});

test("ensureSafeFetchUrl blocks unspecified, CGNAT, reserved and multicast ranges", async () => {
  const blocked = [
    "http://0.0.0.0/",
    "http://0/",
    "http://[::]/",
    "http://100.64.0.1/",
    "http://192.0.0.10/",
    "http://198.18.0.1/",
    "http://224.0.0.1/",
    "http://240.0.0.1/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://metadata/",
  ];

  for (const url of blocked) {
    await assert.rejects(() => ensureSafeFetchUrl(url, { lookup: publicLookup }), /Blocked/, url);
  }

  await assert.rejects(
    () =>
      ensureSafeFetchUrl("https://rebind.example.com/", {
        lookup: async () => [{ address: "0.0.0.0", family: 4 }],
      }),
    /Blocked/,
  );
});

test("ensureSafeFetchUrl rejects a hostname that resolves to a private address", async () => {
  await assert.rejects(
    () => ensureSafeFetchUrl("https://rebind.example.com/", {
      lookup: async () => [{ address: "10.1.2.3", family: 4 }],
    }),
    /Blocked/,
  );
});

test("ensureSafeFetchUrl accepts a public host on an allowed port", async () => {
  const url = await ensureSafeFetchUrl("https://example.com/path", { lookup: publicLookup });
  assert.equal(url, "https://example.com/path");
});

test("hasUnsafeDns is true for private answers and DNS failure", async () => {
  assert.equal(
    await hasUnsafeDns("private.example.com", async () => [{ address: "192.168.1.1" }]),
    true,
  );
  assert.equal(
    await hasUnsafeDns("broken.example.com", async () => {
      throw new Error("ENOTFOUND");
    }),
    true,
  );
});

// ---------------------------------------------------------------------------
// Supabase URL allow-list
// ---------------------------------------------------------------------------

test("assertSupabaseProjectUrl rejects non-canonical origins", () => {
  const cases = [
    "http://abcdefghijklmnop.supabase.co",
    "https://abcdefghijklmnop.supabase.co:8443",
    "https://user:pass@abcdefghijklmnop.supabase.co",
    "https://abcdefghijklmnop.supabase.co/rest/v1",
    "https://abcdefghijklmnop.supabase.co/?x=1",
    "https://evil.example.com",
    "https://abcdefghijklmnop.supabase.co.evil.example.com",
  ];

  for (const value of cases) {
    assert.throws(() => assertSupabaseProjectUrl(value), /Supabase project URL/, value);
  }
});

test("normalizeSupabaseConnection derives the canonical URL and rejects a mismatch", () => {
  const normalized = normalizeSupabaseConnection({
    projectRef: "ABCDEFGHIJKLMNOP",
    projectUrl: "https://abcdefghijklmnop.supabase.co",
    apiKey: "sb_publishable_test",
  });
  assert.equal(normalized.projectUrl, "https://abcdefghijklmnop.supabase.co");

  assert.throws(
    () =>
      normalizeSupabaseConnection({
        projectRef: "abcdefghijklmnop",
        projectUrl: "https://zzzzzzzzzzzzzzzz.supabase.co",
        apiKey: "sb_publishable_test",
      }),
    /does not match/,
  );
});

// ---------------------------------------------------------------------------
// Alert egress
// ---------------------------------------------------------------------------

test("sendSlack refuses a non-Slack URL before fetching", async () => {
  const originalFetch = global.fetch;
  let called = false;
  global.fetch = async () => {
    called = true;
    return new Response("ok");
  };

  try {
    await assert.rejects(
      () => sendSlack("http://169.254.169.254/latest/meta-data/", "x"),
      /non-Slack webhook URL/,
    );
    assert.equal(called, false);
  } finally {
    global.fetch = originalFetch;
  }
});

test("POST /api/alerts/test rejects an arbitrary webhookUrl", async () => {
  const db = createFakeDb({
    tables: {
      user_settings: [
        {
          user_id: "user-a",
          slack_webhook_url: null,
          slack_min_severity: "high",
          alerts_enabled: true,
        },
      ],
    },
  });
  const app = createApp({ db, serveStatic: false });

  await withServer(app, async (base) => {
    const response = await fetch(`${base}/api/alerts/test`, {
      method: "POST",
      headers: { authorization: "Bearer token-a", "content-type": "application/json" },
      body: JSON.stringify({ webhookUrl: "http://127.0.0.1:8443/admin" }),
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /Slack incoming webhook/i);
  });
});