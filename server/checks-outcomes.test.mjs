import test from "node:test";
import assert from "node:assert/strict";
import {
  runChecks,
  isBlockedOutboundHost,
  isUnsafeIp,
  hasUnsafeDns,
  ensureSafeFetchUrl,
} from "./checks.mjs";

// ---------------------------------------------------------------------------
// SSRF / network-safety unit tests (no real network required)
// ---------------------------------------------------------------------------

test("blocks localhost and private IP ranges", () => {
  assert.equal(isBlockedOutboundHost("localhost"), true);
  assert.equal(isBlockedOutboundHost("127.0.0.1"), true);
  assert.equal(isBlockedOutboundHost("10.0.0.5"), true);
  assert.equal(isBlockedOutboundHost("172.16.0.1"), true);
  assert.equal(isBlockedOutboundHost("192.168.1.1"), true);
  assert.equal(isBlockedOutboundHost("example.com"), false);
  assert.equal(isBlockedOutboundHost("intranet.local"), true);
});

test("isUnsafeIp flags private and loopback addresses", () => {
  assert.equal(isUnsafeIp("127.0.0.1"), true);
  assert.equal(isUnsafeIp("10.0.0.5"), true);
  assert.equal(isUnsafeIp("172.16.0.1"), true);
  assert.equal(isUnsafeIp("192.168.1.1"), true);
  assert.equal(isUnsafeIp("::1"), true);
  assert.equal(isUnsafeIp("93.184.216.34"), false); // example.com
});

// ---------------------------------------------------------------------------
// Critical: network failure must never produce a "pass" outcome
// ---------------------------------------------------------------------------

test("total network failure fails the scan, never reports clean", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => {
    throw new Error("ECONNREFUSED");
  };
  try {
    const result = await runChecks("localhost");
    assert.equal(result.status, "failed");
    assert.equal(result.checkResults.site_uptime, "error");
    assert.equal(result.checksErrored, 1);
    assert.equal(result.checksPassed, 0);
    assert.ok(result.findings.some((f) => f.check_key === "site_unreachable"));
  } finally {
    global.fetch = originalFetch;
  }
});

test("exposed-files probe failure records error, not pass", async () => {
  const originalFetch = global.fetch;
  const blockedPaths = ["/.env", "/.git/config", "/backup.sql", "/phpinfo.php"];
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>hello</body></html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    }
    if (blockedPaths.some((p) => url.endsWith(p))) {
      throw new Error("ECONNREFUSED");
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    // The exposed_files check attempted network probes and they failed -> error, never pass.
    assert.equal(result.checkResults.exposed_files, "error");
    assert.notEqual(result.status, "completed");
    // No pass should be inferred from an empty exposed_files findings array.
    assert.equal(result.checkResults.exposed_files, "error");
  } finally {
    global.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------
// Critical: SSRF protection applies to every request path
// ---------------------------------------------------------------------------

test("ensureSafeFetchUrl rejects unsupported schemes", async () => {
  await assert.rejects(() => ensureSafeFetchUrl("ftp://example.com/"), /Blocked/);
});

test("ensureSafeFetchUrl rejects non-web ports", async () => {
  await assert.rejects(() => ensureSafeFetchUrl("http://example.com:22/"), /Blocked/);
});

test("redirect to private address blocks the scan, never reports clean", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(null, {
        status: 302,
        headers: { location: "http://127.0.0.1/" },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "failed");
    assert.equal(result.checkResults.site_uptime, "error");
  } finally {
    global.fetch = originalFetch;
  }
});
