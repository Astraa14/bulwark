import test from "node:test";
import assert from "node:assert/strict";

import { isBlockedOutboundHost, runChecks } from "./checks.mjs";

test("blocks localhost and private IP ranges", () => {
  assert.equal(isBlockedOutboundHost("localhost"), true);
  assert.equal(isBlockedOutboundHost("127.0.0.1"), true);
  assert.equal(isBlockedOutboundHost("10.0.0.5"), true);
  assert.equal(isBlockedOutboundHost("172.16.0.1"), true);
  assert.equal(isBlockedOutboundHost("example.com"), false);
});

test("failed site scans stay failed and do not look clean", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => {
    throw new Error("ECONNREFUSED");
  };

  try {
    const result = await runChecks("localhost");
    assert.equal(result.status, "failed");
    assert.equal(result.checksErrored, 1);
    assert.equal(result.checksPassed, 0);
  } finally {
    global.fetch = originalFetch;
  }
});

