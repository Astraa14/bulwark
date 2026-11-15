import test from "node:test";
import assert from "node:assert/strict";
import {
  UUID_RE,
  assertScanId,
  uuidv5,
  websiteScanIdentity,
  SCAN_ID_NAMESPACE,
  IDEMPOTENCY_NAMESPACE,
} from "./scan-id.mjs";

test("uuidv5 is deterministic and shaped like a v5 UUID", () => {
  const first = uuidv5("example", SCAN_ID_NAMESPACE);
  const second = uuidv5("example", SCAN_ID_NAMESPACE);

  assert.equal(first, second);
  assert.match(first, UUID_RE);
  assert.equal(first[14], "5", "version nibble must be 5");
  assert.ok(["8", "9", "a", "b"].includes(first[19]), "variant nibble must be RFC 4122");
});

test("uuidv5 separates names and namespaces", () => {
  assert.notEqual(
    uuidv5("a", SCAN_ID_NAMESPACE),
    uuidv5("b", SCAN_ID_NAMESPACE),
  );
  assert.notEqual(
    uuidv5("a", SCAN_ID_NAMESPACE),
    uuidv5("a", IDEMPOTENCY_NAMESPACE),
  );
});

test("uuidv5 rejects a non-UUID namespace", () => {
  assert.throws(() => uuidv5("a", "not-a-uuid"), /namespace must be a UUID/);
});

test("websiteScanIdentity is stable for one slot and new for the next", () => {
  const siteId = "99999999-9999-4999-8999-999999999999";
  const slot = "2026-01-01T00:00:00.000Z";

  const first = websiteScanIdentity({ siteId, slot });
  const retry = websiteScanIdentity({ siteId, slot });
  const next = websiteScanIdentity({ siteId, slot: "2026-01-01T01:00:00.000Z" });

  assert.deepEqual(first, retry);
  assert.match(first.scanId, UUID_RE);
  assert.match(first.idempotencyKey, UUID_RE);
  assert.notEqual(first.scanId, first.idempotencyKey);
  assert.notEqual(first.scanId, next.scanId);
  assert.notEqual(first.idempotencyKey, next.idempotencyKey);
  assert.notEqual(first.scanId, siteId);
});

test("assertScanId accepts UUIDs and rejects everything else", () => {
  const id = "11111111-1111-4111-8111-111111111111";
  assert.equal(assertScanId(id), id);
  assert.throws(() => assertScanId("user:conn:repo:sha"), /must be a UUID/);
  assert.throws(() => assertScanId(null), /must be a UUID/);
});