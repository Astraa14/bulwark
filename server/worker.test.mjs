import test from "node:test";
import assert from "node:assert/strict";
import { scanSite } from "./worker.mjs";
import { UUID_RE } from "./scan-id.mjs";
import { createFakeDb } from "./test-support/fake-db.mjs";

const SITE_ID = "99999999-9999-4999-8999-999999999999";
const SLOT = "2026-01-01T00:00:00.000Z";
const NEXT_SLOT = "2026-01-01T01:00:00.000Z";

function site(slot = SLOT) {
  return {
    id: SITE_ID,
    user_id: "user-a",
    domain: "example.com",
    scan_interval_minutes: 60,
    page_sample: null,
    next_scan_at: slot,
  };
}

const runChecks = async () => ({
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
});

function harness() {
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
  return { db, calls };
}

test("a retry of the same slot reuses the scan UUID and idempotency key", async () => {
  const { db, calls } = harness();

  await scanSite(db, site(), { runChecks });
  await scanSite(db, site(), { runChecks });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].p_scan_id, calls[1].p_scan_id);
  assert.equal(calls[0].p_idempotency_key, calls[1].p_idempotency_key);
  assert.match(calls[0].p_scan_id, UUID_RE);
  assert.match(calls[0].p_idempotency_key, UUID_RE);
  assert.notEqual(calls[0].p_scan_id, SITE_ID);
});

test("the next due slot is a new scan with a new UUID pair", async () => {
  const first = harness();
  const second = harness();

  await scanSite(first.db, site(), { runChecks });
  await scanSite(second.db, site(NEXT_SLOT), { runChecks });

  const a = first.calls[0];
  const b = second.calls[0];

  assert.notEqual(a.p_scan_id, b.p_scan_id);
  assert.notEqual(a.p_idempotency_key, b.p_idempotency_key);
  assert.match(b.p_scan_id, UUID_RE);
  assert.match(b.p_idempotency_key, UUID_RE);
});

test("scan ids are never derived from the site id", async () => {
  const { db, calls } = harness();
  await scanSite(db, site(), { runChecks });

  assert.notEqual(calls[0].p_scan_id, SITE_ID);
  assert.notEqual(calls[0].p_idempotency_key, SITE_ID);
});