import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { findWebhookConnection } from "./webhooks.mjs";
import { createFakeDb } from "./test-support/fake-db.mjs";

const SECRET = "a-very-long-webhook-test-secret";
const CONN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CONN_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const decryptSecret = (value) => value;

function row(overrides = {}) {
  return {
    id: CONN_A,
    user_id: "user-a",
    webhook_secret_encrypted: SECRET,
    ...overrides,
  };
}

function sign(body, secret = SECRET) {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

test("returns the named connection when the signature matches", async () => {
  const rawBody = Buffer.from(JSON.stringify({ hello: "world" }));
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    connectionId: CONN_A,
    rawBody,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched?.id, CONN_A);
  assert.equal(matched?.user_id, "user-a");
});

test("returns null for a malformed connection id without querying uuid", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    connectionId: "not-a-uuid",
    rawBody,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched, null);
  assert.equal(db.calls.length, 0);
});

test("returns null for an unknown connection id", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    connectionId: CONN_B,
    rawBody,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched, null);
});

test("returns the only match for an unscoped webhook URL", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    rawBody,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched?.id, CONN_A);
});

test("refuses an unscoped URL when two connections share the secret", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({
    tables: {
      github_connections: [
        row(),
        row({ id: CONN_B, user_id: "user-b", github_username: "other" }),
      ],
    },
  });

  const matched = await findWebhookConnection({
    db,
    rawBody,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched, null);
});

test("returns null when the only secret cannot be decrypted", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    rawBody,
    signature: sign(rawBody),
    decryptSecret: () => {
      throw new Error("bad key");
    },
  });

  assert.equal(matched, null);
});

test("propagates a database error", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });
  db.from = () => {
    throw new Error("db unavailable");
  };

  await assert.rejects(
    () =>
      findWebhookConnection({
        db,
        connectionId: CONN_A,
        rawBody,
        signature: sign(rawBody),
        decryptSecret,
      }),
    /db unavailable/,
  );
});

test("accepts an uppercase hex signature and rejects a wrong-length one", async () => {
  const rawBody = Buffer.from("{}");
  const db = createFakeDb({ tables: { github_connections: [row()] } });
  const signature = sign(rawBody);

  const upper = await findWebhookConnection({
    db,
    connectionId: CONN_A,
    rawBody,
    signature: signature.toUpperCase().replace("SHA256=", "sha256="),
    decryptSecret,
  });
  assert.equal(upper?.id, CONN_A);

  const short = await findWebhookConnection({
    db,
    connectionId: CONN_A,
    rawBody,
    signature: "sha256=abcd",
    decryptSecret,
  });
  assert.equal(short, null);
});

test("a tampered body does not match the signature", async () => {
  const rawBody = Buffer.from(JSON.stringify({ hello: "world" }));
  const tampered = Buffer.from(JSON.stringify({ hello: "tampered" }));
  const db = createFakeDb({ tables: { github_connections: [row()] } });

  const matched = await findWebhookConnection({
    db,
    connectionId: CONN_A,
    rawBody: tampered,
    signature: sign(rawBody),
    decryptSecret,
  });

  assert.equal(matched, null);
});