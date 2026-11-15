import { createHmac, timingSafeEqual } from "node:crypto";

/** GitHub rejects payloads above 25 MB; Bulwark accepts a much smaller bound. */
export const MAX_WEBHOOK_BYTES = 1_000_000;

/** Upper bound on HMAC comparisons for the global (non per-connection) URL. */
export const MAX_GLOBAL_WEBHOOK_SECRETS = 200;

/**
 * Verify X-Hub-Signature-256 against the exact request bytes. Never pass a
 * parsed object here: re-serialising JSON changes the bytes and breaks HMAC.
 */
export function verifyGitHubSignature(rawBody, signatureHeader, secret) {
  if (!Buffer.isBuffer(rawBody) || rawBody.length === 0) return false;
  if (rawBody.length > MAX_WEBHOOK_BYTES) return false;
  if (typeof signatureHeader !== "string" || typeof secret !== "string" || !secret) return false;

  const match = /^sha256=([0-9a-f]{64})$/i.exec(signatureHeader.trim());
  if (!match) return false;

  const expected = createHmac("sha256", secret).update(rawBody).digest();
  const provided = Buffer.from(match[1], "hex");
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

export function parseGitHubPush(rawBody) {
  if (!Buffer.isBuffer(rawBody)) throw new Error("Webhook body was not received as raw bytes.");
  if (rawBody.length > MAX_WEBHOOK_BYTES) throw new Error("Webhook body is too large.");

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new Error("Webhook payload is not valid JSON.");
  }

  const repository = payload?.repository;
  const owner = repository?.owner?.login;
  const repo = repository?.name;
  const after = payload?.after;
  const ref = payload?.ref ?? null;

  if (!owner || !repo || !after) {
    throw new Error("Webhook payload is missing repository or commit information.");
  }

  return {
    payload,
    owner,
    repo,
    resource: `${owner}/${repo}`,
    after,
    ref,
    deleted: payload?.deleted === true,
    allZeroCommit: /^0+$/.test(String(after)),
  };
}

/**
 * Find the one GitHub connection whose webhook secret signed this delivery.
 * When the URL names a connection, only that connection is considered.
 */
export async function findWebhookConnection({
  db,
  connectionId = null,
  rawBody,
  signature,
  decryptSecret,
}) {
  const columns = "id, user_id, webhook_secret_encrypted";

  if (connectionId) {
    // Reject malformed IDs before querying a uuid column, so a bad URL is a
    // clean 401 rather than a database syntax error surfaced as HTTP 500.
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(connectionId)) {
      return null;
    }
    const { data, error } = await db
      .from("github_connections")
      .select(columns)
      .eq("id", connectionId)
      .not("webhook_secret_encrypted", "is", null)
      .maybeSingle();
    if (error) throw new Error(`load webhook connection: ${error.message}`);
    if (!data) return null;
    try {
      const secret = decryptSecret(data.webhook_secret_encrypted);
      return verifyGitHubSignature(rawBody, signature, secret) ? data : null;
    } catch {
      return null;
    }
  }

  // The per-connection URL is the documented path. The global endpoint still
  // works, but only ever inspects a bounded number of secrets per delivery.
  const { data, error } = await db
    .from("github_connections")
    .select(columns)
    .not("webhook_secret_encrypted", "is", null)
    .order("created_at", { ascending: true })
    .limit(MAX_GLOBAL_WEBHOOK_SECRETS);
  if (error) throw new Error(`load webhook connections: ${error.message}`);

  const matches = [];
  for (const row of data ?? []) {
    try {
      const secret = decryptSecret(row.webhook_secret_encrypted);
      if (verifyGitHubSignature(rawBody, signature, secret)) matches.push(row);
    } catch {
      // A connection with an unreadable secret cannot authenticate anything.
    }
  }

  // If two connections reuse one secret, the request cannot be attributed to a
  // tenant. Refuse it and require the per-connection webhook URL instead.
  return matches.length === 1 ? matches[0] : null;
}
