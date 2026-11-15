import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { verifyGitHubSignature, parseGitHubPush, MAX_WEBHOOK_BYTES } from "./webhooks.mjs";

const SECRET = "a-very-long-webhook-test-secret";

function signature(raw, secret = SECRET) {
  return `sha256=${createHmac("sha256", secret).update(raw).digest("hex")}`;
}

test("verifyGitHubSignature accepts valid signature", async () => {
  const body = JSON.stringify({ test: "payload" });
  const rawBody = Buffer.from(body);
  const sig = signature(rawBody);
  const result = verifyGitHubSignature(rawBody, sig, SECRET);
  assert.equal(result, true);
});

test("verifyGitHubSignature rejects wrong secret", async () => {
  const body = JSON.stringify({ test: "payload" });
  const rawBody = Buffer.from(body);
  const sig = signature(rawBody, "wrong-secret");
  const result = verifyGitHubSignature(rawBody, sig, SECRET);
  assert.equal(result, false);
});

test("verifyGitHubSignature rejects malformed signature header", async () => {
  const body = JSON.stringify({ test: "payload" });
  const rawBody = Buffer.from(body);
  const result = verifyGitHubSignature(rawBody, "invalid-signature", SECRET);
  assert.equal(result, false);
});

test("verifyGitHubSignature rejects empty body", async () => {
  const result = verifyGitHubSignature(Buffer.from(""), signature(Buffer.from("")), SECRET);
  assert.equal(result, false);
});

test("verifyGitHubSignature rejects oversized body", async () => {
  const body = "x".repeat(MAX_WEBHOOK_BYTES + 1);
  const result = verifyGitHubSignature(Buffer.from(body), signature(Buffer.from(body)), SECRET);
  assert.equal(result, false);
});

test("verifyGitHubSignature accepts zero-length signature header", async () => {
  const result = verifyGitHubSignature(Buffer.from("test"), "", SECRET);
  assert.equal(result, false);
});

test("parseGitHubPush parses valid push payload", async () => {
  const payload = {
    ref: "refs/heads/main",
    after: "abc123",
    repository: { name: "repo", owner: { login: "octo" } },
    deleted: false,
  };
  const rawBody = Buffer.from(JSON.stringify(payload));
  const result = parseGitHubPush(rawBody);
  assert.equal(result.owner, "octo");
  assert.equal(result.repo, "repo");
  assert.equal(result.after, "abc123");
  assert.equal(result.ref, "refs/heads/main");
  assert.equal(result.resource, "octo/repo");
});

test("parseGitHubPush rejects missing owner", async () => {
  const payload = { ref: "refs/heads/main", after: "abc123", repository: { name: "repo" } };
  const rawBody = Buffer.from(JSON.stringify(payload));
  assert.throws(() => parseGitHubPush(rawBody), /missing repository or commit information/);
});

test("parseGitHubPush rejects missing repo", async () => {
  const payload = { ref: "refs/heads/main", after: "abc123", repository: { owner: { login: "octo" } } };
  const rawBody = Buffer.from(JSON.stringify(payload));
  assert.throws(() => parseGitHubPush(rawBody), /missing repository or commit information/);
});

test("parseGitHubPush rejects missing after", async () => {
  const payload = { ref: "refs/heads/main", repository: { name: "repo", owner: { login: "octo" } } };
  const rawBody = Buffer.from(JSON.stringify(payload));
  assert.throws(() => parseGitHubPush(rawBody), /missing repository or commit information/);
});

test("parseGitHubPush handles deleted branches", async () => {
  const payload = {
    ref: "refs/heads/main",
    after: "0".repeat(40),
    repository: { name: "repo", owner: { login: "octo" } },
    deleted: true,
  };
  const rawBody = Buffer.from(JSON.stringify(payload));
  const result = parseGitHubPush(rawBody);
  assert.equal(result.deleted, true);
  assert.equal(result.allZeroCommit, true);
});

test("verifyGitHubSignature rejects non-buffer body", () => {
  assert.equal(verifyGitHubSignature("not-a-buffer", "sig", SECRET), false);
});