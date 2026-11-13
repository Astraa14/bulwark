import test from "node:test";
import assert from "node:assert/strict";
import { scanGitHubRepo } from "./github.mjs";
import { scanSupabaseProject } from "./supabase.mjs";

// ============================================================================
// GitHub scanner tests
// ============================================================================

test("scanGitHubRepo returns findings for hardcoded secrets", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/") {
      return new Response(
        JSON.stringify([
          { type: "file", path: "config.js", size: 200, encoding: "base64", content: Buffer.from("const key = 'sk_live_abc123xyz45678901234';").toString("base64") },
        ]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/config.js") {
      return new Response(
        JSON.stringify({ type: "file", path: "config.js", size: 200, encoding: "base64", content: Buffer.from("const key = 'sk_live_abc123xyz45678901234';").toString("base64") }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanGitHubRepo("ghp_faketoken1234567890", "octocat", "Hello-World");
    assert.ok(result.findings.length > 0, "should find at least one secret");
    const secretFinding = result.findings.find((f) => f.check_key === "secret_stripe");
    assert.ok(secretFinding, "should find Stripe live key");
    assert.equal(secretFinding.severity, "critical");
  } finally {
    global.fetch = originalFetch;
  }
});

test("scanGitHubRepo returns clean repo with zero findings", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/") {
      return new Response(
        JSON.stringify([
          { type: "file", path: "readme.md", size: 100, encoding: "base64", content: Buffer.from("# Hello World").toString("base64") },
        ]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanGitHubRepo("ghp_faketoken1234567890", "octocat", "Hello-World");
    assert.equal(result.findings.length, 0, "clean repo should have zero findings");
  } finally {
    global.fetch = originalFetch;
  }
});

test("scanGitHubRepo detects sensitive filenames", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/") {
      return new Response(
        JSON.stringify([
          { type: "file", path: ".env", size: 300, encoding: "base64", content: Buffer.from("DB_PASSWORD=secret123").toString("base64") },
        ]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/.env") {
      return new Response(
        JSON.stringify({ type: "file", path: ".env", size: 300, encoding: "base64", content: Buffer.from("DB_PASSWORD=secret123").toString("base64") }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanGitHubRepo("ghp_faketoken1234567890", "octocat", "Hello-World");
    const sensitiveFinding = result.findings.find((f) => f.check_key === "exposed_config_file");
    assert.ok(sensitiveFinding, "should flag .env file");
    assert.equal(sensitiveFinding.severity, "high");
  } finally {
    global.fetch = originalFetch;
  }
});

test("scanGitHubRepo detects unpinned dependencies", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/") {
      return new Response(
        JSON.stringify([
          { type: "file", path: "package.json", size: 200, encoding: "base64", content: Buffer.from('{"dependencies": {"lodash": "*"}}').toString("base64") },
        ]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "https://api.github.com/repos/octocat/Hello-World/contents/package.json") {
      return new Response(
        JSON.stringify({ type: "file", path: "package.json", size: 200, encoding: "base64", content: Buffer.from('{"dependencies": {"lodash": "*"}}').toString("base64") }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanGitHubRepo("ghp_faketoken1234567890", "octocat", "Hello-World");
    const depFinding = result.findings.find((f) => f.check_key === "dep_unpinned");
    assert.ok(depFinding, "should flag unpinned dependency");
    assert.equal(depFinding.severity, "medium");
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Supabase scanner tests
// ============================================================================

test("scanSupabaseProject flags public storage bucket", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://abcdef.supabase.co/rest/v1/") {
      return new Response(null, { status: 200 });
    }
    if (url === "https://abcdef.supabase.co/storage/v1/bucket") {
      return new Response(
        JSON.stringify([{ name: "avatars", public: true }]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanSupabaseProject("https://abcdef.supabase.co", "anon-key-123");
    const bucketFinding = result.findings.find((f) => f.check_key === "supabase_public_storage");
    assert.ok(bucketFinding, "should flag public storage bucket");
    assert.equal(bucketFinding.severity, "high");
  } finally {
    global.fetch = originalFetch;
  }
});

test("scanSupabaseProject returns no findings for private buckets", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://abcdef.supabase.co/rest/v1/") {
      return new Response(null, { status: 200 });
    }
    if (url === "https://abcdef.supabase.co/storage/v1/bucket") {
      return new Response(
        JSON.stringify([{ name: "avatars", public: false }]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await scanSupabaseProject("https://abcdef.supabase.co", "anon-key-123");
    const bucketFinding = result.findings.find((f) => f.check_key === "supabase_public_storage");
    assert.equal(bucketFinding, undefined, "private bucket should not be flagged");
  } finally {
    global.fetch = originalFetch;
  }
});
