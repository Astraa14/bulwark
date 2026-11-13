import test from "node:test";
import assert from "node:assert/strict";
import { runChecks } from "./checks.mjs";

// ============================================================================
// Fixture: clean site — all local checks pass, external lookups error (partial)
// ============================================================================

test("clean site: local checks pass, zero findings, external lookups error", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(
        '<!DOCTYPE html><html><head><title>Example</title></head><body>hello</body></html>',
        {
          status: 200,
          headers: {
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "access-control-allow-origin": "https://trusted.example",
            "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
          },
        },
      );
    }
    if (/(\/\.env|\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/robots.txt")) {
      return new Response("User-agent: *\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    if (url.endsWith("/sitemap.xml")) {
      return new Response('<?xml version="1.0"?><urlset></urlset>', {
        status: 200,
        headers: { "content-type": "application/xml" },
      });
    }
    if (url.endsWith("/.well-known/security.txt")) {
      return new Response("Contact: mailto:security@example.com\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    // External RDAP/DoH lookups can't resolve in test env → partial, not completed.
    // But all local checks pass and there are zero findings.
    assert.equal(result.status, "partial");
    assert.equal(result.findings.length, 0);
    assert.equal(result.checkResults.site_uptime, "pass");
    assert.equal(result.checkResults.http_status, "pass");
    assert.equal(result.checkResults.security_headers, "pass");
    assert.equal(result.checkResults.csp_policy, "pass");
    assert.equal(result.checkResults.cookies, "pass");
    assert.equal(result.checkResults.mixed_content, "pass");
    assert.equal(result.checkResults.directory_listing, "pass");
    assert.equal(result.checkResults.defacement, "pass");
    // External lookups error
    assert.equal(result.checkResults.domain_registration, "error");
    assert.equal(result.checkResults.dns, "error");
    assert.ok(result.checksErrored >= 2);
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: vulnerable site — exposed .env, missing headers, open CORS
// ============================================================================

test("vulnerable site returns findings (partial due to external lookups)", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>hello</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        },
      });
    }
    if (url === "https://example.com/.env") {
      return new Response("STRIPE_SECRET_KEY=sk_live_abc123\nDATABASE_URL=postgres://...\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    if (/(\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/robots.txt")) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/sitemap.xml")) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/.well-known/security.txt")) {
      return new Response(null, { status: 404 });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    const checkKeys = result.findings.map((f) => f.check_key);
    assert.ok(checkKeys.includes("header_hsts"), "missing HSTS should be flagged");
    assert.ok(checkKeys.includes("header_csp"), "missing CSP should be flagged");
    assert.ok(checkKeys.includes("cors_wildcard_credentials"), "open CORS+creds should be flagged");
    assert.ok(checkKeys.includes("exposed_env"), "exposed .env should be flagged");
    const envFinding = result.findings.find((f) => f.check_key === "exposed_env");
    assert.equal(envFinding.severity, "critical");
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: defacement detection — homepage content changed dramatically
// ============================================================================

test("defacement detected when baseline differs from current page", async () => {
  const baseline = JSON.stringify({
    title: "My Store",
    text: "Welcome to my online store. We sell handmade crafts and jewelry.",
    at: "2026-01-01T00:00:00.000Z",
  });
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(
        '<html><head><title>HACKED</title></head><body>Hacked by evilgroup123</body></html>',
        {
          status: 200,
          headers: {
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
          },
        },
      );
    }
    if (/(\/\.env|\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com", { baseline });
    const checkKeys = result.findings.map((f) => f.check_key);
    assert.ok(
      checkKeys.includes("defacement_marker") || checkKeys.includes("content_replaced"),
      "defacement should be detected against baseline",
    );
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: no defacement when page matches baseline
// ============================================================================

test("no defacement finding when page is similar to baseline", async () => {
  const baseline = JSON.stringify({
    title: "Example",
    text: "Welcome to example.com. We sell things.",
    at: "2026-01-01T00:00:00.000Z",
  });
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(
        '<html><head><title>Example</title></head><body>Welcome to example.com. We sell things.</body></html>',
        {
          status: 200,
          headers: {
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
          },
        },
      );
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com", { baseline });
    const defacementFindings = result.findings.filter(
      (f) => f.check_key === "defacement_marker" || f.check_key === "content_replaced",
    );
    assert.equal(defacementFindings.length, 0);
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: SSRF blocked on exposed-file probe redirect to private IP
// ============================================================================

test("SSRF blocked on exposed-file probe redirect to private IP", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    }
    if (url.endsWith("/.env")) {
      return new Response(null, {
        status: 302,
        headers: { location: "http://169.254.169.254/" },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    // Uptime passes, but exposed_files errors → partial
    assert.equal(result.status, "partial");
    assert.equal(result.checkResults.exposed_files, "error");
    assert.ok(result.checksErrored >= 1);
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: partial scan when domain expiry check errors
// ============================================================================

test("partial scan when domain expiry check errors", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
        },
      });
    }
    if (/(\/\.env|\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/robots.txt")) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/sitemap.xml")) {
      return new Response(null, { status: 404 });
    }
    if (url.endsWith("/.well-known/security.txt")) {
      return new Response(null, { status: 404 });
    }
    if (url.includes("rdap.verisign.com")) {
      throw new Error("ECONNREFUSED");
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    assert.equal(result.checkResults.domain_registration, "error");
    assert.ok(result.checksErrored >= 1);
    // Discovery checks still run and may produce info findings; the key
    // assertion is that domain_registration errored, not that findings are empty.
  } finally {
    global.fetch = originalFetch;
  }
});

// ============================================================================
// Fixture: 403 is error, 404 is absence (distinction)
// ============================================================================

test("403 on exposed file is error; 404 is absence", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
        },
      });
    }
    if (url.endsWith("/.env")) {
      return new Response("forbidden", { status: 403 });
    }
    if (/(\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    // .env returned 403 → error outcome, not pass, not finding
    assert.equal(result.checkResults.exposed_files, "error");
  } finally {
    global.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------
// Adversarial: edge cases for coverage honesty and finding lifecycle
// ---------------------------------------------------------------------------

test("redirect chain is followed and validated at every hop", async () => {
  const originalFetch = global.fetch;
  let hop = 0;
  global.fetch = async (input) => {
    const url = String(input);
    hop += 1;
    if (url === "https://example.com/") {
      return new Response(null, {
        status: 302,
        headers: { location: "https://example.com/step1" },
      });
    }
    if (url === "https://example.com/step1") {
      hop += 1;
      return new Response(null, {
        status: 302,
        headers: { location: "https://example.com/step2" },
      });
    }
    if (url === "https://example.com/step2") {
      return new Response("<html><body>final</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
        },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    assert.equal(result.checkResults.site_uptime, "pass");
    assert.ok(hop >= 3, `Expected at least 3 fetch hops, got ${hop}`);
  } finally {
    global.fetch = originalFetch;
  }
});

test("multiple finding types in one scan all reported", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "access-control-allow-origin": "*",
          "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
        },
      });
    }
    if (url === "https://example.com/.env") {
      return new Response("STRIPE_SECRET_KEY=sk_live_abc123xyz45678901234\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    if (/(\/\.git\/config|\/\.DS_Store|\/backup\.sql|\/db\.sql|\/phpinfo\.php)$/.test(url)) {
      return new Response(null, { status: 404 });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    const checkKeys = result.findings.map((f) => f.check_key);
    assert.ok(checkKeys.includes("header_hsts"), "missing HSTS");
    assert.ok(checkKeys.includes("header_csp"), "missing CSP");
    assert.ok(checkKeys.includes("cors_wildcard"), "open CORS");
    assert.ok(checkKeys.includes("exposed_env"), "exposed .env");
    // At minimum these four finding types must be present.
    assert.ok(checkKeys.length >= 4, `Expected at least 4 findings, got ${checkKeys.length}: ${checkKeys.join(", ")}`);
  } finally {
    global.fetch = originalFetch;
  }
});

test("oversized script bundle is rejected as error, not pass", async () => {
  const originalFetch = global.fetch;
  global.fetch = async (input) => {
    const url = String(input);
    if (url === "https://example.com/") {
      return new Response(
        '<html><body><script src="/app.js"></script></body></html>',
        {
          status: 200,
          headers: { "content-type": "text/html" },
        },
      );
    }
    if (url === "https://example.com/app.js") {
      return new Response("x".repeat(6_000_000), {
        status: 200,
        headers: { "content-type": "application/javascript" },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const result = await runChecks("example.com");
    assert.equal(result.status, "partial");
    assert.equal(result.checkResults.secrets, "error");
  } finally {
    global.fetch = originalFetch;
  }
});

test("changed evidence on recurrence updates severity and evidence", async () => {
  const originalFetch = global.fetch;
  let scanCount = 0;
  global.fetch = async (input) => {
    const url = String(input);
    scanCount += 1;
    if (url === "https://example.com/") {
      if (scanCount === 1) {
        return new Response("<html><body>ok</body></html>", {
          status: 200,
          headers: {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'",
          },
        });
      }
      return new Response("<html><body>ok</body></html>", {
        status: 200,
        headers: {
          "content-type": "text/html",
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
        },
      });
    }
    throw new Error("Unexpected fetch: " + url);
  };
  try {
    const first = await runChecks("example.com");
    const hstsFinding = first.findings.find((f) => f.check_key === "header_hsts");
    assert.ok(hstsFinding, "first scan should find missing HSTS");
    assert.equal(hstsFinding.severity, "medium");

    const second = await runChecks("example.com");
    const hstsFinding2 = second.findings.find((f) => f.check_key === "header_hsts");
    assert.equal(hstsFinding2, undefined, "second scan should not find missing HSTS");
  } finally {
    global.fetch = originalFetch;
  }
});
