import test from "node:test";
import assert from "node:assert/strict";
import { buildPath, parseLocation } from "../src/lib/router.ts";
import { buildFixPrompt } from "../src/lib/fixPrompt.ts";
import {
  csvCell,
  findingImpactSummary,
  isShipBlocker,
  scanOutcomeSummary,
  sortFindingsByPriority,
} from "../src/lib/scanOutcomes.ts";

function makeFinding(overrides = {}) {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    site_id: null,
    scan_id: "22222222-2222-2222-2222-222222222222",
    check_key: "header_csp",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    status: "open",
    detail: "No CSP header observed.",
    evidence: "content-security-policy: (missing)",
    url: "https://example.com/",
    platform: null,
    explanation: null,
    explanation_model: null,
    explained_at: null,
    first_seen_at: "2026-11-20T00:00:00.000Z",
    last_seen_at: "2026-11-24T00:00:00.000Z",
    ...overrides,
  };
}

test("router parses and builds deep links across pages, threat details, and integration tabs", () => {
  assert.deepEqual(parseLocation("/", ""), {
    page: "Overview",
    findingId: null,
    integrationTab: "alerts",
  });
  assert.deepEqual(parseLocation("/integrations/", "?tab=platforms"), {
    page: "Integrations",
    findingId: null,
    integrationTab: "platforms",
  });
  assert.deepEqual(parseLocation("/threats/abc-123", ""), {
    page: "Threats",
    findingId: "abc-123",
    integrationTab: "alerts",
  });
  assert.equal(
    buildPath({ page: "Integrations", integrationTab: "findings" }),
    "/integrations?tab=findings",
  );
  assert.equal(buildPath({ page: "Threats", findingId: "abc-123" }), "/threats/abc-123");
});

test("ship-blocker classification and priority sorting separate blockers from post-launch polish", () => {
  const csp = makeFinding({ id: "csp", check_key: "header_csp", severity: "medium" });
  const pkTest = makeFinding({
    id: "pktest",
    check_key: "stripe_test_key_in_production",
    severity: "medium",
    last_seen_at: "2026-11-21T00:00:00.000Z",
  });
  const anonLeak = makeFinding({
    id: "anon",
    check_key: "supabase_anon_readable_table",
    severity: "critical",
    last_seen_at: "2026-11-22T00:00:00.000Z",
  });

  assert.equal(isShipBlocker(csp), false);
  assert.equal(isShipBlocker(pkTest), true);
  assert.equal(isShipBlocker(anonLeak), true);

  const sorted = sortFindingsByPriority([csp, pkTest, anonLeak]);
  assert.deepEqual(
    sorted.map((f) => f.id),
    ["anon", "pktest", "csp"],
  );
  assert.match(findingImpactSummary(anonLeak), /anon key/i);
  assert.match(findingImpactSummary(csp), /hardening/i);
});

test("buildFixPrompt includes launch priority, blast radius, and check-specific instructions", () => {
  const aiRoute = makeFinding({
    platform: "github",
    check_key: "ai_route_without_auth",
    title: "Metered AI endpoint without auth or rate limit: app/api/chat/route.ts",
    severity: "high",
    affected_resource: "app/api/chat/route.ts",
  });
  const prompt = buildFixPrompt(aiRoute, "octocat/vibe-app", "nextjs-vercel");
  assert.match(prompt, /Priority: Ship-blocker/);
  assert.match(prompt, /Real-world risk:.*drain your paid AI/i);
  assert.match(prompt, /Next\.js on Vercel/);
  assert.match(prompt, /rate limiting before calling the AI provider/i);
});

test("csvCell neutralizes spreadsheet formula injection and scanOutcomeSummary counts outcomes", () => {
  assert.equal(csvCell("=CMD|' /C calc'!A0"), `"'=CMD|' /C calc'!A0"`);
  assert.equal(csvCell('hello "world"'), '"hello ""world"""');

  const summary = scanOutcomeSummary({
    id: "s1",
    site_id: "site1",
    started_at: "2026-11-25T00:00:00Z",
    finished_at: "2026-11-25T00:00:05Z",
    status: "partial",
    http_status: 200,
    response_ms: 120,
    checks_total: 3,
    checks_passed: 1,
    error: null,
    check_results: [
      { key: "tls", label: "TLS", status: "pass", complete: true },
      { key: "secrets", label: "Secrets", status: "finding", complete: true },
      { key: "rls", label: "RLS", status: "not_checked", complete: false },
    ],
  });
  assert.equal(summary.passed, 1);
  assert.equal(summary.finding, 1);
  assert.equal(summary.not_checked, 1);
  assert.equal(summary.completed, 2);
});
