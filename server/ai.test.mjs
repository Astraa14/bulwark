import test from "node:test";
import assert from "node:assert/strict";
import {
  PROVIDERS,
  buildDeterministicBrief,
  buildExplanationPrompt,
  explainWithProvider,
  generateWorkspaceBriefWithProvider,
  isProvider,
} from "./ai.mjs";

test("supports OpenAI, Anthropic, and Google Gemini providers", () => {
  assert.equal(isProvider("openai"), true);
  assert.equal(isProvider("anthropic"), true);
  assert.equal(isProvider("gemini"), true);
  assert.equal(isProvider("unknown"), false);
  assert.equal(PROVIDERS.gemini.label, "Google Gemini");
});

test("buildExplanationPrompt incorporates stack profile when present", () => {
  const prompt = buildExplanationPrompt({
    domain: "acme.dev",
    stack: "nextjs-vercel",
    finding: { title: "Missing HSTS", severity: "medium", detail: "No HSTS header" },
  });
  assert.match(prompt, /Application stack: Next\.js on Vercel/);
  assert.match(prompt, /tailored specifically for Next\.js on Vercel/);
});

test("explainWithProvider calls Gemini API with x-goog-api-key header", async () => {
  const calls = [];
  const res = await explainWithProvider({
    provider: "gemini",
    apiKey: "AIza-fake-gemini-key-for-unit-test",
    model: "gemini-2.5-flash",
    domain: "acme.dev",
    stack: "cloudflare",
    finding: { title: "Missing CSP", severity: "medium", detail: "No CSP header" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), headers: init.headers, body: JSON.parse(init.body) });
      return new Response(
        JSON.stringify({
          modelVersion: "gemini-2.5-flash",
          candidates: [{ content: { parts: [{ text: "1. Meaning\n2. Risk\n3. Fix on Cloudflare." }] } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
  );
  assert.equal(calls[0].headers["x-goog-api-key"], "AIza-fake-gemini-key-for-unit-test");
  assert.match(calls[0].body.contents[0].parts[0].text, /Cloudflare/);
  assert.match(res.text, /Fix on Cloudflare/);
  assert.equal(res.model, "gemini-2.5-flash");
});

test("buildDeterministicBrief ranks top 3 open findings by severity and recency", () => {
  const sites = [{ id: "s1", domain: "acme.dev" }];
  const findings = [
    { id: "f1", site_id: "s1", status: "open", severity: "low", title: "Low", last_seen_at: "2026-11-22T00:00:00Z" },
    { id: "f2", site_id: "s1", status: "open", severity: "critical", title: "Exposed .env", last_seen_at: "2026-11-20T00:00:00Z" },
    { id: "f3", site_id: "s1", status: "resolved", severity: "critical", title: "Already fixed", last_seen_at: "2026-11-22T00:00:00Z" },
    { id: "f4", site_id: null, platform: "github", resource: "octo/app", status: "open", severity: "high", title: "Leaked key", last_seen_at: "2026-11-22T01:00:00Z" },
    { id: "f5", site_id: "s1", status: "open", severity: "high", title: "Weak CORS", last_seen_at: "2026-11-21T00:00:00Z" },
  ];

  const brief = buildDeterministicBrief({ sites, findings });
  assert.deepEqual(
    brief.topItems.map((i) => i.id),
    ["f2", "f4", "f5"],
  );
  assert.match(brief.brief, /4 open findings/);
  assert.match(brief.brief, /Exposed \.env/);
});

test("generateWorkspaceBriefWithProvider synthesizes brief via provider", async () => {
  const out = await generateWorkspaceBriefWithProvider({
    provider: "gemini",
    apiKey: "AIza-fake-gemini-key-for-unit-test",
    sites: [{ id: "s1", domain: "acme.dev" }],
    findings: [
      { id: "f1", site_id: "s1", status: "open", severity: "critical", title: "Exposed .env", remediation: "Block /.env" },
    ],
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          modelVersion: "gemini-2.5-flash",
          candidates: [{ content: { parts: [{ text: "1. Block /.env immediately on acme.dev." }] } }],
        }),
        { status: 200 },
      ),
  });

  assert.equal(out.generatedBy, "ai");
  assert.equal(out.model, "gemini:gemini-2.5-flash");
  assert.match(out.brief, /Block \/\.env/);
});
