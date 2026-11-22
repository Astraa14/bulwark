/**
 * BYOK provider adapters (OpenAI, Anthropic, Google Gemini) + workspace brief.
 * Keys are decrypted in memory for the duration of one request and never logged.
 */

export const PROVIDERS = {
  openai: {
    label: "OpenAI",
    defaultModel: "gpt-4.1-mini",
    docs: "https://platform.openai.com/api-keys",
  },
  anthropic: {
    label: "Anthropic",
    defaultModel: "claude-haiku-4-5",
    docs: "https://console.anthropic.com/settings/keys",
  },
  gemini: {
    label: "Google Gemini",
    defaultModel: "gemini-2.5-flash",
    docs: "https://aistudio.google.com/apikey",
  },
};

export const STACK_LABELS = {
  "nextjs-vercel": "Next.js on Vercel",
  "vite-render": "Vite + Node on Render",
  cloudflare: "Cloudflare Pages / Workers",
  nginx: "Nginx reverse proxy",
  express: "Node.js / Express",
  supabase: "Supabase backend",
  other: "Custom web stack",
};

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function isProvider(value) {
  return Object.prototype.hasOwnProperty.call(PROVIDERS, String(value));
}

function timeout(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

function httpError(provider, status, body) {
  const snippet = String(body ?? "").slice(0, 240);
  if (status === 401 || status === 403) {
    return new Error(`${PROVIDERS[provider].label} rejected the key. Check it and try again.`);
  }
  if (status === 429) {
    return new Error(`${PROVIDERS[provider].label} rate limit or quota reached. Try again shortly.`);
  }
  return new Error(`${PROVIDERS[provider].label} returned HTTP ${status}. ${snippet}`);
}

const SYSTEM_PROMPT =
  "You are a pragmatic security engineer. You explain findings to developers who ship fast and are not security specialists. Be concrete, calm, and specific. No preamble.";

async function callOpenAI({ apiKey, model, prompt, system = SYSTEM_PROMPT, fetchImpl = fetch }) {
  const t = timeout(45_000);
  try {
    const res = await fetchImpl("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      signal: t.signal,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        max_tokens: 700,
        messages: [
          { role: "system", content: system },
          { role: "user", content: prompt },
        ],
      }),
    });
    const text = await res.text();
    if (!res.ok) throw httpError("openai", res.status, text);
    const json = JSON.parse(text);
    const out = json.choices?.[0]?.message?.content?.trim();
    if (!out) throw new Error("OpenAI returned an empty explanation.");
    return { text: out, model: json.model ?? model };
  } finally {
    t.clear();
  }
}

async function callAnthropic({ apiKey, model, prompt, system = SYSTEM_PROMPT, fetchImpl = fetch }) {
  const t = timeout(45_000);
  try {
    const res = await fetchImpl("https://api.anthropic.com/v1/messages", {
      method: "POST",
      signal: t.signal,
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 700,
        temperature: 0.2,
        system,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const text = await res.text();
    if (!res.ok) throw httpError("anthropic", res.status, text);
    const json = JSON.parse(text);
    const out = (json.content ?? [])
      .filter((part) => part.type === "text")
      .map((part) => part.text)
      .join("\n")
      .trim();
    if (!out) throw new Error("Anthropic returned an empty explanation.");
    return { text: out, model: json.model ?? model };
  } finally {
    t.clear();
  }
}

async function callGemini({ apiKey, model, prompt, system = SYSTEM_PROMPT, fetchImpl = fetch }) {
  const t = timeout(45_000);
  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
      model,
    )}:generateContent`;
    const res = await fetchImpl(endpoint, {
      method: "POST",
      signal: t.signal,
      headers: {
        "content-type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 700,
        },
      }),
    });
    const text = await res.text();
    if (!res.ok) throw httpError("gemini", res.status, text);
    const json = JSON.parse(text);
    const out = (json.candidates?.[0]?.content?.parts ?? [])
      .map((part) => part.text ?? "")
      .join("\n")
      .trim();
    if (!out) throw new Error("Gemini returned an empty explanation.");
    return { text: out, model: json.modelVersion ?? model };
  } finally {
    t.clear();
  }
}

function providerCaller(provider) {
  if (provider === "openai") return callOpenAI;
  if (provider === "anthropic") return callAnthropic;
  if (provider === "gemini") return callGemini;
  throw new Error("Unsupported AI provider.");
}

export function buildExplanationPrompt({ finding, domain, stack = null }) {
  const stackLabel = stack ? STACK_LABELS[stack] ?? stack : null;
  const lines = [
    `A security scanner found this on ${domain}:`,
    "",
    `Finding: ${finding.title}`,
    `Severity: ${finding.severity}`,
    ...(stackLabel ? [`Application stack: ${stackLabel}`] : []),
    `What the scanner observed: ${finding.detail ?? "n/a"}`,
  ];
  if (finding.evidence) lines.push(`Evidence: ${finding.evidence}`);
  if (finding.url) lines.push(`Affected URL: ${finding.url}`);
  lines.push(
    "",
    "Write three short labelled parts, plain text, no markdown symbols:",
    "1. What this means — 2 sentences in everyday language.",
    "2. Why it matters — 1 sentence about the realistic risk for a small product.",
    stackLabel
      ? `3. How to fix it — 2 to 4 numbered, concrete steps tailored specifically for ${stackLabel}.`
      : "3. How to fix it — 2 to 4 numbered, concrete steps.",
    "Keep the whole answer under 180 words. Do not invent facts that are not in the finding.",
  );
  return lines.join("\n");
}

/** Calls the user's provider. Throws a human-readable Error on failure. */
export async function explainWithProvider({
  provider,
  apiKey,
  model,
  finding,
  domain,
  stack = null,
  fetchImpl = fetch,
}) {
  if (!isProvider(provider)) throw new Error("Unsupported AI provider.");
  const chosen = model || PROVIDERS[provider].defaultModel;
  const prompt = buildExplanationPrompt({ finding, domain, stack });
  return providerCaller(provider)({ apiKey, model: chosen, prompt, fetchImpl });
}

/** Deterministic Top-3 priority action plan (works even without an AI key). */
export function buildDeterministicBrief({ sites = [], findings = [] }) {
  const siteById = new Map(sites.map((s) => [s.id, s]));
  const open = findings
    .filter((f) => f.status === "open")
    .slice()
    .sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return String(b.last_seen_at ?? "").localeCompare(String(a.last_seen_at ?? ""));
    });

  const topItems = open.slice(0, 3).map((f) => {
    const target = siteById.get(f.site_id)?.domain ?? f.resource ?? f.platform ?? "workspace";
    return {
      id: f.id,
      title: f.title,
      severity: f.severity,
      target,
      checkKey: f.check_key,
      remediation: f.remediation ?? f.detail ?? "Open the finding for exact fix steps.",
    };
  });

  if (!topItems.length) {
    return {
      brief:
        "No open findings across your monitored assets right now. Keep scheduled scans enabled and review any partial scan coverage notes periodically.",
      topItems: [],
    };
  }

  const lines = [
    `You have ${open.length} open finding${open.length === 1 ? "" : "s"}. Focus on these ${topItems.length} first:`,
    "",
    ...topItems.map(
      (item, i) =>
        `${i + 1}. [${item.severity.toUpperCase()}] ${item.title} on ${item.target} — ${item.remediation}`,
    ),
  ];

  return { brief: lines.join("\n"), topItems };
}

export async function generateWorkspaceBriefWithProvider({
  provider,
  apiKey,
  model,
  sites = [],
  findings = [],
  fetchImpl = fetch,
}) {
  const deterministic = buildDeterministicBrief({ sites, findings });
  if (!deterministic.topItems.length) {
    return { ...deterministic, model: null, generatedBy: "deterministic" };
  }

  const prompt = [
    `Summarize the top ${deterministic.topItems.length} security priorities for a small product team:`,
    "",
    ...deterministic.topItems.map(
      (item, index) =>
        `${index + 1}. [${item.severity}] ${item.title} (${item.target}) — ${item.remediation}`,
    ),
    "",
    "Write a calm, plain-text weekly priority brief under 160 words with numbered action items (no markdown symbols). Explain briefly why each item goes first and what exact first step to take. Do not invent findings.",
  ].join("\n");

  const chosen = model || PROVIDERS[provider].defaultModel;
  const out = await providerCaller(provider)({
    apiKey,
    model: chosen,
    prompt,
    fetchImpl,
  });

  return {
    brief: out.text,
    topItems: deterministic.topItems,
    model: `${provider}:${out.model}`,
    generatedBy: "ai",
  };
}

/** Cheap validation used when a key is added. */
export async function verifyProviderKey({ provider, apiKey, model, fetchImpl = fetch }) {
  return explainWithProvider({
    provider,
    apiKey,
    model,
    domain: "bulwark.app",
    finding: {
      title: "Key check",
      severity: "info",
      detail: "Confirm the provider key works.",
    },
    fetchImpl,
  });
}
