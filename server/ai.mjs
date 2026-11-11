/**
 * BYOK provider adapters. Only OpenAI and Anthropic are supported.
 * Keys are decrypted in memory for the duration of one request and never logged.
 */

export const PROVIDERS = {
  openai: {
    label: "OpenAI",
    defaultModel: "gpt-4o-mini",
    docs: "https://platform.openai.com/api-keys",
  },
  anthropic: {
    label: "Anthropic",
    defaultModel: "claude-3-5-haiku-latest",
    docs: "https://console.anthropic.com/settings/keys",
  },
};

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

async function callOpenAI({ apiKey, model, prompt }) {
  const t = timeout(45_000);
  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
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
          {
            role: "system",
            content:
              "You are a pragmatic security engineer. You explain findings to developers who ship fast and are not security specialists. Be concrete, calm, and specific. No preamble.",
          },
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

async function callAnthropic({ apiKey, model, prompt }) {
  const t = timeout(45_000);
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
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
        system:
          "You are a pragmatic security engineer. You explain findings to developers who ship fast and are not security specialists. Be concrete, calm, and specific. No preamble.",
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

export function buildExplanationPrompt({ finding, domain }) {
  const lines = [
    `A security scanner found this on ${domain}:`,
    "",
    `Finding: ${finding.title}`,
    `Severity: ${finding.severity}`,
    `What the scanner observed: ${finding.detail ?? "n/a"}`,
  ];
  if (finding.evidence) lines.push(`Evidence: ${finding.evidence}`);
  if (finding.url) lines.push(`Affected URL: ${finding.url}`);
  lines.push(
    "",
    "Write three short labelled parts, plain text, no markdown symbols:",
    "1. What this means — 2 sentences in everyday language.",
    "2. Why it matters — 1 sentence about the realistic risk for a small product.",
    "3. How to fix it — 2 to 4 numbered, concrete steps.",
    "Keep the whole answer under 170 words. Do not invent facts that are not in the finding.",
  );
  return lines.join("\n");
}

/** Calls the user's provider. Throws a human-readable Error on failure. */
export async function explainWithProvider({ provider, apiKey, model, finding, domain }) {
  if (!isProvider(provider)) throw new Error("Unsupported AI provider.");
  const chosen = model || PROVIDERS[provider].defaultModel;
  const prompt = buildExplanationPrompt({ finding, domain });
  const fn = provider === "openai" ? callOpenAI : callAnthropic;
  return fn({ apiKey, model: chosen, prompt });
}

/** Cheap validation used when a key is added. */
export async function verifyProviderKey({ provider, apiKey, model }) {
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
  });
}
