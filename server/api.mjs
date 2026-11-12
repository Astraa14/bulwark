import express from "express";
import { explainWithProvider } from "./ai.mjs";
import { getSettings, saveSettings, sendSlack } from "./alerts.mjs";
import { fetchPageSample } from "./checks.mjs";
import { addKey, deleteKey, listKeys, markKeyUsed, resolveKey } from "./keys.mjs";
import { adminClient } from "./lib.mjs";
import { verifyDomain } from "./verify.mjs";
import { scanSite } from "./worker.mjs";

const PORT = Number(process.env.PORT ?? process.env.API_PORT ?? 8787);
const app = express();

const allowedOrigins = new Set(
  [
    process.env.BULWARK_APP_URL,
    "http://localhost:8443",
    "http://127.0.0.1:8443",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
  ].filter(Boolean),
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed =
    origin &&
    (allowedOrigins.has(origin) ||
      /^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin) ||
      /^http:\/\/(localhost|127\.0\.0\.1):\d+$/i.test(origin));

  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Max-Age", "86400");
  }

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "64kb" }));

const db = adminClient();

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((err) => {
    console.error(err);
    res.status(500).json({ error: err.message });
  });

async function requireUser(req, res, next) {
  const header = req.headers.authorization ?? "";
  const jwt = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!jwt) return res.status(401).json({ error: "Missing bearer token" });

  const { data, error } = await db.auth.getUser(jwt);
  if (error || !data?.user) return res.status(401).json({ error: "Invalid session" });

  req.user = data.user;
  next();
}

async function ownedSite(userId, siteId) {
  if (!siteId) return null;
  const select = "id, domain, status, verify_token, scan_interval_minutes, page_sample, user_id";
  let { data, error } = await db
    .from("sites")
    .select(select)
    .eq("id", siteId)
    .eq("user_id", userId)
    .maybeSingle();

  // Pre-migration fallback when the defacement columns do not exist yet.
  if (error?.message?.includes("page_sample")) {
    const retry = await db
      .from("sites")
      .select("id, domain, status, verify_token, scan_interval_minutes, user_id")
      .eq("id", siteId)
      .eq("user_id", userId)
      .maybeSingle();
    data = retry.data;
    error = retry.error;
  }

  if (error) throw error;
  return data;
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "bulwark-api" }));

// ---------------------------------------------------------------------------
// Ownership + scanning
// ---------------------------------------------------------------------------
app.post(
  "/api/verify",
  requireUser,
  wrap(async (req, res) => {
    const site = await ownedSite(req.user.id, req.body?.siteId);
    if (!site) return res.status(404).json({ error: "Site not found" });

    const result = await verifyDomain(site.domain, site.verify_token);
    if (!result.ok) {
      return res.status(422).json({
        error: "Ownership could not be verified yet. DNS records can take a few minutes to propagate.",
      });
    }

    await db
      .from("sites")
      .update({ status: "verified", next_scan_at: new Date().toISOString() })
      .eq("id", site.id);

    res.json({ ok: true, method: result.method });
  }),
);

app.post(
  "/api/site/status",
  requireUser,
  wrap(async (req, res) => {
    const site = await ownedSite(req.user.id, req.body?.siteId);
    if (!site) return res.status(404).json({ error: "Site not found" });

    const action = req.body?.action;

    if (action === "pause") {
      if (site.status !== "verified") {
        return res.status(409).json({ error: "Only verified sites can be paused." });
      }
      await db.from("sites").update({ status: "paused" }).eq("id", site.id);
      return res.json({ ok: true, status: "paused" });
    }

    if (action === "resume") {
      if (site.status !== "paused") {
        return res.status(409).json({
          error: "This site has not been verified yet. Complete ownership verification first.",
        });
      }
      await db
        .from("sites")
        .update({ status: "verified", next_scan_at: new Date().toISOString() })
        .eq("id", site.id);
      return res.json({ ok: true, status: "verified" });
    }

    return res.status(400).json({ error: "Unknown action." });
  }),
);

app.post(
  "/api/scan",
  requireUser,
  wrap(async (req, res) => {
    const site = await ownedSite(req.user.id, req.body?.siteId);
    if (!site) return res.status(404).json({ error: "Site not found" });
    if (site.status !== "verified") {
      return res.status(409).json({ error: "Site is not verified yet" });
    }

    const out = await scanSite(db, site);
    res.json({ ok: true, ...out });
  }),
);

app.post(
  "/api/site/baseline",
  requireUser,
  wrap(async (req, res) => {
    const site = await ownedSite(req.user.id, req.body?.siteId);
    if (!site) return res.status(404).json({ error: "Site not found" });

    const sample = await fetchPageSample(site.domain).catch((err) => {
      throw Object.assign(new Error(err.message), { status: 422 });
    });

    await db
      .from("sites")
      .update({ page_sample: sample, page_sample_at: new Date().toISOString() })
      .eq("id", site.id);

    res.json({ ok: true });
  }),
);

// ---------------------------------------------------------------------------
// BYOK keys
// ---------------------------------------------------------------------------
app.get(
  "/api/keys",
  requireUser,
  wrap(async (req, res) => {
    res.json({ keys: await listKeys(db, req.user.id) });
  }),
);

app.post(
  "/api/keys",
  requireUser,
  wrap(async (req, res) => {
    try {
      const key = await addKey(db, req.user.id, req.body ?? {});
      res.status(201).json({ ok: true, key });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.delete(
  "/api/keys/:id",
  requireUser,
  wrap(async (req, res) => {
    await deleteKey(db, req.user.id, req.params.id);
    res.json({ ok: true });
  }),
);

// ---------------------------------------------------------------------------
// AI explanations (cached on the finding row)
// ---------------------------------------------------------------------------
app.post(
  "/api/explain",
  requireUser,
  wrap(async (req, res) => {
    const findingId = req.body?.findingId;
    if (!findingId) return res.status(400).json({ error: "Missing findingId" });

    const { data: finding, error } = await db
      .from("findings")
      .select("*, sites(id, domain, user_id)")
      .eq("id", findingId)
      .maybeSingle();

    if (error) throw new Error(error.message);
    if (!finding || finding.sites?.user_id !== req.user.id) {
      return res.status(404).json({ error: "Finding not found" });
    }

    if (finding.explanation && !req.body?.refresh) {
      return res.json({
        explanation: finding.explanation,
        model: finding.explanation_model,
        cached: true,
        explainedAt: finding.explained_at,
      });
    }

    const key = await resolveKey(db, req.user.id);
    if (!key) {
      return res.status(400).json({ error: "Add an OpenAI or Anthropic key before using AI explanations." });
    }

    let result;
    try {
      result = await explainWithProvider({
        provider: key.provider,
        apiKey: key.apiKey,
        model: key.model,
        domain: finding.sites.domain,
        finding,
      });
    } catch (err) {
      return res.status(422).json({ error: err.message });
    }

    await db
      .from("findings")
      .update({
        explanation: result.text,
        explanation_model: `${key.provider}:${result.model}`,
        explained_at: new Date().toISOString(),
      })
      .eq("id", finding.id);

    await markKeyUsed(db, key.id);

    res.json({
      explanation: result.text,
      model: `${key.provider}:${result.model}`,
      cached: false,
      explainedAt: new Date().toISOString(),
    });
  }),
);

// ---------------------------------------------------------------------------
// Settings + alerts
// ---------------------------------------------------------------------------
app.get(
  "/api/settings",
  requireUser,
  wrap(async (req, res) => {
    res.json({ settings: await getSettings(db, req.user.id) });
  }),
);

app.put(
  "/api/settings",
  requireUser,
  wrap(async (req, res) => {
    try {
      const settings = await saveSettings(db, req.user.id, req.body ?? {});
      res.json({ ok: true, settings });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.post(
  "/api/alerts/test",
  requireUser,
  wrap(async (req, res) => {
    const settings = await getSettings(db, req.user.id);
    const url = String(req.body?.webhookUrl ?? settings.slackWebhookUrl ?? "").trim();
    if (!url) return res.status(400).json({ error: "Add a Slack webhook URL first." });

    try {
      await sendSlack(
        url,
        `:white_check_mark: *Bulwark test alert*\nAlerts are wired up for ${req.user.email ?? "your workspace"}. New critical and high findings will land here.`,
      );
    } catch (err) {
      return res.status(422).json({ error: err.message });
    }

    res.json({ ok: true });
  }),
);

app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bulwark API listening on http://0.0.0.0:${PORT}`);
});
