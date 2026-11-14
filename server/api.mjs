import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { decrypt } from "./crypto.mjs";
import { explainWithProvider } from "./ai.mjs";
import { getSettings, saveSettings, sendSlack, alertNewFindings } from "./alerts.mjs";
import { fetchPageSample } from "./checks.mjs";
import { addKey, deleteKey, listKeys, markKeyUsed, resolveKey } from "./keys.mjs";
import {
  addConnection,
  deleteConnection,
  listConnections,
  resolveConnection,
  setWebhookSecret,
} from "./connections.mjs";
import { scanGitHubRepo } from "./github.mjs";
import { scanSupabaseProject } from "./supabase.mjs";
import { adminClient } from "./lib.mjs";
import { verifyDomain } from "./verify.mjs";
import { scanSite } from "./worker.mjs";

const PORT = Number(process.env.PORT ?? process.env.API_PORT ?? 8787);
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

app.use(express.static(path.join(__dirname, "../dist")));
app.use(express.json({ limit: "64kb" }));

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

// ---------------------------------------------------------------------------
// Read-only GitHub + Supabase connections (encrypted at rest)
// ---------------------------------------------------------------------------

app.get(
  "/api/connections/github",
  requireUser,
  wrap(async (req, res) => {
    res.json({ connections: await listConnections(db, req.user.id, "github_connections") });
  }),
);

app.get(
  "/api/connections/github_connections",
  requireUser,
  wrap(async (req, res) => {
    res.json({ connections: await listConnections(db, req.user.id, "github_connections") });
  }),
);

app.get(
  "/api/connections/github/:id/repos",
  requireUser,
  wrap(async (req, res) => {
    const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
    if (!conn) return res.status(404).json({ error: "GitHub connection not found" });

    const res2 = await fetch(`https://api.github.com/user/repos?per_page=100&sort=updated`, {
      headers: {
        authorization: `Bearer ${conn.token}`,
        "user-agent": "BulwarkBot/0.5",
        accept: "application/vnd.github+json",
      },
    });
    if (!res2.ok) {
      const body = await res2.text().catch(() => "");
      throw new Error(`GitHub API ${res2.status}: ${body.slice(0, 200)}`);
    }
    const repos = await res2.json();
    res.json({
      repos: repos.map((r) => ({
        full_name: r.full_name,
        owner: r.owner.login,
        name: r.name,
        private: r.private,
      })),
    });
  }),
);

app.post(
  "/api/connections/github",
  requireUser,
  wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "github_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.post(
  "/api/connections/github_connections",
  requireUser,
  wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "github_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.delete(
  "/api/connections/github/:id",
  requireUser,
  wrap(async (req, res) => {
    await deleteConnection(db, req.user.id, req.params.id, "github_connections");
    res.json({ ok: true });
  }),
);

app.get(
  "/api/connections/supabase",
  requireUser,
  wrap(async (req, res) => {
    res.json({ connections: await listConnections(db, req.user.id, "supabase_connections") });
  }),
);

app.get(
  "/api/connections/supabase_connections",
  requireUser,
  wrap(async (req, res) => {
    res.json({ connections: await listConnections(db, req.user.id, "supabase_connections") });
  }),
);

app.post(
  "/api/connections/supabase",
  requireUser,
  wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "supabase_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.post(
  "/api/connections/supabase_connections",
  requireUser,
  wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "supabase_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }),
);

app.delete(
  "/api/connections/supabase/:id",
  requireUser,
  wrap(async (req, res) => {
    await deleteConnection(db, req.user.id, req.params.id, "supabase_connections");
    res.json({ ok: true });
  }),
);

app.post(
  "/api/connections/github/:id/scan",
  requireUser,
  wrap(async (req, res) => {
    const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
    if (!conn) return res.status(404).json({ error: "GitHub connection not found" });

    const { owner, repo } = req.body ?? {};
    if (!owner || !repo) {
      return res.status(400).json({ error: "Missing owner and repo." });
    }

    const result = await scanGitHubRepo(conn.token, owner, repo);

    await db.from("github_connections").update({ last_checked_at: new Date().toISOString() }).eq("id", req.params.id);

    const startedAt = new Date().toISOString();
    const finishedAt = new Date().toISOString();

    const { data: scan, error: scanError } = await db
      .from("scans")
      .insert({
        site_id: null,
        status: result.error ? "failed" : "completed",
        http_status: null,
        response_ms: null,
        checks_total: 1,
        checks_passed: result.error ? 0 : 1,
        checks_errored: result.error ? 1 : 0,
        checks_skipped: 0,
        check_results: { github_scan: result.error ? "error" : "pass" },
        error: result.error ?? null,
        started_at: startedAt,
        finished_at: finishedAt,
      })
      .select("id")
      .single();

    if (scanError) throw new Error(`insert scan: ${scanError.message}`);

    const findingRows = (result.findings ?? []).map((f) => ({
      scan_id: scan.id,
      site_id: null,
      check_key: f.check_key ?? "github_finding",
      title: f.title ?? "GitHub finding",
      severity: f.severity ?? "medium",
      status: "open",
      detail: f.detail ?? null,
      evidence: f.evidence ?? null,
      url: f.url ?? null,
      affected_resource: f.affected_resource ?? null,
      first_seen_at: finishedAt,
      last_seen_at: finishedAt,
    }));

    if (findingRows.length) {
      const { error: insertError } = await db.from("findings").insert(findingRows);
      if (insertError) throw new Error(`insert findings: ${insertError.message}`);
    }

    res.json({ ok: true, scanId: scan.id, ...result });
  }),
);

app.post(
  "/api/connections/supabase/:id/scan",
  requireUser,
  wrap(async (req, res) => {
    const conn = await resolveConnection(db, req.user.id, req.params.id, "supabase_connections");
    if (!conn) return res.status(404).json({ error: "Supabase connection not found" });

    const result = await scanSupabaseProject(conn.projectUrl, conn.apiKey);

    await db.from("supabase_connections").update({ last_checked_at: new Date().toISOString() }).eq("id", req.params.id);

    const startedAt = new Date().toISOString();
    const finishedAt = new Date().toISOString();

    const { data: scan, error: scanError } = await db
      .from("scans")
      .insert({
        site_id: null,
        status: result.error ? "failed" : "completed",
        http_status: null,
        response_ms: null,
        checks_total: 1,
        checks_passed: result.error ? 0 : 1,
        checks_errored: result.error ? 1 : 0,
        checks_skipped: 0,
        check_results: { supabase_scan: result.error ? "error" : "pass" },
        error: result.error ?? null,
        started_at: startedAt,
        finished_at: finishedAt,
      })
      .select("id")
      .single();

    if (scanError) throw new Error(`insert scan: ${scanError.message}`);

    const findingRows = (result.findings ?? []).map((f) => ({
      scan_id: scan.id,
      site_id: null,
      check_key: f.check_key ?? "supabase_finding",
      title: f.title ?? "Supabase finding",
      severity: f.severity ?? "medium",
      status: "open",
      detail: f.detail ?? null,
      evidence: f.evidence ?? null,
      url: f.url ?? null,
      affected_resource: f.affected_resource ?? null,
      first_seen_at: finishedAt,
      last_seen_at: finishedAt,
    }));

    if (findingRows.length) {
      const { error: insertError } = await db.from("findings").insert(findingRows);
      if (insertError) throw new Error(`insert findings: ${insertError.message}`);
    }

    res.json({ ok: true, scanId: scan.id, ...result });
  }),
);

app.post(
  "/api/connections/github/:id/webhook-secret",
  requireUser,
  wrap(async (req, res) => {
    const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
    if (!conn) return res.status(404).json({ error: "GitHub connection not found" });
    const { secret } = req.body ?? {};
    if (!secret || typeof secret !== "string") {
      return res.status(400).json({ error: "Missing webhook secret." });
    }
    await setWebhookSecret(db, req.user.id, req.params.id, secret);
    res.json({ ok: true });
  }),
);

// ---------------------------------------------------------------------------
// GitHub webhook (no bearer token — validated by HMAC signature)
// ---------------------------------------------------------------------------

app.post(
  "/api/webhooks/github",
  express.raw({ type: "*/*" }),
  wrap(async (req, res) => {
    const signature = req.headers["x-hub-signature-256"];
    const event = req.headers["x-github-event"];
    const deliveryId = req.headers["x-github-delivery"];

    if (!signature || !event) {
      return res.status(401).json({ error: "Missing GitHub webhook headers" });
    }

    const { data: connections, error: connError } = await db
      .from("github_connections")
      .select("*")
      .not("webhook_secret_encrypted", "is", null);
    if (connError) throw new Error(`load connections: ${connError.message}`);

    let matched = null;
    for (const row of connections ?? []) {
      try {
        const secret = decrypt(row.webhook_secret_encrypted);
        const expected = createHmac("sha256", secret).update(req.body).digest("hex");
        if (timingSafeEqual(Buffer.from(`sha256=${expected}`), Buffer.from(signature))) {
          matched = row;
          break;
        }
      } catch {
        // Skip connections whose secret can't be decrypted.
      }
    }

    if (!matched) {
      return res.status(401).json({ error: "No matching webhook secret" });
    }

    if (event !== "push") {
      return res.json({ ok: true, ignored: true });
    }

    const payload = JSON.parse(req.body.toString("utf8"));
    const { repository, ref, after, before } = payload;
    if (!repository || !after) {
      return res.status(400).json({ error: "Invalid push payload" });
    }

    const owner = repository.owner.login;
    const repo = repository.name;
    const conn = await resolveConnection(db, matched.user_id, matched.id, "github_connections");
    if (!conn) {
      return res.status(404).json({ error: "Connection not found" });
    }

    if (matched.last_scanned_commit === after) {
      return res.json({ ok: true, skipped: true, reason: "already scanned" });
    }

    const result = await scanGitHubRepo(conn.token, owner, repo);

    await db
      .from("github_connections")
      .update({ last_scanned_commit: after, last_checked_at: new Date().toISOString() })
      .eq("id", matched.id);

    const { data: priorFindings, error: priorError } = await db
      .from("findings")
      .select("id, check_key, title, severity, status, affected_resource, evidence, detail, url")
      .eq("site_id", null)
      .eq("user_id", matched.user_id)
      .eq("status", "open")
      .order("last_seen_at", { ascending: false });
    if (priorError) throw new Error(`load prior findings: ${priorError.message}`);

    const priorKeys = new Set(
      (priorFindings ?? []).map((f) => `${f.check_key}\0${f.affected_resource ?? ""}`),
    );

    const newFindings = (result.findings ?? []).filter(
      (f) => !priorKeys.has(`${f.check_key}\0${f.affected_resource ?? ""}`),
    );

    if (newFindings.length > 0 && matched.user_id) {
      const { data: site } = await db
        .from("sites")
        .select("id, domain, user_id")
        .eq("user_id", matched.user_id)
        .limit(1)
        .maybeSingle();

      try {
        await alertNewFindings(db, {
          site: site
            ? { id: site.id, domain: site.domain, user_id: matched.user_id }
            : { id: null, domain: `${owner}/${repo}`, user_id: matched.user_id },
          findings: newFindings,
          userId: matched.user_id,
          appUrl: process.env.BULWARK_APP_URL ?? "http://localhost:8443",
        });
      } catch (err) {
        console.error(`slack alert failed for ${owner}/${repo}: ${err.message}`);
      }
    }

    res.json({
      ok: true,
      repository: `${owner}/${repo}`,
      commit: after,
      findings: result.findings.length,
      newFindings: newFindings.length,
    });
  }),
);

// ---------------------------------------------------------------------------
// Platform findings (GitHub / Supabase scans, site_id = null)
// ---------------------------------------------------------------------------

app.get(
  "/api/findings/platform",
  requireUser,
  wrap(async (req, res) => {
    const { data, error } = await db
      .from("findings")
      .select("*")
      .is("site_id", null)
      .order("last_seen_at", { ascending: false })
      .limit(200);
    if (error) throw new Error(`load platform findings: ${error.message}`);
    res.json({ findings: data ?? [] });
  }),
);

const db = adminClient();

async function ownedSite(userId, siteId) {
  if (!siteId) return null;
  const select = "id, domain, status, verify_token, scan_interval_minutes, page_sample, user_id";
  let { data, error } = await db
    .from("sites")
    .select(select)
    .eq("id", siteId)
    .eq("user_id", userId)
    .maybeSingle();

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

app.get("/api/health", (_req, res) =>
  res.json({
    ok: true,
    service: "bulwark-api",
    commit: process.env.RENDER_GIT_COMMIT ?? null,
  }),
);

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

app.get("/{*path}", (req, res, next) => {
  if (req.path === "/api" || req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "../dist/index.html"));
});

app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bulwark API listening on http://0.0.0.0:${PORT}`);
});
