import express from "express";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { decrypt, isEncryptionKeyConfigured } from "./crypto.mjs";
import {
  buildDeterministicBrief,
  explainWithProvider,
  generateWorkspaceBriefWithProvider,
} from "./ai.mjs";
import {
  getSettings,
  saveSettings,
  sendSlack,
  sendDiscord,
  sendEmail,
  isSlackWebhookUrl,
  isDiscordWebhookUrl,
  isValidAlertEmail,
  isEmailDeliveryConfigured,
  listAlertDeliveries,
  sendWeeklyDigestForUser,
} from "./alerts.mjs";
import { fetchPageSample } from "./checks.mjs";
import { addKey, deleteKey, listKeys, markKeyUsed, resolveKey } from "./keys.mjs";
import {
  addConnection,
  deleteConnection,
  listConnections,
  listGitHubSchedules,
  resolveConnection,
  setWebhookSecret,
  updateGitHubSchedule,
  updateSupabaseSchedule,
} from "./connections.mjs";
import { assertRepoCoordinates, checkRepoAccess, listGitHubRepos } from "./github.mjs";
import { adminClient } from "./lib.mjs";
import { verifyDomain } from "./verify.mjs";
import { readWorkerHeartbeat, scanSite } from "./worker.mjs";
import { scanGitHubConnection, scanSupabaseConnection, enqueuePlatformScan } from "./platform-scans.mjs";
import {
  MAX_WEBHOOK_BYTES,
  findWebhookConnection,
  parseGitHubPush,
} from "./webhooks.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------

function securityHeaders() {
  const baseCsp = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    // Vite emits external module scripts only; no inline script is required.
    "script-src 'self'",
    // React sets style attributes, and Google Fonts serves the stylesheet.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co",
    "frame-src 'none'",
  ];

  return (req, res, next) => {
    const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
    // Only ask for HTTPS upgrades on an HTTPS page; on plain-http localhost it
    // would rewrite the dev server's own requests to https and break them.
    const csp = [...baseCsp, ...(secure ? ["upgrade-insecure-requests"] : [])].join("; ");
    res.setHeader("Content-Security-Policy", csp);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    if (secure) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    next();
  };
}

/** Fixed-window in-memory limiter. Per process; front with an edge limiter for multi-instance. */
function rateLimit({ windowMs, max, scope }) {
  const buckets = new Map();

  return (req, res, next) => {
    const identity = req.user?.id ?? req.ip ?? "unknown";
    const key = `${scope}:${identity}`;
    const now = Date.now();
    let bucket = buckets.get(key);

    if (!bucket || now - bucket.start >= windowMs) {
      bucket = { start: now, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    if (buckets.size > 10_000) {
      for (const [entryKey, entry] of buckets) {
        if (now - entry.start >= windowMs) buckets.delete(entryKey);
      }
    }

    if (bucket.count > max) {
      res.setHeader("Retry-After", String(Math.ceil((bucket.start + windowMs - now) / 1000)));
      return res.status(429).json({ error: "Too many requests. Please slow down." });
    }
    next();
  };
}

/** Bounds how many scans (each with ~40 outbound requests) run at once. */
function createScanSemaphore(limit) {
  let active = 0;
  const waiting = [];

  return async (task) => {
    if (active >= limit) await new Promise((resolve) => waiting.push(resolve));
    active += 1;
    try {
      return await task();
    } finally {
      active -= 1;
      waiting.shift()?.();
    }
  };
}

const allowedOrigins = new Set(
  [
    process.env.BULWARK_APP_URL,
    // Deployment-specific origins (e.g. a Vercel preview) go here, comma
    // separated. Wildcarding *.vercel.app would let any Vercel tenant call
    // this API from a browser with the user's bearer token in scope.
    ...String(process.env.BULWARK_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    "http://localhost:8443",
    "http://127.0.0.1:8443",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
  ].filter(Boolean),
);

function createCors() {
  return (req, res, next) => {
    const origin = req.headers.origin;
    const allowed =
      origin &&
      (allowedOrigins.has(origin) || /^http:\/\/(localhost|127\.0\.0\.1):\d+$/i.test(origin));

    if (allowed) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      res.setHeader("Access-Control-Max-Age", "86400");
    }

    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  };
}

/**
 * Build the API without binding a port or reading process env for a database
 * client. Tests inject a fake database and fake outbound fetch.
 */
export function createApp({
  db,
  fetchImpl = fetch,
  osvFetchImpl = fetch,
  decryptSecret = decrypt,
  appUrl = process.env.BULWARK_APP_URL ?? "http://localhost:8443",
  logger = console,
  serveStatic = true,
} = {}) {
  if (!db) throw new Error("createApp requires a database client.");

  const app = express();

  // Behind Render's proxy, req.ip must come from X-Forwarded-For.
  app.set("trust proxy", 1);
  app.disable("x-powered-by");

  const wrap = (fn) => (req, res) =>
    fn(req, res).catch((err) => {
      const requestId = randomUUID();
      const status = Number.isInteger(err?.status) ? err.status : 500;
      logger.error?.(`[${requestId}] ${req.method} ${req.originalUrl}`, err);
      if (status >= 500) {
        // Never leak table names, SQL fragments or provider errors.
        return res
          .status(status)
          .json({ error: "Something went wrong. Please try again.", requestId });
      }
      res.status(status).json({ error: err?.message ?? "Request failed", requestId });
    });

  const apiLimiter = rateLimit({ windowMs: 60_000, max: 240, scope: "api" });
  const scanLimiter = rateLimit({ windowMs: 60_000, max: 6, scope: "scan" });
  const explainLimiter = rateLimit({ windowMs: 60_000, max: 10, scope: "explain" });
  const alertLimiter = rateLimit({ windowMs: 60_000, max: 5, scope: "alert" });
  const webhookLimiter = rateLimit({ windowMs: 60_000, max: 120, scope: "webhook" });
  const withScanSlot = createScanSemaphore(
    Math.max(1, Number(process.env.BULWARK_SCAN_CONCURRENCY ?? 2)),
  );

  async function requireUser(req, res, next) {
    try {
      const header = req.headers.authorization ?? "";
      const jwt = header.startsWith("Bearer ") ? header.slice(7) : null;
      if (!jwt) return res.status(401).json({ error: "Missing bearer token" });

      const { data, error } = await db.auth.getUser(jwt);
      if (error || !data?.user) return res.status(401).json({ error: "Invalid session" });

      req.user = data.user;
      next();
    } catch (err) {
      next(err);
    }
  }

  app.use(securityHeaders());
  app.use(createCors());
  app.use("/api", apiLimiter);

  app.get(
    "/api/health",
    wrap(async (_req, res) => {
      const encryptionConfigured = isEncryptionKeyConfigured();
      let dbOk = true;
      try {
        const { error } = await db.from("sites").select("id").limit(1);
        if (error) dbOk = false;
      } catch {
        dbOk = false;
      }
      const heartbeat = await readWorkerHeartbeat();
      const ok = encryptionConfigured && dbOk;
      res.status(ok ? 200 : 503).json({
        ok,
        service: "bulwark-api",
        commit: process.env.RENDER_GIT_COMMIT ?? null,
        checks: {
          database: dbOk ? "ok" : "error",
          encryptionKey: encryptionConfigured ? "ok" : "missing",
          workerHeartbeatAt: heartbeat?.at ?? null,
        },
      });
    }),
  );

  // -------------------------------------------------------------------------
  // GitHub webhook. This MUST be registered before express.json(): HMAC
  // verification needs the exact bytes GitHub signed, and a JSON parser would
  // replace them with a re-serialisable object.
  // -------------------------------------------------------------------------
  const webhookParser = express.raw({
    type: "application/json",
    limit: MAX_WEBHOOK_BYTES,
  });

  const handleGitHubWebhook = wrap(async (req, res) => {
    const signature = req.headers["x-hub-signature-256"];
    const event = req.headers["x-github-event"];
    const deliveryId = req.headers["x-github-delivery"];

    if (!signature) return res.status(401).json({ error: "Missing webhook signature" });
    if (!Buffer.isBuffer(req.body)) {
      return res.status(400).json({ error: "Expected an application/json webhook body" });
    }
    if (!deliveryId || typeof deliveryId !== "string") {
      return res.status(400).json({ error: "Missing X-GitHub-Delivery header" });
    }

    const matched = await findWebhookConnection({
      db,
      connectionId: req.params.connectionId ?? null,
      rawBody: req.body,
      signature,
      decryptSecret,
    });
    if (!matched) {
      return res.status(401).json({ error: "No matching webhook secret" });
    }

    if (event === "ping") return res.json({ ok: true, ping: true });
    if (event !== "push") return res.json({ ok: true, ignored: true });

    let push;
    try {
      push = parseGitHubPush(req.body);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }

    if (push.deleted || push.allZeroCommit) {
      return res.json({ ok: true, ignored: true, reason: "branch deleted" });
    }

    const connection = await resolveConnection(
      db,
      matched.user_id,
      matched.id,
      "github_connections",
    );
    if (!connection) {
      return res.status(401).json({ error: "Webhook connection is no longer usable" });
    }

    // The signature proves which secret signed the delivery. It does not prove
    // that this connection's token may read the repository named in the
    // payload, so check that before queueing any work.
    let authorized = false;
    try {
      authorized = await checkRepoAccess(connection.token, push.owner, push.repo, {
        fetchImpl,
      });
    } catch (err) {
      logger.error?.(`webhook repository check failed: ${err.message}`);
      return res.status(502).json({ error: "Could not verify repository access with GitHub" });
    }
    if (!authorized) {
      return res.status(403).json({
        error: "This connection is not authorized to scan that repository",
      });
    }

    const queued = await enqueuePlatformScan(db, {
      userId: matched.user_id,
      platform: "github",
      connectionId: matched.id,
      resource: push.resource,
      ref: push.ref,
      commitSha: push.after,
      deliveryId,
      scanId: randomUUID(),
    });

    return res.status(queued.duplicate ? 200 : 202).json({
      ok: true,
      duplicate: queued.duplicate,
      queued: !queued.duplicate,
      jobId: queued.jobId,
    });
  });

  // Webhook routes must be registered before express.json(): HMAC verification
  // needs the exact bytes GitHub signed, and the JSON parser consumes them.
  app.post("/api/webhooks/github", webhookLimiter, webhookParser, handleGitHubWebhook);
  app.post(
    "/api/webhooks/github/:connectionId",
    webhookLimiter,
    webhookParser,
    handleGitHubWebhook,
  );

  app.use(express.json({ limit: "64kb" }));

  // -------------------------------------------------------------------------
  // Read-only GitHub + Supabase connections (encrypted at rest)
  // -------------------------------------------------------------------------
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

      try {
        const repos = await listGitHubRepos(conn.token, { fetchImpl });
        res.json({ repos });
      } catch (err) {
        res.status(422).json({ error: err.message });
      }
    }),
  );

  const addGitHubConnection = wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "github_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/connections/github", requireUser, addGitHubConnection);
  app.post("/api/connections/github_connections", requireUser, addGitHubConnection);

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

  const addSupabaseConnection = wrap(async (req, res) => {
    try {
      const conn = await addConnection(db, req.user.id, "supabase_connections", req.body ?? {});
      res.status(201).json({ ok: true, connection: conn });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/connections/supabase", requireUser, addSupabaseConnection);
  app.post("/api/connections/supabase_connections", requireUser, addSupabaseConnection);

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
    scanLimiter,
    wrap(async (req, res) => {
      const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
      if (!conn) return res.status(404).json({ error: "GitHub connection not found" });

      const owner = String(req.body?.owner ?? "").trim();
      const repo = String(req.body?.repo ?? "").trim();
      if (!owner || !repo) return res.status(400).json({ error: "Missing owner and repo." });

      try {
        assertRepoCoordinates(owner, repo);
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }

      const sha = String(req.body?.sha ?? "").trim();
      const ref = String(req.body?.ref ?? "").trim();
      if (sha && !/^[0-9a-f]{7,64}$/i.test(sha)) {
        return res.status(400).json({ error: "Invalid commit SHA." });
      }
      if (ref && !/^refs\/heads\//.test(ref)) {
        return res.status(400).json({ error: "Invalid ref. Must be in refs/heads/ format." });
      }

      const authorized = await checkRepoAccess(conn.token, owner, repo, { fetchImpl });
      if (!authorized) {
        return res.status(403).json({
          error: "This connection is not authorized to scan that repository.",
        });
      }

      const out = await withScanSlot(() =>
        scanGitHubConnection({
          db,
          userId: req.user.id,
          connection: conn,
          owner,
          repo,
          sha: sha || null,
          ref: ref || null,
          fetchImpl,
          osvFetchImpl,
          appUrl,
          logger,
        }),
      );
      res.json({ ok: true, ...out });
    }),
  );

  app.post(
    "/api/connections/supabase/:id/scan",
    requireUser,
    scanLimiter,
    wrap(async (req, res) => {
      const conn = await resolveConnection(db, req.user.id, req.params.id, "supabase_connections");
      if (!conn) return res.status(404).json({ error: "Supabase connection not found" });

      const out = await withScanSlot(() =>
        scanSupabaseConnection({
          db,
          userId: req.user.id,
          connection: conn,
          fetchImpl,
          appUrl,
          logger,
        }),
      );
      res.json({ ok: true, ...out });
    }),
  );

  app.put(
    "/api/connections/supabase/:id/schedule",
    requireUser,
    wrap(async (req, res) => {
      try {
        const connection = await updateSupabaseSchedule(
          db,
          req.user.id,
          req.params.id,
          req.body ?? {},
        );
        if (!connection) return res.status(404).json({ error: "Supabase connection not found" });
        res.json({ ok: true, connection });
      } catch (err) {
        res.status(400).json({ error: err.message });
      }
    }),
  );

  app.post(
    "/api/connections/github/:id/webhook-secret",
    requireUser,
    wrap(async (req, res) => {
      const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
      if (!conn) return res.status(404).json({ error: "GitHub connection not found" });
      const { secret } = req.body ?? {};
      if (!secret || typeof secret !== "string" || secret.length < 16) {
        return res.status(400).json({ error: "Use a webhook secret of at least 16 characters." });
      }
      await setWebhookSecret(db, req.user.id, req.params.id, secret);
      res.json({ ok: true });
    }),
  );

  app.get(
    "/api/connections/github/:id/schedules",
    requireUser,
    wrap(async (req, res) => {
      const conn = await resolveConnection(db, req.user.id, req.params.id, "github_connections");
      if (!conn) return res.status(404).json({ error: "GitHub connection not found" });
      const schedules = await listGitHubSchedules(db, req.user.id, req.params.id);
      res.json({ schedules });
    }),
  );

  app.put(
    "/api/connections/github/:id/schedule",
    requireUser,
    wrap(async (req, res) => {
      const owner = String(req.body?.owner ?? "").trim();
      const repo = String(req.body?.repo ?? "").trim();
      try {
        assertRepoCoordinates(owner, repo);
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
      try {
        const schedule = await updateGitHubSchedule(db, req.user.id, req.params.id, req.body ?? {});
        if (!schedule) return res.status(404).json({ error: "GitHub connection not found" });
        res.json({ ok: true, schedule });
      } catch (err) {
        res.status(400).json({ error: err.message });
      }
    }),
  );

  // -------------------------------------------------------------------------
  // Platform findings (GitHub / Supabase scans, site_id = null)
  // -------------------------------------------------------------------------
  app.get(
    "/api/findings/platform",
    requireUser,
    wrap(async (req, res) => {
      const { data, error } = await db
        .from("findings")
        .select("*")
        .eq("user_id", req.user.id)
        .is("site_id", null)
        .order("last_seen_at", { ascending: false })
        .limit(200);
      if (error) throw new Error(`load platform findings: ${error.message}`);
      res.json({ findings: data ?? [] });
    }),
  );

  // -------------------------------------------------------------------------
  // Finding triage (status, snooze expiry, note) + 1-click re-check loop
  // -------------------------------------------------------------------------
  app.post(
    "/api/findings/:id/triage",
    requireUser,
    wrap(async (req, res) => {
      const findingId = req.params.id;
      const { data: finding, error: loadErr } = await db
        .from("findings")
        .select("*, sites(id, domain, user_id)")
        .eq("id", findingId)
        .maybeSingle();
      if (loadErr) throw new Error(loadErr.message);

      const owned =
        finding?.user_id === req.user.id ||
        (finding?.site_id && finding?.sites?.user_id === req.user.id);
      if (!finding || !owned) {
        return res.status(404).json({ error: "Finding not found" });
      }

      const patch = {};
      if (req.body?.status !== undefined) {
        const status = String(req.body.status);
        if (!["open", "acknowledged", "resolved", "ignored"].includes(status)) {
          return res.status(400).json({ error: "Invalid finding status." });
        }
        patch.status = status;
        if (status !== "ignored") patch.ignored_until = null;
      }

      if (req.body?.snoozeDays !== undefined && req.body?.snoozeDays !== null) {
        const days = Number(req.body.snoozeDays);
        if (!Number.isFinite(days) || days < 1 || days > 365) {
          return res.status(400).json({ error: "Snooze duration must be between 1 and 365 days." });
        }
        patch.status = "ignored";
        patch.ignored_until = new Date(Date.now() + Math.round(days) * 86_400_000).toISOString();
      } else if (req.body?.ignoredUntil === null) {
        patch.ignored_until = null;
      }

      if (req.body?.triageNote !== undefined) {
        const note = String(req.body.triageNote ?? "").trim();
        if (note.length > 500) {
          return res.status(400).json({ error: "Triage note must be 500 characters or fewer." });
        }
        patch.triage_note = note || null;
      }

      if (!Object.keys(patch).length) {
        return res.status(400).json({ error: "No triage fields provided." });
      }

      const { data: updated, error: updateErr } = await db
        .from("findings")
        .update(patch)
        .eq("id", finding.id)
        .select("*")
        .single();
      if (updateErr) {
        if (/ignored_until|triage_note/i.test(updateErr.message)) {
          return res.status(400).json({
            error: "Snooze and triage note columns are not migrated yet. Run supabase/apply_all.sql.",
          });
        }
        throw new Error(updateErr.message);
      }
      res.json({ ok: true, finding: updated });
    }),
  );

  app.post(
    "/api/findings/:id/recheck",
    requireUser,
    scanLimiter,
    wrap(async (req, res) => {
      const findingId = req.params.id;
      const { data: finding, error: loadErr } = await db
        .from("findings")
        .select("*, sites(id, domain, status, verify_token, scan_interval_minutes, page_sample, user_id)")
        .eq("id", findingId)
        .maybeSingle();
      if (loadErr) throw new Error(loadErr.message);

      const owned =
        finding?.user_id === req.user.id ||
        (finding?.site_id && finding?.sites?.user_id === req.user.id);
      if (!finding || !owned) {
        return res.status(404).json({ error: "Finding not found" });
      }

      let scanOut;
      if (finding.site_id) {
        const site = finding.sites ?? (await ownedSite(req.user.id, finding.site_id));
        if (!site) return res.status(404).json({ error: "Site not found" });
        if (site.status !== "verified") {
          return res.status(409).json({ error: "Verify this site before re-checking findings." });
        }
        scanOut = await withScanSlot(() => scanSite(db, site, { manual: true }));
      } else if (finding.platform === "supabase" && finding.connection_id) {
        const conn = await resolveConnection(
          db,
          req.user.id,
          finding.connection_id,
          "supabase_connections",
        );
        if (!conn) return res.status(404).json({ error: "Supabase connection no longer exists." });
        scanOut = await withScanSlot(() =>
          scanSupabaseConnection({
            db,
            userId: req.user.id,
            connection: conn,
            fetchImpl,
            appUrl,
            logger,
          }),
        );
      } else if (finding.platform === "github" && finding.connection_id && finding.resource) {
        const conn = await resolveConnection(
          db,
          req.user.id,
          finding.connection_id,
          "github_connections",
        );
        if (!conn) return res.status(404).json({ error: "GitHub connection no longer exists." });
        const [owner, repo] = String(finding.resource).split("/");
        assertRepoCoordinates(owner, repo);
        scanOut = await withScanSlot(() =>
          scanGitHubConnection({
            db,
            userId: req.user.id,
            connection: conn,
            owner,
            repo,
            ref: finding.ref ?? null,
            fetchImpl,
            osvFetchImpl,
            appUrl,
            logger,
          }),
        );
      } else {
        return res.status(400).json({ error: "This finding cannot be automatically re-checked." });
      }

      const { data: refreshed } = await db
        .from("findings")
        .select("id, status, last_seen_at")
        .eq("id", finding.id)
        .maybeSingle();

      const status = refreshed?.status ?? finding.status;
      res.json({
        ok: true,
        resolved: status === "resolved",
        status,
        scanStatus: scanOut?.status ?? "completed",
        scanId: scanOut?.scanId ?? null,
        error: scanOut?.error ?? null,
      });
    }),
  );

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
    scanLimiter,
    wrap(async (req, res) => {
      const site = await ownedSite(req.user.id, req.body?.siteId);
      if (!site) return res.status(404).json({ error: "Site not found" });
      if (site.status !== "verified") {
        return res.status(409).json({ error: "Site is not verified yet" });
      }

      const out = await withScanSlot(() => scanSite(db, site, { manual: true }));
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

  // Self-serve workspace + account deletion. Every table also cascades from
  // auth.users, but rows are removed explicitly first so a partially failed
  // auth deletion never leaves encrypted credentials behind.
  const ACCOUNT_TABLES = [
    "alert_deliveries",
    "platform_scan_jobs",
    "findings",
    "scans",
    "github_repositories",
    "github_connections",
    "supabase_connections",
    "api_keys",
    "sites",
    "user_settings",
  ];

  app.delete(
    "/api/account",
    requireUser,
    wrap(async (req, res) => {
      if (req.body?.confirm !== "DELETE") {
        return res.status(400).json({ error: 'Type "DELETE" to confirm account deletion.' });
      }
      const userId = req.user.id;
      for (const table of ACCOUNT_TABLES) {
        const { error } = await db.from(table).delete().eq("user_id", userId);
        if (error && !/does not exist|schema cache/i.test(error.message ?? "")) {
          throw new Error(`delete ${table}: ${error.message}`);
        }
      }
      await db.from("profiles").delete().eq("id", userId);

      if (typeof db.auth?.admin?.deleteUser === "function") {
        const { error } = await db.auth.admin.deleteUser(userId);
        if (error) throw new Error(`delete auth user: ${error.message}`);
      }
      logger.log?.(`account deleted: ${userId}`);
      res.json({ ok: true });
    }),
  );

  app.post(
    "/api/explain",
    requireUser,
    explainLimiter,
    wrap(async (req, res) => {
      const findingId = req.body?.findingId;
      if (!findingId) return res.status(400).json({ error: "Missing findingId" });

      const { data: finding, error } = await db
        .from("findings")
        .select("*, sites(id, domain, stack, user_id)")
        .eq("id", findingId)
        .maybeSingle();

      if (error) throw new Error(error.message);

      const ownedByUser =
        finding?.user_id === req.user.id ||
        (finding?.site_id && finding?.sites?.user_id === req.user.id);
      if (!finding || !ownedByUser) {
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
        return res
          .status(400)
          .json({ error: "Add an OpenAI, Anthropic, or Gemini key before using AI explanations." });
      }

      const subject =
        finding.sites?.domain ??
        finding.resource ??
        finding.affected_resource ??
        "platform scan";

      let result;
      try {
        result = await explainWithProvider({
          provider: key.provider,
          apiKey: key.apiKey,
          model: key.model,
          domain: subject,
          stack: finding.sites?.stack ?? null,
          finding,
          fetchImpl,
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

  app.post(
    "/api/copilot/brief",
    requireUser,
    explainLimiter,
    wrap(async (req, res) => {
      const [sitesRes, findingsRes] = await Promise.all([
        db.from("sites").select("id, domain, status").eq("user_id", req.user.id),
        db
          .from("findings")
          .select("id, site_id, platform, resource, check_key, title, severity, status, detail, remediation, last_seen_at")
          .eq("user_id", req.user.id)
          .order("last_seen_at", { ascending: false })
          .limit(200),
      ]);
      const sites = sitesRes.data ?? [];
      const findings = findingsRes.data ?? [];

      const wantAi = req.body?.useAi !== false;
      const key = wantAi ? await resolveKey(db, req.user.id) : null;
      if (!key) {
        const deterministic = buildDeterministicBrief({ sites, findings });
        return res.json({
          ok: true,
          ...deterministic,
          model: null,
          generatedBy: "deterministic",
        });
      }

      try {
        const brief = await generateWorkspaceBriefWithProvider({
          provider: key.provider,
          apiKey: key.apiKey,
          model: key.model,
          sites,
          findings,
          fetchImpl,
        });
        await markKeyUsed(db, key.id);
        return res.json({ ok: true, ...brief });
      } catch (err) {
        return res.status(422).json({ error: err.message });
      }
    }),
  );

  app.get(
    "/api/alerts/deliveries",
    requireUser,
    wrap(async (req, res) => {
      const deliveries = await listAlertDeliveries(db, req.user.id);
      res.json({ deliveries });
    }),
  );

  app.post(
    "/api/alerts/digest/test",
    requireUser,
    alertLimiter,
    wrap(async (req, res) => {
      try {
        const out = await sendWeeklyDigestForUser(db, req.user.id, {
          appUrl,
          fetchImpl,
          force: true,
        });
        if (!out.sent) {
          return res.status(400).json({
            error: "Enable at least one alert channel (Slack, Discord, or Email) first.",
          });
        }
        res.json({ ok: true, channels: out.channels, summary: out.summary });
      } catch (err) {
        res.status(422).json({ error: err.message });
      }
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
    alertLimiter,
    wrap(async (req, res) => {
      const channel = String(req.body?.channel ?? "slack").trim().toLowerCase();
      const settings = await getSettings(db, req.user.id);

      if (channel === "slack") {
        const url = String(req.body?.webhookUrl ?? settings.slackWebhookUrl ?? "").trim();
        if (!url) return res.status(400).json({ error: "Add a Slack webhook URL first." });
        if (!isSlackWebhookUrl(url)) {
          return res
            .status(400)
            .json({ error: "That does not look like a Slack incoming webhook URL." });
        }

        try {
          await sendSlack(
            url,
            `:white_check_mark: *Bulwark test alert*\nAlerts are wired up for ${req.user.email ?? "your workspace"}. New findings above your threshold will land here.`,
            { fetchImpl },
          );
        } catch (err) {
          return res.status(422).json({ error: err.message });
        }

        return res.json({ ok: true, channel: "slack" });
      }

      if (channel === "discord") {
        const url = String(req.body?.webhookUrl ?? settings.discordWebhookUrl ?? "").trim();
        if (!url) return res.status(400).json({ error: "Add a Discord webhook URL first." });
        if (!isDiscordWebhookUrl(url)) {
          return res
            .status(400)
            .json({ error: "That does not look like a Discord webhook URL." });
        }

        try {
          await sendDiscord(
            url,
            {
              embeds: [
                {
                  title: "Bulwark test alert",
                  description: `Alerts are wired up for **${req.user.email ?? "your workspace"}**. New findings above your threshold will land here.`,
                  color: 0x16a34a,
                  footer: { text: "Bulwark security monitoring" },
                },
              ],
            },
            { fetchImpl },
          );
        } catch (err) {
          return res.status(422).json({ error: err.message });
        }

        return res.json({ ok: true, channel: "discord" });
      }

      if (channel === "email") {
        const to = String(req.body?.email ?? settings.alertEmail ?? req.user.email ?? "").trim();
        if (!to) return res.status(400).json({ error: "Add an alert email address first." });
        if (!isValidAlertEmail(to)) {
          return res.status(400).json({ error: "Enter a valid email address for alerts." });
        }
        if (!isEmailDeliveryConfigured()) {
          return res.status(400).json({
            error: "Server email delivery is not configured yet (set RESEND_API_KEY).",
          });
        }

        try {
          await sendEmail(
            {
              to,
              subject: "[Bulwark] Test security alert",
              text: `Bulwark email alerts are wired up for ${req.user.email ?? "your workspace"}. New findings above your severity threshold will arrive here.`,
              html: `<p>Bulwark email alerts are wired up for <strong>${(req.user.email ?? "your workspace").replace(/[<>&"]/g, "")}</strong>. New findings above your severity threshold will arrive here.</p>`,
            },
            { fetchImpl },
          );
        } catch (err) {
          return res.status(422).json({ error: err.message });
        }

        return res.json({ ok: true, channel: "email" });
      }

      return res.status(400).json({ error: "Unsupported alert channel." });
    }),
  );

  if (serveStatic) {
    app.use(express.static(path.join(__dirname, "../dist")));
    app.get("/{*path}", (req, res, next) => {
      if (req.path === "/api" || req.path.startsWith("/api/")) return next();
      res.sendFile(path.join(__dirname, "../dist/index.html"));
    });
  }

  app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

  // JSON error responses for parser failures (bad JSON, oversized body) so
  // webhook providers and browsers never receive an HTML stack page.
  app.use((err, _req, res, _next) => {
    if (err?.type === "entity.too.large") {
      return res.status(413).json({ error: "Request body is too large." });
    }
    if (err instanceof SyntaxError && "body" in err) {
      return res.status(400).json({ error: "Invalid JSON body." });
    }
    const requestId = randomUUID();
    logger.error?.(`[${requestId}] unhandled request error`, err);
    const status = Number.isInteger(err?.status) ? err.status : 500;
    res.status(status).json({
      error: status >= 500 ? "Something went wrong. Please try again." : "Request failed.",
      requestId,
    });
  });

  return app;
}

/** Entry point used by `npm run api` / `node server/api.mjs`. */
export function startApi() {
  const port = Number(process.env.PORT ?? process.env.API_PORT ?? 8787);
  const app = createApp({ db: adminClient() });
  return app.listen(port, "0.0.0.0", () => {
    console.log(`Bulwark API listening on http://0.0.0.0:${port}`);
  });
}
