import { decrypt, encrypt } from "./crypto.mjs";

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const ALERT_TIMEOUT_MS = 8000;
const RESEND_API_URL = "https://api.resend.com/emails";
const MAX_OUTBOX_ATTEMPTS = 5;
const DIGEST_INTERVAL_MS = 7 * 86_400_000;

/** Only Slack incoming-webhook URLs may be called by the server. */
export const SLACK_WEBHOOK_RE = /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+$/;

/** Only official Discord webhook URLs may be called by the server. */
export const DISCORD_WEBHOOK_RE =
  /^https:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{30,128}$/;

/** Strict single-address email check (rejects header injection / control chars). */
export const EMAIL_RE = /^[^\s@<>(),;:"\\[\]]+@[^\s@<>(),;:"\\[\]]+\.[^\s@<>(),;:"\\[\]]{2,}$/;

export function isSlackWebhookUrl(url) {
  return SLACK_WEBHOOK_RE.test(String(url ?? "").trim());
}

export function isDiscordWebhookUrl(url) {
  return DISCORD_WEBHOOK_RE.test(String(url ?? "").trim());
}

export function isValidAlertEmail(email) {
  const clean = String(email ?? "").trim();
  if (!clean || clean.length > 254 || /[\r\n]/.test(clean)) return false;
  return EMAIL_RE.test(clean);
}

export function isEmailDeliveryConfigured(env = process.env) {
  return Boolean(String(env?.RESEND_API_KEY ?? "").trim());
}

export function findingAppUrl(appUrl, finding) {
  if (!appUrl) return null;
  const base = String(appUrl).trim().replace(/\/+$/, "");
  if (!base) return null;
  if (finding?.id) return `${base}/threats/${encodeURIComponent(String(finding.id))}`;
  return base;
}

export const DEFAULT_SETTINGS = {
  scan_interval_minutes: 60,
  autonomy: "suggest",
  slack_webhook_url: null,
  slack_min_severity: "high",
  alerts_enabled: true,
  discord_alerts_enabled: false,
  email_alerts_enabled: false,
  alert_email: null,
  weekly_digest_enabled: false,
  last_digest_sent_at: null,
};

function shape(row, { slackWebhookUrl = null, discordWebhookUrl = null } = {}, env = process.env) {
  return {
    scanIntervalMinutes: row.scan_interval_minutes ?? 60,
    autonomy: row.autonomy ?? "suggest",
    slackWebhookUrl,
    slackMinSeverity: row.slack_min_severity ?? "high",
    alertsEnabled: row.alerts_enabled ?? true,
    discordWebhookUrl,
    discordAlertsEnabled: row.discord_alerts_enabled ?? false,
    emailAlertsEnabled: row.email_alerts_enabled ?? false,
    alertEmail: row.alert_email ?? null,
    weeklyDigestEnabled: row.weekly_digest_enabled ?? false,
    lastDigestSentAt: row.last_digest_sent_at ?? null,
    emailConfigured: isEmailDeliveryConfigured(env),
  };
}

async function readSlackWebhook(db, userId, row) {
  if (row?.slack_webhook_encrypted) {
    try {
      return decrypt(row.slack_webhook_encrypted);
    } catch {
      return null;
    }
  }

  const legacy = String(row?.slack_webhook_url ?? "").trim();
  if (!legacy) return null;

  try {
    const encrypted = encrypt(legacy);
    await db
      .from("user_settings")
      .update({ slack_webhook_encrypted: encrypted, slack_webhook_url: null })
      .eq("user_id", userId);
  } catch {
    // Keep serving legacy value if encryption key unavailable.
  }
  return legacy;
}

function readDiscordWebhook(row) {
  if (!row?.discord_webhook_encrypted) return null;
  try {
    return decrypt(row.discord_webhook_encrypted);
  } catch {
    return null;
  }
}

/** Returns defaults when the settings row (or table) does not exist yet. */
export async function getSettings(db, userId, { env = process.env } = {}) {
  const { data, error } = await db
    .from("user_settings")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    return { ...shape(DEFAULT_SETTINGS, {}, env), missing: true };
  }
  if (!data) return shape(DEFAULT_SETTINGS, {}, env);
  return shape(
    data,
    {
      slackWebhookUrl: await readSlackWebhook(db, userId, data),
      discordWebhookUrl: readDiscordWebhook(data),
    },
    env,
  );
}

export async function saveSettings(db, userId, patch, { env = process.env } = {}) {
  const update = { user_id: userId, updated_at: new Date().toISOString() };

  if (patch.scanIntervalMinutes !== undefined) {
    const minutes = Number(patch.scanIntervalMinutes);
    if (!Number.isFinite(minutes) || minutes < 5 || minutes > 1440) {
      throw new Error("Scan interval must be between 5 and 1440 minutes.");
    }
    update.scan_interval_minutes = Math.round(minutes);
  }
  if (patch.autonomy !== undefined) {
    if (!["suggest", "auto_fix"].includes(patch.autonomy)) throw new Error("Invalid autonomy value.");
    update.autonomy = patch.autonomy;
  }

  let patchedSlack = false;
  let slackWebhookUrl = null;
  if (patch.slackWebhookUrl !== undefined) {
    patchedSlack = true;
    const url = String(patch.slackWebhookUrl ?? "").trim();
    if (url && !isSlackWebhookUrl(url)) {
      throw new Error("That does not look like a Slack incoming webhook URL.");
    }
    slackWebhookUrl = url || null;
    update.slack_webhook_url = null;
    if (url) {
      try {
        update.slack_webhook_encrypted = encrypt(url);
      } catch {
        throw new Error(
          "Server encryption is not configured, so the webhook cannot be stored safely.",
        );
      }
    } else {
      update.slack_webhook_encrypted = null;
    }
  }

  let patchedDiscord = false;
  let discordWebhookUrl = null;
  if (patch.discordWebhookUrl !== undefined) {
    patchedDiscord = true;
    const url = String(patch.discordWebhookUrl ?? "").trim();
    if (url && !isDiscordWebhookUrl(url)) {
      throw new Error("That does not look like a Discord webhook URL.");
    }
    discordWebhookUrl = url || null;
    if (url) {
      try {
        update.discord_webhook_encrypted = encrypt(url);
      } catch {
        throw new Error(
          "Server encryption is not configured, so the webhook cannot be stored safely.",
        );
      }
    } else {
      update.discord_webhook_encrypted = null;
    }
  }

  if (patch.slackMinSeverity !== undefined) {
    if (!Object.keys(SEVERITY_RANK).includes(patch.slackMinSeverity)) {
      throw new Error("Invalid minimum severity.");
    }
    update.slack_min_severity = patch.slackMinSeverity;
  }
  if (patch.alertsEnabled !== undefined) update.alerts_enabled = Boolean(patch.alertsEnabled);
  if (patch.discordAlertsEnabled !== undefined) {
    update.discord_alerts_enabled = Boolean(patch.discordAlertsEnabled);
  }
  if (patch.emailAlertsEnabled !== undefined) {
    update.email_alerts_enabled = Boolean(patch.emailAlertsEnabled);
  }
  if (patch.weeklyDigestEnabled !== undefined) {
    update.weekly_digest_enabled = Boolean(patch.weeklyDigestEnabled);
  }
  if (patch.alertEmail !== undefined) {
    const email = String(patch.alertEmail ?? "").trim().toLowerCase();
    if (email && !isValidAlertEmail(email)) {
      throw new Error("Enter a valid email address for alerts.");
    }
    update.alert_email = email || null;
  }

  const { data, error } = await db
    .from("user_settings")
    .upsert(update, { onConflict: "user_id" })
    .select("*")
    .single();

  if (error) {
    if (
      /discord_webhook_encrypted|discord_alerts_enabled|email_alerts_enabled|alert_email|weekly_digest_enabled/i.test(
        error.message,
      )
    ) {
      throw new Error(
        "Latest alert columns are not set up yet. Run supabase/apply_all.sql in Supabase.",
      );
    }
    if (/user_settings|schema cache/i.test(error.message)) {
      throw new Error("Settings storage is not set up yet. Run the v1.1 migration in Supabase.");
    }
    throw new Error(`save settings: ${error.message}`);
  }

  return shape(
    data,
    {
      slackWebhookUrl: patchedSlack ? slackWebhookUrl : await readSlackWebhook(db, userId, data),
      discordWebhookUrl: patchedDiscord ? discordWebhookUrl : readDiscordWebhook(data),
    },
    env,
  );
}

export async function sendSlack(url, text, { fetchImpl = fetch } = {}) {
  if (!url) throw new Error("No Slack webhook configured.");
  if (!isSlackWebhookUrl(url)) {
    throw new Error("Refusing to send an alert to a non-Slack webhook URL.");
  }
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text }),
    redirect: "manual",
    signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error("Slack redirected the webhook request, so it was not followed.");
  }
  if (!res.ok) {
    throw new Error(`Slack returned HTTP ${res.status}.`);
  }
}

export async function sendDiscord(url, payload, { fetchImpl = fetch } = {}) {
  if (!url) throw new Error("No Discord webhook configured.");
  if (!isDiscordWebhookUrl(url)) {
    throw new Error("Refusing to send an alert to a non-Discord webhook URL.");
  }
  const body = typeof payload === "string" ? { content: payload } : payload;
  const res = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "manual",
    signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error("Discord redirected the webhook request, so it was not followed.");
  }
  if (!res.ok) {
    throw new Error(`Discord returned HTTP ${res.status}.`);
  }
}

export async function sendEmail(
  { to, subject, text, html },
  { fetchImpl = fetch, env = process.env } = {},
) {
  if (!isValidAlertEmail(to)) throw new Error("Enter a valid alert email address.");
  const apiKey = String(env?.RESEND_API_KEY ?? "").trim();
  if (!apiKey) {
    throw new Error("Server email delivery is not configured yet (set RESEND_API_KEY).");
  }
  const from = String(env?.BULWARK_EMAIL_FROM ?? "").trim() || "Bulwark Alerts <alerts@bulwark.app>";
  const res = await fetchImpl(RESEND_API_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ from, to: [to.trim()], subject, text, html }),
    redirect: "manual",
    signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error("Email provider redirected the request, so it was not followed.");
  }
  if (!res.ok) {
    throw new Error(`Email provider returned HTTP ${res.status}.`);
  }
}

const SEVERITY_EMOJI = {
  critical: ":red_circle:",
  high: ":large_orange_circle:",
  medium: ":large_yellow_circle:",
  low: ":large_blue_circle:",
  info: ":white_circle:",
};

const DISCORD_SEVERITY_COLOR = {
  critical: 0xdc2626,
  high: 0xea580c,
  medium: 0xca8a04,
  low: 0x2563eb,
  info: 0x64748b,
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pickWorst(findings) {
  return findings
    .slice()
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))[0];
}

export function formatSlackAlert({ site, findings, appUrl }) {
  const worst = pickWorst(findings);
  const leftovers = findings.length - 1;
  const link = findingAppUrl(appUrl, worst);

  const lines = [
    `${SEVERITY_EMOJI[worst.severity] ?? ""} *${worst.severity.toUpperCase()}* on *${site.domain}*`,
    `> ${worst.title}`,
  ];
  if (worst.detail) lines.push(`> ${worst.detail}`);
  if (leftovers > 0) lines.push(`_+${leftovers} more new finding${leftovers === 1 ? "" : "s"}_`);
  if (worst.url) lines.push(`<${worst.url}|View affected URL>`);
  if (link) lines.push(`<${link}|Open finding in Bulwark>`);
  return lines.join("\n");
}

export function formatDiscordAlert({ site, findings, appUrl }) {
  const worst = pickWorst(findings);
  const leftovers = findings.length - 1;
  const link = findingAppUrl(appUrl, worst);

  const descriptionParts = [`**${worst.title}**`];
  if (worst.detail) descriptionParts.push(worst.detail);
  if (leftovers > 0) {
    descriptionParts.push(`*+${leftovers} more new finding${leftovers === 1 ? "" : "s"}*`);
  }

  const fields = [];
  if (worst.url) {
    fields.push({ name: "Affected URL", value: String(worst.url).slice(0, 1000) });
  }
  if (link) {
    fields.push({ name: "Bulwark", value: `[Open finding](${link})` });
  }

  return {
    embeds: [
      {
        title: `${worst.severity.toUpperCase()} on ${site.domain}`,
        description: descriptionParts.join("\n\n").slice(0, 4000),
        color: DISCORD_SEVERITY_COLOR[worst.severity] ?? DISCORD_SEVERITY_COLOR.info,
        ...(link ? { url: link } : {}),
        ...(fields.length ? { fields } : {}),
        footer: { text: "Bulwark security monitoring" },
      },
    ],
  };
}

export function formatEmailAlert({ site, findings, appUrl }) {
  const worst = pickWorst(findings);
  const leftovers = findings.length - 1;
  const link = findingAppUrl(appUrl, worst);
  const severity = String(worst.severity ?? "info").toUpperCase();
  const subject = `[Bulwark · ${severity}] ${worst.title} on ${site.domain}`;

  const textLines = [
    `${severity} finding on ${site.domain}`,
    "",
    worst.title,
    ...(worst.detail ? ["", worst.detail] : []),
    ...(leftovers > 0
      ? ["", `+${leftovers} more new finding${leftovers === 1 ? "" : "s"} in this scan.`]
      : []),
    ...(worst.url ? ["", `Affected URL: ${worst.url}`] : []),
    ...(link ? ["", `Open in Bulwark: ${link}`] : []),
  ];

  const html = [
    `<div style="font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#171717;line-height:1.5;max-width:560px">`,
    `<p style="font-size:12px;letter-spacing:0.06em;text-transform:uppercase;color:#737373;margin:0 0 8px">Bulwark · ${escapeHtml(severity)} on ${escapeHtml(site.domain)}</p>`,
    `<h2 style="font-size:18px;margin:0 0 10px">${escapeHtml(worst.title)}</h2>`,
    worst.detail ? `<p style="margin:0 0 12px">${escapeHtml(worst.detail)}</p>` : "",
    leftovers > 0
      ? `<p style="color:#525252;margin:0 0 12px">+${leftovers} more new finding${leftovers === 1 ? "" : "s"} in this scan.</p>`
      : "",
    worst.url
      ? `<p style="margin:0 0 12px;font-size:13px">Affected URL: <a href="${escapeHtml(worst.url)}">${escapeHtml(worst.url)}</a></p>`
      : "",
    link
      ? `<p style="margin:18px 0 0"><a href="${escapeHtml(link)}" style="display:inline-block;background:#171717;color:#ffffff;padding:9px 14px;border-radius:6px;text-decoration:none;font-size:13px">Open finding in Bulwark</a></p>`
      : "",
    `</div>`,
  ].join("");

  return { subject, text: textLines.join("\n"), html };
}

// ---------------------------------------------------------------------------
// Weekly posture digest formatting
// ---------------------------------------------------------------------------
export function buildWeeklyDigestSummary({ sites = [], findings = [], now = new Date() }) {
  const cutoff = now.getTime() - DIGEST_INTERVAL_MS;
  const open = findings.filter((f) => f.status === "open");
  const resolvedRecently = findings.filter(
    (f) => f.status === "resolved" && new Date(f.last_seen_at ?? 0).getTime() >= cutoff,
  );
  const critical = open.filter((f) => f.severity === "critical").length;
  const high = open.filter((f) => f.severity === "high").length;
  const expiring = open.filter((f) =>
    ["tls_expiring", "tls_expiring_soon", "tls_expired", "domain_expiring", "domain_expiring_soon", "domain_expired"].includes(
      f.check_key,
    ),
  );

  return {
    sitesTotal: sites.length,
    sitesActive: sites.filter((s) => s.status === "verified").length,
    openTotal: open.length,
    critical,
    high,
    resolvedRecently: resolvedRecently.length,
    expiringCount: expiring.length,
    expiringTitles: expiring.slice(0, 3).map((f) => f.title),
  };
}

export function formatWeeklyDigest({ summary, appUrl }) {
  const base = appUrl ? String(appUrl).trim().replace(/\/+$/, "") : null;
  const headline =
    summary.critical + summary.high > 0
      ? `${summary.critical} critical · ${summary.high} high open findings`
      : summary.openTotal > 0
        ? `0 critical/high · ${summary.openTotal} lower-severity open`
        : "All clear — 0 open findings";

  const lines = [
    `Bulwark weekly security digest`,
    `Status: ${headline}`,
    `Sites monitored: ${summary.sitesActive} active of ${summary.sitesTotal}`,
    `Resolved in last 7 days: ${summary.resolvedRecently}`,
    ...(summary.expiringCount
      ? [`Expiring certs/domains: ${summary.expiringTitles.join("; ")}`]
      : []),
    ...(base ? [`Open dashboard: ${base}`] : []),
  ];

  const slack = [
    `:shield: *Bulwark weekly security digest*`,
    `> *${headline}*`,
    `> ${summary.sitesActive}/${summary.sitesTotal} sites actively scanning · ${summary.resolvedRecently} resolved this week`,
    ...(summary.expiringCount
      ? [`> Upcoming renewals: ${summary.expiringTitles.join(" · ")}`]
      : []),
    ...(base ? [`<${base}|Open Bulwark>`] : []),
  ].join("\n");

  const discord = {
    embeds: [
      {
        title: "Bulwark weekly security digest",
        description: `**${headline}**\n${summary.sitesActive}/${summary.sitesTotal} sites active · ${summary.resolvedRecently} resolved in the last 7 days`,
        color: summary.critical > 0 ? 0xdc2626 : summary.high > 0 ? 0xea580c : 0x16a34a,
        ...(base ? { url: base } : {}),
        ...(summary.expiringCount
          ? { fields: [{ name: "Upcoming renewals", value: summary.expiringTitles.join("\n") }] }
          : {}),
        footer: { text: "Bulwark weekly posture digest" },
      },
    ],
  };

  const email = {
    subject: `[Bulwark Weekly] ${headline}`,
    text: lines.join("\n"),
    html: [
      `<div style="font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#171717;line-height:1.5;max-width:560px">`,
      `<p style="font-size:12px;letter-spacing:0.06em;text-transform:uppercase;color:#737373;margin:0 0 8px">Bulwark · Weekly Security Digest</p>`,
      `<h2 style="font-size:18px;margin:0 0 12px">${escapeHtml(headline)}</h2>`,
      `<p style="margin:0 0 10px">Sites monitored: <strong>${summary.sitesActive}</strong> active of ${summary.sitesTotal} · Resolved in last 7 days: <strong>${summary.resolvedRecently}</strong></p>`,
      summary.expiringCount
        ? `<p style="margin:0 0 12px">Upcoming renewals: ${escapeHtml(summary.expiringTitles.join(", "))}</p>`
        : "",
      base
        ? `<p style="margin:18px 0 0"><a href="${escapeHtml(base)}" style="display:inline-block;background:#171717;color:#ffffff;padding:9px 14px;border-radius:6px;text-decoration:none;font-size:13px">Open Bulwark</a></p>`
        : "",
      `</div>`,
    ].join(""),
  };

  return { slack, discord, email };
}

// ---------------------------------------------------------------------------
// Durable alert delivery outbox + immediate fast-path delivery
// ---------------------------------------------------------------------------
async function dispatchChannel(channel, payload, settings, { fetchImpl = fetch, env = process.env } = {}) {
  if (channel === "slack") {
    if (!settings.slackWebhookUrl) throw new Error("No Slack webhook configured.");
    return sendSlack(settings.slackWebhookUrl, payload.text, { fetchImpl });
  }
  if (channel === "discord") {
    if (!settings.discordWebhookUrl) throw new Error("No Discord webhook configured.");
    return sendDiscord(settings.discordWebhookUrl, payload, { fetchImpl });
  }
  if (channel === "email") {
    if (!settings.alertEmail) throw new Error("No alert email configured.");
    return sendEmail({ to: settings.alertEmail, ...payload }, { fetchImpl, env });
  }
  throw new Error(`Unsupported channel: ${channel}`);
}

async function deliverOutboxRow(db, row, settings, { fetchImpl = fetch, env = process.env } = {}) {
  const attempts = Number(row.attempts ?? 1);
  try {
    await dispatchChannel(row.channel, row.payload, settings, { fetchImpl, env });
    if (row.id) {
      await db
        .from("alert_deliveries")
        .update({
          status: "sent",
          attempts,
          last_error: null,
          sent_at: new Date().toISOString(),
        })
        .eq("id", row.id);
    }
    return { ok: true, channel: row.channel };
  } catch (err) {
    const message = err?.message ?? String(err);
    const exhausted = attempts >= MAX_OUTBOX_ATTEMPTS;
    const delaySeconds = Math.min(30 * 60, attempts * attempts * 60);
    if (row.id) {
      await db
        .from("alert_deliveries")
        .update({
          status: exhausted ? "failed" : "queued",
          attempts,
          last_error: message,
          run_after: exhausted
            ? row.run_after ?? new Date().toISOString()
            : new Date(Date.now() + delaySeconds * 1000).toISOString(),
        })
        .eq("id", row.id);
    }
    return { ok: false, channel: row.channel, error: message };
  }
}

async function enqueueAndAttemptDeliveries(
  db,
  { userId, settings, entries, fetchImpl = fetch, env = process.env },
) {
  const channels = [];
  const errors = [];

  const outcomes = await Promise.all(
    entries.map(async (entry) => {
      let row = {
        id: null,
        channel: entry.channel,
        payload: entry.payload,
        attempts: 1,
      };
      // Best-effort durable insert into outbox (falls back cleanly if table not migrated yet).
      try {
        const { data, error } = await db
          .from("alert_deliveries")
          .insert({
            user_id: userId,
            channel: entry.channel,
            kind: entry.kind ?? "finding",
            target_label: entry.targetLabel,
            finding_count: entry.findingCount ?? 1,
            payload: entry.payload,
            status: "sending",
            attempts: 1,
          })
          .select("*")
          .single();
        if (!error && data) row = data;
      } catch {
        // Outbox table unavailable — deliver directly without persistence.
      }
      return deliverOutboxRow(db, row, settings, { fetchImpl, env });
    }),
  );

  for (const outcome of outcomes) {
    if (outcome.ok) channels.push(outcome.channel);
    else errors.push(`${outcome.channel}: ${outcome.error}`);
  }

  return { channels, errors };
}

/** Sends alerts across every enabled, configured channel for findings clearing the threshold. */
export async function alertNewFindings(
  db,
  { site, findings, userId, appUrl, fetchImpl = fetch, env = process.env },
) {
  if (!findings.length) return { sent: false, reason: "no findings", channels: [] };

  const settings = await getSettings(db, userId, { env });
  const threshold = SEVERITY_RANK[settings.slackMinSeverity] ?? 3;
  const worthy = findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= threshold);
  if (!worthy.length) return { sent: false, reason: "below threshold", channels: [] };

  const entries = [];
  if (settings.alertsEnabled && settings.slackWebhookUrl) {
    entries.push({
      channel: "slack",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: worthy.length,
      payload: { text: formatSlackAlert({ site, findings: worthy, appUrl }) },
    });
  }
  if (settings.discordAlertsEnabled && settings.discordWebhookUrl) {
    entries.push({
      channel: "discord",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: worthy.length,
      payload: formatDiscordAlert({ site, findings: worthy, appUrl }),
    });
  }
  if (settings.emailAlertsEnabled && settings.alertEmail && isEmailDeliveryConfigured(env)) {
    entries.push({
      channel: "email",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: worthy.length,
      payload: formatEmailAlert({ site, findings: worthy, appUrl }),
    });
  }

  if (!entries.length) {
    return { sent: false, reason: "no enabled alert channel", channels: [] };
  }

  const { channels, errors } = await enqueueAndAttemptDeliveries(db, {
    userId,
    settings,
    entries,
    fetchImpl,
    env,
  });

  if (channels.length === 0 && errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return { sent: channels.length > 0, count: worthy.length, channels, errors };
}

/** Sends an all-clear notification when a previously unreachable site responds again. */
export async function alertSiteRecovered(
  db,
  { site, httpStatus, responseMs, userId, appUrl, fetchImpl = fetch, env = process.env },
) {
  const settings = await getSettings(db, userId, { env });
  const statusText = httpStatus ? `HTTP ${httpStatus}` : "HTTPS OK";
  const timingText = Number.isFinite(responseMs) ? ` · ${responseMs} ms` : "";
  const cleanAppUrl = String(appUrl ?? "").replace(/\/+$/, "");

  const entries = [];
  if (settings.alertsEnabled && settings.slackWebhookUrl) {
    const lines = [
      `🟢 *RECOVERED* — *${site.domain}* is reachable again`,
      `> Responded with ${statusText}${timingText}. The \`site_unreachable\` alert has been resolved.`,
    ];
    if (cleanAppUrl) lines.push(`<${cleanAppUrl}/sites|View sites in Bulwark>`);
    entries.push({
      channel: "slack",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: 1,
      payload: { text: lines.join("\n") },
    });
  }
  if (settings.discordAlertsEnabled && settings.discordWebhookUrl) {
    entries.push({
      channel: "discord",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: 1,
      payload: {
        embeds: [
          {
            title: `RECOVERED: ${site.domain} is reachable again`,
            description: `Responded with **${statusText}**${timingText}. The \`site_unreachable\` finding has been automatically resolved.`,
            color: 0x16a34a,
            ...(cleanAppUrl ? { url: `${cleanAppUrl}/sites` } : {}),
            footer: { text: "Bulwark security monitoring" },
          },
        ],
      },
    });
  }
  if (settings.emailAlertsEnabled && settings.alertEmail && isEmailDeliveryConfigured(env)) {
    const subject = `[Bulwark · RECOVERED] ${site.domain} is reachable again`;
    const text = `${site.domain} is reachable again (${statusText}${timingText}).\n\nThe site_unreachable alert has been resolved.${cleanAppUrl ? `\n\nOpen Bulwark: ${cleanAppUrl}/sites` : ""}`;
    const html = [
      `<div style="font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#171717;line-height:1.5;max-width:560px">`,
      `<p style="font-size:12px;letter-spacing:0.06em;text-transform:uppercase;color:#15803d;font-weight:600;margin:0 0 8px">Bulwark · Recovered</p>`,
      `<h2 style="font-size:18px;margin:0 0 10px">${escapeHtml(site.domain)} is reachable again</h2>`,
      `<p style="margin:0 0 12px">Responded with <strong>${escapeHtml(statusText)}</strong>${escapeHtml(timingText)}. The <code>site_unreachable</code> finding has been resolved.</p>`,
      cleanAppUrl
        ? `<p style="margin:18px 0 0"><a href="${escapeHtml(`${cleanAppUrl}/sites`)}" style="display:inline-block;background:#171717;color:#ffffff;padding:9px 14px;border-radius:6px;text-decoration:none;font-size:13px">View sites in Bulwark</a></p>`
        : "",
      `</div>`,
    ].join("");
    entries.push({
      channel: "email",
      kind: "finding",
      targetLabel: site.domain,
      findingCount: 1,
      payload: { subject, text, html },
    });
  }

  if (!entries.length) {
    return { sent: false, reason: "no enabled alert channel", channels: [] };
  }

  const { channels, errors } = await enqueueAndAttemptDeliveries(db, {
    userId,
    settings,
    entries,
    fetchImpl,
    env,
  });

  return { sent: channels.length > 0, channels, errors };
}

/** Worker sweep: retries queued or stale alert_deliveries outbox rows. */
export async function processAlertDeliveries(
  db,
  { limit = 10, fetchImpl = fetch, env = process.env } = {},
) {
  const { data, error } = await db.rpc("claim_alert_deliveries", { p_limit: limit });
  if (error) throw new Error(`claim alert deliveries: ${error.message}`);

  const rows = Array.isArray(data) ? data : [];
  const results = [];
  for (const row of rows) {
    const settings = await getSettings(db, row.user_id, { env });
    results.push({
      id: row.id,
      ...(await deliverOutboxRow(db, row, settings, { fetchImpl, env })),
    });
  }
  return results;
}

export async function listAlertDeliveries(db, userId, { limit = 25 } = {}) {
  const { data, error } = await db
    .from("alert_deliveries")
    .select("id, channel, kind, target_label, finding_count, status, attempts, last_error, created_at, sent_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(limit);
  if (error) {
    if (/alert_deliveries|schema cache/i.test(error.message)) return [];
    throw new Error(`load alert deliveries: ${error.message}`);
  }
  return (data ?? []).map((row) => ({
    id: row.id,
    channel: row.channel,
    kind: row.kind,
    targetLabel: row.target_label,
    findingCount: row.finding_count,
    status: row.status,
    attempts: row.attempts,
    lastError: row.last_error,
    createdAt: row.created_at,
    sentAt: row.sent_at,
  }));
}

export async function sendWeeklyDigestForUser(
  db,
  userId,
  { appUrl, fetchImpl = fetch, env = process.env, force = false } = {},
) {
  const settings = await getSettings(db, userId, { env });
  if (!force && !settings.weeklyDigestEnabled) {
    return { sent: false, reason: "digest disabled", channels: [] };
  }

  const [sitesRes, findingsRes] = await Promise.all([
    db.from("sites").select("id, domain, status").eq("user_id", userId),
    db
      .from("findings")
      .select("id, check_key, title, severity, status, last_seen_at")
      .eq("user_id", userId),
  ]);
  const summary = buildWeeklyDigestSummary({
    sites: sitesRes.data ?? [],
    findings: findingsRes.data ?? [],
  });
  const formatted = formatWeeklyDigest({ summary, appUrl });

  const entries = [];
  if (settings.alertsEnabled && settings.slackWebhookUrl) {
    entries.push({
      channel: "slack",
      kind: "digest",
      targetLabel: "Weekly digest",
      findingCount: summary.openTotal,
      payload: { text: formatted.slack },
    });
  }
  if (settings.discordAlertsEnabled && settings.discordWebhookUrl) {
    entries.push({
      channel: "discord",
      kind: "digest",
      targetLabel: "Weekly digest",
      findingCount: summary.openTotal,
      payload: formatted.discord,
    });
  }
  if (settings.emailAlertsEnabled && settings.alertEmail && isEmailDeliveryConfigured(env)) {
    entries.push({
      channel: "email",
      kind: "digest",
      targetLabel: "Weekly digest",
      findingCount: summary.openTotal,
      payload: formatted.email,
    });
  }

  if (!entries.length) {
    return { sent: false, reason: "no enabled alert channel", channels: [], summary };
  }

  const { channels, errors } = await enqueueAndAttemptDeliveries(db, {
    userId,
    settings,
    entries,
    fetchImpl,
    env,
  });

  if (channels.length > 0) {
    await db
      .from("user_settings")
      .update({ last_digest_sent_at: new Date().toISOString() })
      .eq("user_id", userId);
  } else if (errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return { sent: channels.length > 0, channels, errors, summary };
}

export async function runDueWeeklyDigests(
  db,
  { appUrl, fetchImpl = fetch, env = process.env, logger = console } = {},
) {
  const { data, error } = await db
    .from("user_settings")
    .select("user_id, last_digest_sent_at")
    .eq("weekly_digest_enabled", true);
  if (error) {
    if (/weekly_digest_enabled|schema cache/i.test(error.message)) return [];
    throw new Error(`load digest subscribers: ${error.message}`);
  }

  const nowMs = Date.now();
  const due = (data ?? []).filter(
    (row) =>
      !row.last_digest_sent_at ||
      nowMs - new Date(row.last_digest_sent_at).getTime() >= DIGEST_INTERVAL_MS,
  );

  const results = [];
  for (const row of due) {
    try {
      results.push({
        userId: row.user_id,
        ...(await sendWeeklyDigestForUser(db, row.user_id, { appUrl, fetchImpl, env })),
      });
    } catch (err) {
      logger?.error?.(`weekly digest failed for ${row.user_id}: ${err.message}`);
      results.push({ userId: row.user_id, sent: false, error: err.message });
    }
  }
  return results;
}
