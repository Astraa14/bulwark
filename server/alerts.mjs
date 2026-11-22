import { decrypt, encrypt } from "./crypto.mjs";

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const ALERT_TIMEOUT_MS = 8000;
const RESEND_API_URL = "https://api.resend.com/emails";

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
    emailConfigured: isEmailDeliveryConfigured(env),
  };
}

/**
 * Webhook URLs are bearer secrets: anyone holding one can post to the channel.
 * They are encrypted at rest. Rows written before encryption existed are
 * adopted (encrypted, plaintext cleared) the first time they are read.
 */
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
    // No encryption key available: keep serving the legacy value so alerts
    // still work, but do not pretend the row is encrypted.
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
    // Table not migrated yet, or no row. Defaults keep the app usable.
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
    if (/discord_webhook_encrypted|discord_alerts_enabled|email_alerts_enabled|alert_email/i.test(error.message)) {
      throw new Error(
        "Discord and email alert columns are not set up yet. Run supabase/apply_all.sql in Supabase.",
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
    // Do not echo the response body: this is an outbound request to a
    // user-influenced URL, so the body could leak internal data.
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

  const tasks = [];
  if (settings.alertsEnabled && settings.slackWebhookUrl) {
    tasks.push({
      channel: "slack",
      run: () =>
        sendSlack(settings.slackWebhookUrl, formatSlackAlert({ site, findings: worthy, appUrl }), {
          fetchImpl,
        }),
    });
  }
  if (settings.discordAlertsEnabled && settings.discordWebhookUrl) {
    tasks.push({
      channel: "discord",
      run: () =>
        sendDiscord(
          settings.discordWebhookUrl,
          formatDiscordAlert({ site, findings: worthy, appUrl }),
          { fetchImpl },
        ),
    });
  }
  if (settings.emailAlertsEnabled && settings.alertEmail && isEmailDeliveryConfigured(env)) {
    const email = formatEmailAlert({ site, findings: worthy, appUrl });
    tasks.push({
      channel: "email",
      run: () => sendEmail({ to: settings.alertEmail, ...email }, { fetchImpl, env }),
    });
  }

  if (!tasks.length) {
    return { sent: false, reason: "no enabled alert channel", channels: [] };
  }

  const settled = await Promise.allSettled(tasks.map((task) => task.run()));
  const channels = [];
  const errors = [];
  settled.forEach((outcome, index) => {
    const name = tasks[index].channel;
    if (outcome.status === "fulfilled") channels.push(name);
    else errors.push(`${name}: ${outcome.reason?.message ?? String(outcome.reason)}`);
  });

  if (channels.length === 0 && errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return { sent: channels.length > 0, count: worthy.length, channels, errors };
}
