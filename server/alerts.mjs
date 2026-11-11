export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const DEFAULT_SETTINGS = {
  scan_interval_minutes: 60,
  autonomy: "suggest",
  slack_webhook_url: null,
  slack_min_severity: "high",
  alerts_enabled: true,
};

function shape(row) {
  return {
    scanIntervalMinutes: row.scan_interval_minutes ?? 60,
    autonomy: row.autonomy ?? "suggest",
    slackWebhookUrl: row.slack_webhook_url ?? null,
    slackMinSeverity: row.slack_min_severity ?? "high",
    alertsEnabled: row.alerts_enabled ?? true,
  };
}

/** Returns defaults when the settings row (or table) does not exist yet. */
export async function getSettings(db, userId) {
  const { data, error } = await db
    .from("user_settings")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    // Table not migrated yet, or no row. Defaults keep the app usable.
    return { ...shape(DEFAULT_SETTINGS), missing: true };
  }
  if (!data) return shape(DEFAULT_SETTINGS);
  return shape(data);
}

export async function saveSettings(db, userId, patch) {
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
  if (patch.slackWebhookUrl !== undefined) {
    const url = String(patch.slackWebhookUrl ?? "").trim();
    if (url && !/^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+$/.test(url)) {
      throw new Error("That does not look like a Slack incoming webhook URL.");
    }
    update.slack_webhook_url = url || null;
  }
  if (patch.slackMinSeverity !== undefined) {
    if (!Object.keys(SEVERITY_RANK).includes(patch.slackMinSeverity)) {
      throw new Error("Invalid minimum severity.");
    }
    update.slack_min_severity = patch.slackMinSeverity;
  }
  if (patch.alertsEnabled !== undefined) update.alerts_enabled = Boolean(patch.alertsEnabled);

  const { data, error } = await db
    .from("user_settings")
    .upsert(update, { onConflict: "user_id" })
    .select("*")
    .single();

  if (error) {
    if (/user_settings|schema cache/i.test(error.message)) {
      throw new Error("Settings storage is not set up yet. Run the v1.1 migration in Supabase.");
    }
    throw new Error(`save settings: ${error.message}`);
  }
  return shape(data);
}

export async function sendSlack(url, text) {
  if (!url) throw new Error("No Slack webhook configured.");
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Slack returned HTTP ${res.status}. ${body.slice(0, 160)}`);
  }
}

const SEVERITY_EMOJI = {
  critical: ":red_circle:",
  high: ":large_orange_circle:",
  medium: ":large_yellow_circle:",
  low: ":large_blue_circle:",
  info: ":white_circle:",
};

export function formatSlackAlert({ site, findings, appUrl }) {
  const worst = findings
    .slice()
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))[0];
  const leftovers = findings.length - 1;

  const lines = [
    `${SEVERITY_EMOJI[worst.severity] ?? ""} *${worst.severity.toUpperCase()}* on *${site.domain}*`,
    `> ${worst.title}`,
  ];
  if (worst.detail) lines.push(`> ${worst.detail}`);
  if (leftovers > 0) lines.push(`_+${leftovers} more new finding${leftovers === 1 ? "" : "s"}_`);
  if (worst.url) lines.push(`<${worst.url}|View affected URL>`);
  if (appUrl) lines.push(`<${appUrl}|Open Bulwark>`);
  return lines.join("\n");
}

/** Sends one Slack message for the freshly-inserted findings that clear the threshold. */
export async function alertNewFindings(db, { site, findings, userId, appUrl }) {
  if (!findings.length) return { sent: false, reason: "no findings" };

  const settings = await getSettings(db, userId);
  if (!settings.alertsEnabled) return { sent: false, reason: "alerts disabled" };
  if (!settings.slackWebhookUrl) return { sent: false, reason: "no webhook" };

  const threshold = SEVERITY_RANK[settings.slackMinSeverity] ?? 3;
  const worthy = findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= threshold);
  if (!worthy.length) return { sent: false, reason: "below threshold" };

  await sendSlack(
    settings.slackWebhookUrl,
    formatSlackAlert({ site, findings: worthy, appUrl }),
  );
  return { sent: true, count: worthy.length };
}
