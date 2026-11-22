import test from "node:test";
import assert from "node:assert/strict";

process.env.BULWARK_ENCRYPTION_KEY = "bulwark-test-encryption-key";

const {
  alertNewFindings,
  buildWeeklyDigestSummary,
  findingAppUrl,
  formatDiscordAlert,
  formatEmailAlert,
  formatSlackAlert,
  formatWeeklyDigest,
  getSettings,
  isDiscordWebhookUrl,
  isValidAlertEmail,
  listAlertDeliveries,
  processAlertDeliveries,
  runDueWeeklyDigests,
  saveSettings,
  sendDiscord,
  sendEmail,
  sendWeeklyDigestForUser,
} = await import("./alerts.mjs");
const { createFakeDb } = await import("./test-support/fake-db.mjs");

const SLACK_URL = ["https://hooks.slack.com", "services", "T0000", "B0000", "fakeTestWebhookToken"].join("/");
const DISCORD_URL = [
  "https://discord.com/api/webhooks",
  "123456789012345678",
  "abcdefghijklmnopqrstuvwxyz0123456789_ABCDE",
].join("/");

test("findingAppUrl builds deep links to /threats/:id", () => {
  assert.equal(
    findingAppUrl("https://app.bulwark.dev/", { id: "f-123" }),
    "https://app.bulwark.dev/threats/f-123",
  );
  assert.equal(findingAppUrl("https://app.bulwark.dev/", {}), "https://app.bulwark.dev");
  assert.equal(findingAppUrl("", { id: "f-123" }), null);
});

test("Slack, Discord, and Email formatters include finding deep links and escape email HTML", () => {
  const payload = {
    site: { domain: "acme.dev" },
    appUrl: "https://app.bulwark.dev",
    findings: [
      {
        id: "find-1",
        severity: "critical",
        title: "Leaked <script>alert(1)</script> key",
        detail: "Found in bundle",
        url: "https://acme.dev/app.js",
      },
      {
        id: "find-2",
        severity: "low",
        title: "Minor header",
      },
    ],
  };

  const slack = formatSlackAlert(payload);
  assert.match(slack, /https:\/\/app\.bulwark\.dev\/threats\/find-1/);
  assert.match(slack, /\+1 more new finding/);

  const discord = formatDiscordAlert(payload);
  assert.equal(discord.embeds.length, 1);
  assert.equal(discord.embeds[0].url, "https://app.bulwark.dev/threats/find-1");
  assert.equal(discord.embeds[0].color, 0xdc2626);
  assert.match(discord.embeds[0].description, /\+1 more new finding/);

  const email = formatEmailAlert(payload);
  assert.match(email.subject, /CRITICAL/);
  assert.match(email.text, /https:\/\/app\.bulwark\.dev\/threats\/find-1/);
  assert.match(email.html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.ok(!email.html.includes("<script>"), "email HTML must escape finding titles");
});

test("Discord webhook allowlist rejects arbitrary hosts and sendDiscord blocks before fetching", async () => {
  assert.equal(isDiscordWebhookUrl(DISCORD_URL), true);
  assert.equal(
    isDiscordWebhookUrl(
      ["https://canary.discord.com/api/webhooks", "123456789012345678", "abcdefghijklmnopqrstuvwxyz0123456789_ABCDE"].join("/"),
    ),
    true,
  );
  assert.equal(isDiscordWebhookUrl("http://169.254.169.254/latest/meta-data/"), false);
  assert.equal(isDiscordWebhookUrl("https://evil.example.com/api/webhooks/123/abc"), false);
  assert.equal(isDiscordWebhookUrl("https://discord.com/api/webhooks/notanumber/short"), false);

  let fetched = false;
  await assert.rejects(
    () =>
      sendDiscord("http://127.0.0.1:8787/internal", "hi", {
        fetchImpl: async () => {
          fetched = true;
          return new Response("ok");
        },
      }),
    /non-Discord webhook URL/,
  );
  assert.equal(fetched, false);
});

test("Email validator rejects header injection and sendEmail requires RESEND_API_KEY", async () => {
  assert.equal(isValidAlertEmail("founder@acme.dev"), true);
  assert.equal(isValidAlertEmail("founder@acme.dev\r\nBcc: evil@attacker.com"), false);
  assert.equal(isValidAlertEmail("not-an-email"), false);

  let fetched = false;
  await assert.rejects(
    () =>
      sendEmail(
        { to: "founder@acme.dev", subject: "Test", text: "Hi", html: "<p>Hi</p>" },
        {
          env: {},
          fetchImpl: async () => {
            fetched = true;
            return new Response("{}");
          },
        },
      ),
    /RESEND_API_KEY/,
  );
  assert.equal(fetched, false);
});

test("saveSettings encrypts Discord webhooks and preserves untouched channels", async () => {
  const db = createFakeDb({ tables: { user_settings: [] } });

  const first = await saveSettings(db, "user-a", {
    slackWebhookUrl: SLACK_URL,
    alertsEnabled: true,
    slackMinSeverity: "high",
  });
  assert.equal(first.slackWebhookUrl, SLACK_URL);

  const second = await saveSettings(db, "user-a", {
    discordWebhookUrl: DISCORD_URL,
    discordAlertsEnabled: true,
    alertEmail: "Owner@Acme.dev",
    emailAlertsEnabled: true,
  });
  assert.equal(second.slackWebhookUrl, SLACK_URL, "Slack webhook stays intact on partial patch");
  assert.equal(second.discordWebhookUrl, DISCORD_URL);
  assert.equal(second.discordAlertsEnabled, true);
  assert.equal(second.alertEmail, "owner@acme.dev");
  assert.equal(second.emailAlertsEnabled, true);

  const stored = db.tables.get("user_settings")[0];
  assert.ok(stored.discord_webhook_encrypted, "Discord webhook is stored encrypted");
  assert.ok(
    !String(stored.discord_webhook_encrypted).includes(DISCORD_URL),
    "Discord ciphertext does not contain plaintext URL",
  );

  const reloaded = await getSettings(db, "user-a");
  assert.equal(reloaded.slackWebhookUrl, SLACK_URL);
  assert.equal(reloaded.discordWebhookUrl, DISCORD_URL);
});

test("alertNewFindings delivers across Slack, Discord, and Email and isolates channel failures", async () => {
  const db = createFakeDb({ tables: { user_settings: [] } });
  await saveSettings(db, "user-a", {
    slackWebhookUrl: SLACK_URL,
    alertsEnabled: true,
    discordWebhookUrl: DISCORD_URL,
    discordAlertsEnabled: true,
    alertEmail: "founder@acme.dev",
    emailAlertsEnabled: true,
    slackMinSeverity: "high",
  });

  const sentUrls = [];
  const fetchImpl = async (url) => {
    const target = String(url);
    sentUrls.push(target);
    // Simulate Slack outage while Discord and Resend succeed.
    if (target === SLACK_URL) return new Response("error", { status: 500 });
    return new Response(JSON.stringify({ id: "ok" }), { status: 200 });
  };

  const result = await alertNewFindings(db, {
    site: { domain: "acme.dev" },
    userId: "user-a",
    appUrl: "https://app.bulwark.dev",
    findings: [{ id: "f-99", severity: "critical", title: "Exposed .env", detail: "Publicly readable" }],
    fetchImpl,
    env: { RESEND_API_KEY: "re_test_123", BULWARK_EMAIL_FROM: "Bulwark <alerts@acme.dev>" },
  });

  assert.equal(result.sent, true);
  assert.deepEqual(result.channels.sort(), ["discord", "email"]);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /slack: Slack returned HTTP 500/);
  assert.equal(sentUrls.length, 3);
});

test("failed alerts queue in alert_deliveries and succeed on outbox retry", async () => {
  const db = createFakeDb({
    tables: { user_settings: [], alert_deliveries: [] },
    rpcHandlers: {
      claim_alert_deliveries: (_args, fakeDb) => {
        const rows = fakeDb.tables.get("alert_deliveries") ?? [];
        const claimed = rows.filter((r) => r.status === "queued");
        for (const row of claimed) {
          row.status = "sending";
          row.attempts = Number(row.attempts ?? 0) + 1;
        }
        return { data: claimed.map((r) => ({ ...r })), error: null };
      },
    },
  });

  await saveSettings(db, "user-a", {
    slackWebhookUrl: SLACK_URL,
    alertsEnabled: true,
    slackMinSeverity: "high",
  });

  // First attempt fails -> queued for retry in outbox.
  await assert.rejects(
    () =>
      alertNewFindings(db, {
        site: { domain: "acme.dev" },
        userId: "user-a",
        appUrl: "https://app.bulwark.dev",
        findings: [{ id: "f-1", severity: "critical", title: "Exposed .env" }],
        fetchImpl: async () => new Response("err", { status: 503 }),
      }),
    /Slack returned HTTP 503/,
  );

  let history = await listAlertDeliveries(db, "user-a");
  assert.equal(history.length, 1);
  assert.equal(history[0].status, "queued");
  assert.equal(history[0].attempts, 1);

  // Worker drains outbox -> succeeds on retry.
  const retried = await processAlertDeliveries(db, {
    fetchImpl: async () => new Response("ok", { status: 200 }),
  });
  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);

  history = await listAlertDeliveries(db, "user-a");
  assert.equal(history[0].status, "sent");
  assert.equal(history[0].attempts, 2);
});

test("weekly posture digest formats summary and sends only for due subscribers", async () => {
  const summary = buildWeeklyDigestSummary({
    sites: [
      { id: "s1", domain: "acme.dev", status: "verified" },
      { id: "s2", domain: "staging.acme.dev", status: "paused" },
    ],
    findings: [
      { id: "f1", check_key: "tls_expiring", title: "TLS expires in 10 days", severity: "high", status: "open", last_seen_at: new Date().toISOString() },
      { id: "f2", check_key: "header_hsts", title: "Missing HSTS", severity: "medium", status: "resolved", last_seen_at: new Date().toISOString() },
    ],
  });
  assert.equal(summary.sitesActive, 1);
  assert.equal(summary.high, 1);
  assert.equal(summary.resolvedRecently, 1);
  assert.equal(summary.expiringCount, 1);

  const formatted = formatWeeklyDigest({ summary, appUrl: "https://app.bulwark.dev" });
  assert.match(formatted.slack, /weekly security digest/i);
  assert.match(formatted.email.subject, /1 high open/);

  const db = createFakeDb({
    tables: {
      user_settings: [],
      alert_deliveries: [],
      sites: [{ id: "s1", user_id: "user-a", domain: "acme.dev", status: "verified" }],
      findings: [],
    },
  });
  await saveSettings(db, "user-a", {
    slackWebhookUrl: SLACK_URL,
    alertsEnabled: true,
    weeklyDigestEnabled: true,
  });

  const sent = [];
  const firstRun = await runDueWeeklyDigests(db, {
    appUrl: "https://app.bulwark.dev",
    fetchImpl: async (url) => {
      sent.push(String(url));
      return new Response("ok", { status: 200 });
    },
  });
  assert.equal(firstRun.length, 1);
  assert.equal(firstRun[0].sent, true);
  assert.equal(sent.length, 1);

  // Immediately running again does not double-send within the 7-day window.
  const secondRun = await runDueWeeklyDigests(db, {
    appUrl: "https://app.bulwark.dev",
    fetchImpl: async () => new Response("ok", { status: 200 }),
  });
  assert.equal(secondRun.length, 0);

  // Force send preview works anytime.
  const preview = await sendWeeklyDigestForUser(db, "user-a", {
    appUrl: "https://app.bulwark.dev",
    force: true,
    fetchImpl: async () => new Response("ok", { status: 200 }),
  });
  assert.equal(preview.sent, true);
});
