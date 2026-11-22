import test from "node:test";
import assert from "node:assert/strict";

process.env.BULWARK_ENCRYPTION_KEY = "bulwark-test-encryption-key";

const {
  alertNewFindings,
  findingAppUrl,
  formatDiscordAlert,
  formatEmailAlert,
  formatSlackAlert,
  getSettings,
  isDiscordWebhookUrl,
  isValidAlertEmail,
  saveSettings,
  sendDiscord,
  sendEmail,
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
