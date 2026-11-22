import { useEffect, useState } from "react";
import { ConnectionsSection } from "@/components/ConnectionsSection";
import { PlatformFindingsSection } from "@/components/PlatformFindingsSection";
import { Button, Dot, PageTitle, Toggle } from "@/components/Ui";
import { apiPost } from "@/lib/api";
import type { IntegrationTab } from "@/lib/router";
import { SEVERITY_ORDER } from "@/lib/scanOutcomes";
import {
  listAlertDeliveries,
  sendTestDigest,
  shortDate,
  type addConnection,
  type AlertDeliveryRow,
  type ConnectionRow,
  type ConnectionType,
  type FindingRow,
  type FindingStatus,
  type ScanConnectionResult,
  type Settings,
  type Severity,
} from "@/lib/workspace";

export function Integrations({
  activeTab,
  onTabChange,
  settings,
  onSave,
  onChanged,
  email,
  connections,
  loading,
  error,
  onAddConnection,
  onRemoveConnection,
  onScanConnection,
  onUpdateSupabaseSchedule,
  platformFindings,
  platformFindingsLoading,
  onSetPlatformFindingStatus,
  onOpenFinding,
  onSetWebhookSecret,
}: {
  activeTab: IntegrationTab;
  onTabChange: (tab: IntegrationTab) => void;
  settings: Settings | null;
  onSave: (patch: Partial<Settings>) => Promise<Settings>;
  onChanged: () => void;
  email?: string | null;
  connections: ConnectionRow[];
  loading: boolean;
  error: string | null;
  onAddConnection: (input: Parameters<typeof addConnection>[0]) => Promise<void>;
  onRemoveConnection: (id: string, type: ConnectionType) => Promise<void>;
  onScanConnection: (
    id: string,
    type: ConnectionType,
    repo?: { owner: string; repo: string },
  ) => Promise<ScanConnectionResult>;
  onUpdateSupabaseSchedule: (
    id: string,
    input: { autoScanEnabled?: boolean; scanIntervalMinutes?: number },
  ) => Promise<void>;
  platformFindings: FindingRow[];
  platformFindingsLoading: boolean;
  onSetPlatformFindingStatus: (id: string, status: FindingStatus) => Promise<void>;
  onOpenFinding: (finding: FindingRow) => void;
  onSetWebhookSecret: (id: string, secret: string) => Promise<void>;
}) {
  const [slackWebhook, setSlackWebhook] = useState(settings?.slackWebhookUrl ?? "");
  const [showSlackWebhook, setShowSlackWebhook] = useState(false);
  const [slackEnabled, setSlackEnabled] = useState(
    Boolean(settings?.slackWebhookUrl && settings?.alertsEnabled),
  );

  const [discordWebhook, setDiscordWebhook] = useState(settings?.discordWebhookUrl ?? "");
  const [showDiscordWebhook, setShowDiscordWebhook] = useState(false);
  const [discordEnabled, setDiscordEnabled] = useState(
    Boolean(settings?.discordWebhookUrl && settings?.discordAlertsEnabled),
  );

  const [alertEmail, setAlertEmail] = useState(settings?.alertEmail ?? email ?? "");
  const [emailEnabled, setEmailEnabled] = useState(Boolean(settings?.emailAlertsEnabled));
  const [weeklyDigestEnabled, setWeeklyDigestEnabled] = useState(
    Boolean(settings?.weeklyDigestEnabled),
  );

  const [severity, setSeverity] = useState<Severity>(settings?.slackMinSeverity ?? "high");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [alertError, setAlertError] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<AlertDeliveryRow[]>([]);
  const [deliveriesLoading, setDeliveriesLoading] = useState(false);

  const loadDeliveries = async () => {
    setDeliveriesLoading(true);
    try {
      setDeliveries(await listAlertDeliveries());
    } catch {
      setDeliveries([]);
    } finally {
      setDeliveriesLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "alerts") void loadDeliveries();
  }, [activeTab]);

  useEffect(() => {
    if (!settings) return;
    setSlackWebhook(settings.slackWebhookUrl ?? "");
    setSlackEnabled(Boolean(settings.slackWebhookUrl && settings.alertsEnabled));
    setDiscordWebhook(settings.discordWebhookUrl ?? "");
    setDiscordEnabled(Boolean(settings.discordWebhookUrl && settings.discordAlertsEnabled));
    setAlertEmail(settings.alertEmail ?? email ?? "");
    setEmailEnabled(Boolean(settings.emailAlertsEnabled));
    setWeeklyDigestEnabled(Boolean(settings.weeklyDigestEnabled));
    setSeverity(settings.slackMinSeverity);
  }, [settings, email]);

  const saveAlerts = async () => {
    setBusy("save");
    setAlertError(null);
    setMessage(null);
    try {
      await onSave({
        slackWebhookUrl: slackWebhook,
        alertsEnabled: slackEnabled && Boolean(slackWebhook.trim()),
        discordWebhookUrl: discordWebhook,
        discordAlertsEnabled: discordEnabled && Boolean(discordWebhook.trim()),
        alertEmail: alertEmail.trim() || null,
        emailAlertsEnabled: emailEnabled && Boolean(alertEmail.trim()),
        weeklyDigestEnabled,
        slackMinSeverity: severity,
      });
      onChanged();
      setMessage("Alert settings saved.");
    } catch (err) {
      setAlertError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const testChannel = async (channel: "slack" | "discord" | "email") => {
    setBusy(`test-${channel}`);
    setAlertError(null);
    setMessage(null);
    try {
      if (channel === "slack") {
        if (!slackWebhook.trim()) {
          throw new Error("Add a Slack webhook URL before sending a test message.");
        }
        await apiPost("/api/alerts/test", { channel: "slack", webhookUrl: slackWebhook });
        setMessage("Slack test sent. Save changes separately to keep this configuration.");
      } else if (channel === "discord") {
        if (!discordWebhook.trim()) {
          throw new Error("Add a Discord webhook URL before sending a test message.");
        }
        await apiPost("/api/alerts/test", { channel: "discord", webhookUrl: discordWebhook });
        setMessage("Discord test sent. Save changes separately to keep this configuration.");
      } else {
        if (!alertEmail.trim()) {
          throw new Error("Enter an alert email address before sending a test email.");
        }
        await apiPost("/api/alerts/test", { channel: "email", email: alertEmail.trim() });
        setMessage("Test email sent. Save changes separately to keep this configuration.");
      }
    } catch (err) {
      setAlertError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const triggerDigestPreview = async () => {
    setBusy("digest");
    setAlertError(null);
    setMessage(null);
    try {
      const res = await sendTestDigest();
      setMessage(`Weekly digest sent via ${res.channels.join(", ")}.`);
      void loadDeliveries();
    } catch (err) {
      setAlertError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const slackConfigured = Boolean(slackWebhook.trim());
  const discordConfigured = Boolean(discordWebhook.trim());
  const emailConfiguredOnServer = Boolean(settings?.emailConfigured);
  const emailReady = Boolean(alertEmail.trim());
  const anyChannelEnabled =
    (slackConfigured && slackEnabled) ||
    (discordConfigured && discordEnabled) ||
    (emailReady && emailEnabled && emailConfiguredOnServer);

  return (
    <>
      <PageTitle
        title="Integrations"
        subtitle="Send alerts to your team, and connect the platforms Bulwark scans."
      />
      <div className="tabs" role="tablist" aria-label="Integration sections">
        {(
          [
            { id: "alerts", label: "Alerts", count: undefined },
            { id: "platforms", label: "Platform connections", count: connections.length },
            { id: "findings", label: "Platform findings", count: platformFindings.length },
          ] as const
        ).map((item) => (
          <button
            type="button"
            role="tab"
            key={item.id}
            aria-selected={activeTab === item.id}
            className={activeTab === item.id ? "selected" : ""}
            onClick={() => onTabChange(item.id)}
          >
            {item.label}
            {item.count !== undefined && <small>{item.count}</small>}
          </button>
        ))}
      </div>
      {activeTab === "alerts" && (
        <div className="integration-body">
          <div className="api-grid">
            <div className="alert-stack">
              <section className="card setting-list">
                <div className="setting-title">
                  <h3>Delivery threshold &amp; weekly digest</h3>
                  <p>
                    Applies across Slack, Discord, and email alerts. Failed deliveries retry
                    automatically via the alert outbox.
                  </p>
                </div>
                <div className="setting-row">
                  <span>
                    <strong>Minimum severity</strong>
                    <small>Lower severities are still recorded in the app.</small>
                  </span>
                  <select
                    className="inline-select"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as Severity)}
                  >
                    {SEVERITY_ORDER.map((s) => (
                      <option value={s} key={s}>
                        {s[0].toUpperCase() + s.slice(1)} and above
                      </option>
                    ))}
                  </select>
                </div>
                <div className="setting-row">
                  <span>
                    <strong>Weekly posture digest</strong>
                    <small>
                      A quiet once-a-week summary across your enabled channels, even when all scans
                      are clean.
                    </small>
                  </span>
                  <Toggle
                    checked={weeklyDigestEnabled}
                    onChange={setWeeklyDigestEnabled}
                    title="Enable or disable weekly posture digest"
                  />
                </div>
                <div className="setting-actions">
                  <Button
                    onClick={() => void triggerDigestPreview()}
                    disabled={!anyChannelEnabled || busy !== null}
                  >
                    {busy === "digest" ? "Sending digest…" : "Send digest now"}
                  </Button>
                </div>
              </section>

              <section className="card setting-list">
                <div className="setting-title">
                  <h3>Slack</h3>
                  <p>
                    Create an incoming webhook in Slack, then paste the URL here. Stored encrypted at rest.
                  </p>
                </div>
                <div className="field-block">
                  <label htmlFor="slack-webhook">Incoming webhook URL</label>
                  <div className="webhook-input-row">
                    <input
                      id="slack-webhook"
                      type={showSlackWebhook ? "text" : "password"}
                      autoComplete="off"
                      spellCheck={false}
                      value={slackWebhook}
                      onChange={(e) => setSlackWebhook(e.target.value)}
                      placeholder="https://hooks.slack.com/services/T000/B000/xxxx"
                      aria-label="Slack incoming webhook URL"
                    />
                    <button
                      type="button"
                      className="field-reveal"
                      onClick={() => setShowSlackWebhook((visible) => !visible)}
                      aria-pressed={showSlackWebhook}
                    >
                      {showSlackWebhook ? "Hide" : "Show"}
                    </button>
                  </div>
                  <small className="field-help">Only https://hooks.slack.com/services/... URLs are accepted.</small>
                </div>
                <div className="setting-row">
                  <span>
                    <strong>Send Slack alerts</strong>
                    <small>Off pauses delivery without deleting the webhook.</small>
                  </span>
                  <Toggle
                    checked={slackEnabled && slackConfigured}
                    onChange={setSlackEnabled}
                    disabled={!slackConfigured}
                    title={slackConfigured ? "Enable or pause Slack alerts" : "Add a Slack webhook URL first"}
                  />
                </div>
                <div className="setting-actions">
                  <Button onClick={() => void testChannel("slack")} disabled={!slackConfigured || busy !== null}>
                    {busy === "test-slack" ? "Sending…" : "Send test Slack"}
                  </Button>
                </div>
              </section>

              <section className="card setting-list">
                <div className="setting-title">
                  <h3>Discord</h3>
                  <p>
                    In Discord, open Server Settings → Integrations → Webhooks, copy the URL, and paste it here.
                  </p>
                </div>
                <div className="field-block">
                  <label htmlFor="discord-webhook">Discord webhook URL</label>
                  <div className="webhook-input-row">
                    <input
                      id="discord-webhook"
                      type={showDiscordWebhook ? "text" : "password"}
                      autoComplete="off"
                      spellCheck={false}
                      value={discordWebhook}
                      onChange={(e) => setDiscordWebhook(e.target.value)}
                      placeholder="https://discord.com/api/webhooks/123456789012345678/..."
                      aria-label="Discord webhook URL"
                    />
                    <button
                      type="button"
                      className="field-reveal"
                      onClick={() => setShowDiscordWebhook((visible) => !visible)}
                      aria-pressed={showDiscordWebhook}
                    >
                      {showDiscordWebhook ? "Hide" : "Show"}
                    </button>
                  </div>
                  <small className="field-help">Only official discord.com webhook URLs are accepted.</small>
                </div>
                <div className="setting-row">
                  <span>
                    <strong>Send Discord alerts</strong>
                    <small>Posts a severity-colored embed with a deep link to the finding.</small>
                  </span>
                  <Toggle
                    checked={discordEnabled && discordConfigured}
                    onChange={setDiscordEnabled}
                    disabled={!discordConfigured}
                    title={discordConfigured ? "Enable or pause Discord alerts" : "Add a Discord webhook URL first"}
                  />
                </div>
                <div className="setting-actions">
                  <Button
                    onClick={() => void testChannel("discord")}
                    disabled={!discordConfigured || busy !== null}
                  >
                    {busy === "test-discord" ? "Sending…" : "Send test Discord"}
                  </Button>
                </div>
              </section>

              <section className="card setting-list">
                <div className="setting-title">
                  <h3>Email</h3>
                  <p>
                    Receive one email per scan with new findings above your threshold. Delivered via Resend.
                  </p>
                </div>
                <div className="field-block">
                  <label htmlFor="alert-email">Recipient email</label>
                  <input
                    id="alert-email"
                    type="email"
                    autoComplete="email"
                    value={alertEmail}
                    onChange={(e) => setAlertEmail(e.target.value)}
                    placeholder={email ?? "you@example.com"}
                    aria-label="Alert email address"
                  />
                  <small className="field-help">
                    {emailConfiguredOnServer
                      ? "Server email delivery is configured and ready."
                      : "Set RESEND_API_KEY (and optionally BULWARK_EMAIL_FROM) on the server to activate email delivery."}
                  </small>
                </div>
                <div className="setting-row">
                  <span>
                    <strong>Send email alerts</strong>
                    <small>Toggle email notifications for this workspace.</small>
                  </span>
                  <Toggle
                    checked={emailEnabled && emailReady}
                    onChange={setEmailEnabled}
                    disabled={!emailReady}
                    title={emailReady ? "Enable or pause email alerts" : "Enter an alert email address first"}
                  />
                </div>
                <div className="setting-actions">
                  <Button
                    onClick={() => void testChannel("email")}
                    disabled={!emailReady || !emailConfiguredOnServer || busy !== null}
                  >
                    {busy === "test-email" ? "Sending…" : "Send test email"}
                  </Button>
                </div>
              </section>

              <section className="card setting-list">
                {alertError && <p className="modal-error" role="alert">{alertError}</p>}
                {message && <p className="save-note" role="status" aria-live="polite">{message}</p>}
                <div className="setting-actions">
                  <Button dark onClick={() => void saveAlerts()} disabled={busy !== null}>
                    {busy === "save" ? "Saving…" : "Save alert settings"}
                  </Button>
                </div>
              </section>

              <section className="card setting-list">
                <div className="setting-title">
                  <h3>Recent alert deliveries</h3>
                  <p>Outbox delivery log with automatic retry status across Slack, Discord, and email.</p>
                  <div className="title-actions">
                    <Button onClick={() => void loadDeliveries()} disabled={deliveriesLoading}>
                      {deliveriesLoading ? "Refreshing…" : "↻ Refresh"}
                    </Button>
                  </div>
                </div>
                {deliveries.length === 0 ? (
                  <p className="muted pad">No alert deliveries recorded yet.</p>
                ) : (
                  <div className="delivery-list">
                    {deliveries.slice(0, 12).map((d) => (
                      <div className="setting-row" key={d.id}>
                        <span>
                          <strong>
                            <Dot
                              tone={
                                d.status === "sent"
                                  ? "healthy"
                                  : d.status === "failed"
                                    ? "critical"
                                    : "medium"
                              }
                            />{" "}
                            {d.channel.toUpperCase()} · {d.targetLabel}
                          </strong>
                          <small>
                            {d.kind === "digest"
                              ? "Weekly digest"
                              : `${d.findingCount} finding${d.findingCount === 1 ? "" : "s"}`}
                            {" · "}
                            {shortDate(d.sentAt ?? d.createdAt)}
                            {d.attempts > 1 ? ` · attempt ${d.attempts}` : ""}
                            {d.lastError ? ` · ${d.lastError}` : ""}
                          </small>
                        </span>
                        <span className={`tag status-tag status-${d.status}`}>{d.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
            <div>
              <section className="card side-setting">
                <h3>Status</h3>
                <div>
                  <span>Slack</span>
                  <code>
                    {slackConfigured ? (slackEnabled ? "Enabled" : "Paused") : "Not configured"}
                  </code>
                </div>
                <div>
                  <span>Discord</span>
                  <code>
                    {discordConfigured ? (discordEnabled ? "Enabled" : "Paused") : "Not configured"}
                  </code>
                </div>
                <div>
                  <span>Email</span>
                  <code>
                    {!emailConfiguredOnServer
                      ? "Needs server key"
                      : emailReady
                        ? emailEnabled
                          ? "Enabled"
                          : "Paused"
                        : "Not configured"}
                  </code>
                </div>
                <div>
                  <span>Weekly digest</span>
                  <code>{weeklyDigestEnabled ? "Enabled" : "Off"}</code>
                </div>
                <div>
                  <span>Threshold</span>
                  <code>{severity}</code>
                </div>
                <p>Workspace: {email ?? "—"}</p>
              </section>
              <section className="card side-setting">
                <h3>What gets sent</h3>
                <pre className="slack-preview">{`:red_circle: *CRITICAL* on *example.com*
> Supabase service_role key exposed
> The service_role key bypasses Row Level Security.
<https://your-bulwark/threats/…|Open finding in Bulwark>`}</pre>
                <p>One message per scan with new or reopened findings above your threshold.</p>
              </section>
            </div>
          </div>
        </div>
      )}

      {activeTab === "platforms" && (
        <div className="integration-body">
          <ConnectionsSection
            connections={connections}
            loading={loading}
            error={error}
            onAdd={onAddConnection}
            onRemove={onRemoveConnection}
            onScan={onScanConnection}
            onSetWebhookSecret={(id, secret) => onSetWebhookSecret(id, secret)}
            onUpdateSupabaseSchedule={onUpdateSupabaseSchedule}
          />
        </div>
      )}

      {activeTab === "findings" && (
        <div className="integration-body">
          <PlatformFindingsSection
            findings={platformFindings}
            loading={platformFindingsLoading}
            onSetStatus={onSetPlatformFindingStatus}
            onOpenFinding={onOpenFinding}
          />
        </div>
      )}
    </>
  );
}
