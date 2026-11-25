import { useEffect, useState } from "react";
import { Button, PageTitle, Toggle } from "@/components/Ui";
import { INTERVAL_OPTIONS, intervalLabel } from "@/lib/scanOutcomes";
import {
  PLAN_SITE_LIMIT,
  setSiteInterval,
  type Settings as SettingsModel,
  type SiteRow,
} from "@/lib/workspace";

export function Settings({
  settings,
  sites,
  email,
  onSave,
  onChanged,
  goIntegrations,
}: {
  settings: SettingsModel | null;
  sites: SiteRow[];
  email?: string | null;
  onSave: (patch: Partial<SettingsModel>) => Promise<SettingsModel>;
  onChanged: () => void;
  goIntegrations: () => void;
}) {
  const [interval, setIntervalMinutes] = useState(settings?.scanIntervalMinutes ?? 60);
  const [applyAll, setApplyAll] = useState(true);
  const [busy, setBusy] = useState(false);
  const [alertBusy, setAlertBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [alertError, setAlertError] = useState<string | null>(null);

  useEffect(() => {
    if (!settings) return;
    setIntervalMinutes(settings.scanIntervalMinutes);
  }, [settings]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await onSave({ scanIntervalMinutes: interval });
      if (applyAll && sites.length) {
        await Promise.all(sites.map((s) => setSiteInterval(s.id, interval)));
        onChanged();
      }
      setMessage("Saved. New scans pick this up on the next cycle.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const toggleAlertChannel = async (
    channel: "slack" | "discord" | "email" | "digest",
    next: boolean,
  ) => {
    setAlertBusy(channel);
    setAlertError(null);
    try {
      if (channel === "slack") await onSave({ alertsEnabled: next });
      else if (channel === "discord") await onSave({ discordAlertsEnabled: next });
      else if (channel === "email") await onSave({ emailAlertsEnabled: next });
      else await onSave({ weeklyDigestEnabled: next });
    } catch (err) {
      setAlertError((err as Error).message);
    } finally {
      setAlertBusy(null);
    }
  };

  const slackConfigured = Boolean(settings?.slackWebhookUrl);
  const discordConfigured = Boolean(settings?.discordWebhookUrl);
  const emailTarget = settings?.alertEmail ?? email ?? null;
  const emailReady = Boolean(emailTarget && settings?.emailConfigured);

  return (
    <>
      <PageTitle
        title="Settings"
        subtitle="Set boundaries. Let Bulwark handle the watching."
        action={
          <Button dark onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </Button>
        }
      />
      <div className="settings-grid">
        <div>
          <section className="card setting-list">
            <div className="setting-title">
              <h3>Monitoring</h3>
              <p>Applies to every site in this workspace unless noted.</p>
            </div>
            <div className="setting-row">
              <span>
                <strong>Scan interval</strong>
                <small>How often Bulwark re-checks each verified site.</small>
              </span>
              <select
                className="inline-select"
                value={interval}
                onChange={(e) => setIntervalMinutes(Number(e.target.value))}
              >
                {INTERVAL_OPTIONS.map((o) => (
                  <option value={o.value} key={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="setting-row">
              <span>
                <strong>Apply to existing sites</strong>
                <small>Update all {sites.length} monitored site(s) now.</small>
              </span>
              <Toggle checked={applyAll} onChange={setApplyAll} />
            </div>
            <div className="setting-row">
              <span>
                <strong>Operating mode</strong>
                <small>
                  Bulwark inspects and explains findings — it never edits your code or changes
                  production settings.
                </small>
              </span>
              <code>Read-only</code>
            </div>
            {error && <p className="modal-error" role="alert">{error}</p>}
            {message && <p className="save-note" role="status" aria-live="polite">{message}</p>}
          </section>

          <section className="card setting-list alerts">
            <div className="setting-title">
              <h3>Notifications</h3>
              <p>Send alerts for new findings above your threshold across Slack, Discord, and email.</p>
            </div>
            <div className="setting-row">
              <span>
                <strong>Slack</strong>
                <code>{slackConfigured ? "Webhook configured" : "Not configured"}</code>
              </span>
              <button type="button" className="setting-edit-btn" onClick={goIntegrations}>
                Configure
              </button>
              <Toggle
                checked={Boolean(slackConfigured && settings?.alertsEnabled)}
                disabled={!slackConfigured || alertBusy !== null}
                onChange={(next) => void toggleAlertChannel("slack", next)}
                title={slackConfigured ? "Toggle Slack alerts" : "Configure a Slack webhook in Integrations first"}
              />
            </div>
            <div className="setting-row">
              <span>
                <strong>Discord</strong>
                <code>{discordConfigured ? "Webhook configured" : "Not configured"}</code>
              </span>
              <button type="button" className="setting-edit-btn" onClick={goIntegrations}>
                Configure
              </button>
              <Toggle
                checked={Boolean(discordConfigured && settings?.discordAlertsEnabled)}
                disabled={!discordConfigured || alertBusy !== null}
                onChange={(next) => void toggleAlertChannel("discord", next)}
                title={discordConfigured ? "Toggle Discord alerts" : "Configure a Discord webhook in Integrations first"}
              />
            </div>
            <div className="setting-row">
              <span>
                <strong>Email</strong>
                <code>
                  {settings?.emailConfigured
                    ? emailTarget ?? "Not configured"
                    : "Server email key not set"}
                </code>
              </span>
              <button type="button" className="setting-edit-btn" onClick={goIntegrations}>
                Configure
              </button>
              <Toggle
                checked={Boolean(emailReady && settings?.emailAlertsEnabled)}
                disabled={!emailReady || alertBusy !== null}
                onChange={(next) => void toggleAlertChannel("email", next)}
                title={
                  emailReady
                    ? "Toggle email alerts"
                    : "Configure an alert email (and RESEND_API_KEY on the server) first"
                }
              />
            </div>
            <div className="setting-row">
              <span>
                <strong>Weekly posture digest</strong>
                <small>Quiet weekly summary across enabled channels.</small>
              </span>
              <Toggle
                checked={Boolean(settings?.weeklyDigestEnabled)}
                disabled={alertBusy !== null}
                onChange={(next) => void toggleAlertChannel("digest", next)}
                title="Toggle weekly security digest"
              />
            </div>
            <div className="setting-row">
              <span>
                <strong>Minimum severity</strong>
                <small>Lower severities stay in the app only.</small>
              </span>
              <code>{settings?.slackMinSeverity ?? "high"}</code>
            </div>
            {alertError && <p className="modal-error" role="alert">{alertError}</p>}
          </section>
        </div>
        <div>
          <section className="card side-setting">
            <h3>Workspace</h3>
            <label>Signed in as</label>
            <code>{email ?? "—"}</code>
            <div>
              <span>Sites monitored</span>
              <code>{sites.length}</code>
            </div>
            <div>
              <span>Plan</span>
              <code>Free · {sites.length} of {PLAN_SITE_LIMIT}</code>
            </div>
            <p>Billing and team seats are not part of this build yet.</p>
          </section>
          <section className="card side-setting">
            <h3>Scan coverage</h3>
            <label>Every website scan checks</label>
            <ul className="coverage-list">
              <li>Uptime, HTTP status and TLS expiry</li>
              <li>Security headers, weak CSP, CORS and cookie flags</li>
              <li>Exposed .env, .git, backups, source maps and OpenAPI/GraphQL</li>
              <li>Leaked API keys in HTML and JS bundles</li>
              <li>Domain expiry, nameservers, MX, SPF and DMARC</li>
              <li>Defacement, robots.txt, sitemap and security.txt</li>
            </ul>
            <p>{sites.filter((s) => s.status === "verified").length} site(s) actively scanning.</p>
          </section>
        </div>
      </div>
      <div className="settings-foot">
        <span>Changes apply to this workspace only.</span>
        <span>{settings ? `Interval: ${intervalLabel(settings.scanIntervalMinutes)}` : "Loading…"}</span>
      </div>
    </>
  );
}
