import { useEffect, useState, type FormEvent } from "react";
import { apiGet, apiUrl } from "@/lib/api";
import {
  GITHUB_INTERVAL_OPTIONS,
  SUPABASE_INTERVAL_OPTIONS,
  githubIntervalLabel,
  supabaseIntervalLabel,
} from "@/lib/scanOutcomes";
import {
  listGitHubSchedules,
  shortDate,
  updateGitHubSchedule,
  type addConnection,
  type ConnectionRow,
  type ConnectionType,
  type GitHubRepoSchedule,
  type ScanConnectionResult,
  type ScanStatus,
} from "@/lib/workspace";
import { Button, Dot } from "./Ui";

export function ConnectionsSection({
  connections,
  loading,
  error,
  onAdd,
  onRemove,
  onScan,
  onSetWebhookSecret,
  onUpdateSupabaseSchedule,
}: {
  connections: ConnectionRow[];
  loading: boolean;
  error: string | null;
  onAdd: (input: Parameters<typeof addConnection>[0]) => Promise<void>;
  onRemove: (id: string, type: ConnectionType) => Promise<void>;
  onScan: (
    id: string,
    type: ConnectionType,
    repo?: { owner: string; repo: string },
  ) => Promise<ScanConnectionResult>;
  onSetWebhookSecret: (id: string, secret: string) => Promise<void>;
  onUpdateSupabaseSchedule: (
    id: string,
    input: { autoScanEnabled?: boolean; scanIntervalMinutes?: number },
  ) => Promise<void>;
}) {
  const [addType, setAddType] = useState<ConnectionType | null>(null);
  const [ghUsername, setGhUsername] = useState("");
  const [ghToken, setGhToken] = useState("");
  const [sbRef, setSbRef] = useState("");
  const [sbName, setSbName] = useState("");
  const [sbKey, setSbKey] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [webhookId, setWebhookId] = useState<string | null>(null);
  const [webhookSecret, setWebhookSecretState] = useState("");
  const [repos, setRepos] = useState<
    { full_name: string; owner: string; name: string; private: boolean }[]
  >([]);
  const [repoSchedules, setRepoSchedules] = useState<Record<string, GitHubRepoSchedule>>({});
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState<string | null>(null);
  const [reposConnectionId, setReposConnectionId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const closeAddForm = () => {
    setAddType(null);
    setGhUsername("");
    setGhToken("");
    setSbRef("");
    setSbName("");
    setSbKey("");
    setLocalError(null);
  };

  useEffect(() => {
    if (!addType && !webhookId) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (webhookId) {
        setWebhookId(null);
        setWebhookSecretState("");
      } else if (addType) {
        closeAddForm();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [addType, webhookId]);

  const submitConnection = async () => {
    setLocalError(null);
    setNotice(null);
    setBusy("add");
    try {
      if (addType === "github") {
        if (!ghUsername.trim()) throw new Error("Enter the GitHub username or organization.");
        if (!ghToken.trim()) throw new Error("Enter a personal access token.");
        await onAdd({
          type: "github",
          githubUsername: ghUsername.trim(),
          token: ghToken.trim(),
        });
        setNotice("GitHub connection saved. Load its repositories to choose what to scan.");
      } else if (addType === "supabase") {
        const projectRef = sbRef.trim().toLowerCase();
        if (!/^[a-z0-9]{10,32}$/.test(projectRef)) {
          throw new Error(
            "Project ref must be the 10–32 character reference from the Supabase project URL.",
          );
        }
        if (!sbKey.trim()) throw new Error("Enter the project's publishable (anon) key.");
        await onAdd({
          type: "supabase",
          projectRef,
          projectName: sbName.trim() || undefined,
          apiKey: sbKey.trim(),
        });
        setNotice("Supabase connection saved. Run a scan when ready.");
      }
      closeAddForm();
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const removeConnection = async (id: string, type: ConnectionType) => {
    if (!window.confirm("Remove this connection? Scans using it will stop working.")) return;
    setBusy(`remove-${id}`);
    setLocalError(null);
    try {
      await onRemove(id, type);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const loadRepos = async (id: string) => {
    setReposConnectionId(id);
    setRepos([]);
    setRepoSchedules({});
    setReposError(null);
    setReposLoading(true);
    try {
      const [data, schedules] = await Promise.all([
        apiGet<{
          repos: { full_name: string; owner: string; name: string; private: boolean }[];
        }>(`/api/connections/github/${id}/repos`),
        listGitHubSchedules(id).catch(() => []),
      ]);
      setRepos(data.repos ?? []);
      const map: Record<string, GitHubRepoSchedule> = {};
      for (const s of schedules) map[s.fullName] = s;
      setRepoSchedules(map);
    } catch (err) {
      setReposError((err as Error).message);
    } finally {
      setReposLoading(false);
    }
  };

  const toggleRepoSchedule = async (
    connectionId: string,
    owner: string,
    repo: string,
    autoScanEnabled: boolean,
    scanIntervalMinutes: number,
  ) => {
    const key = `${owner}/${repo}`;
    setBusy(`gh-schedule-${key}`);
    setLocalError(null);
    setNotice(null);
    try {
      const updated = await updateGitHubSchedule(connectionId, {
        owner,
        repo,
        autoScanEnabled,
        scanIntervalMinutes,
      });
      setRepoSchedules((prev) => ({ ...prev, [key]: updated }));
      setNotice(
        autoScanEnabled
          ? `Scheduled ${githubIntervalLabel(scanIntervalMinutes).toLowerCase()} scans for ${key}.`
          : `Paused scheduled scans for ${key}.`,
      );
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const runScan = async (
    id: string,
    type: ConnectionType,
    repo?: { owner: string; repo: string },
  ) => {
    const busyKey = repo ? `scan-${id}-${repo.owner}/${repo.repo}` : `scan-${id}`;
    setBusy(busyKey);
    setLocalError(null);
    setNotice(null);
    try {
      const result = await onScan(id, type, repo);
      const parts = [
        `${result.findings} finding${result.findings === 1 ? "" : "s"} observed`,
      ];
      if (result.newFindings) parts.push(`${result.newFindings} new`);
      if (result.reopenedFindings) parts.push(`${result.reopenedFindings} reopened`);
      if (result.duplicate) parts.push("already recorded — no alert sent");
      if (result.status !== "completed") parts.push(`status ${result.status}`);
      if (result.error) parts.push(result.error);
      setNotice(`Scan finished: ${parts.join(" · ")}`);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const setWebhookSecret = async (id: string, secret: string) => {
    setBusy(`webhook-${id}`);
    setLocalError(null);
    setNotice(null);
    try {
      await onSetWebhookSecret(id, secret.trim());
      setWebhookId(null);
      setWebhookSecretState("");
      setNotice("Webhook secret saved. Configure the same secret in GitHub.");
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId(null), 1500);
    } catch {
      setLocalError("Copy failed. Select the URL and copy it manually.");
    }
  };

  const updateSchedule = async (
    id: string,
    input: { autoScanEnabled?: boolean; scanIntervalMinutes?: number },
  ) => {
    setBusy(`schedule-${id}`);
    setLocalError(null);
    setNotice(null);
    try {
      await onUpdateSupabaseSchedule(id, input);
      setNotice(
        input.autoScanEnabled === false
          ? "Scheduled Supabase scans paused."
          : "Supabase scan schedule updated.",
      );
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const coverageSummary = (connection: ConnectionRow) => {
    const coverage = connection.lastScanCoverage;
    if (!coverage) return null;
    const parts: string[] = [];
    if (connection.type === "github") {
      parts.push(`${coverage.filesRead ?? coverage.filesScanned ?? 0} files read`);
      if (typeof coverage.historyCommitsScanned === "number" && coverage.historyCommitsScanned > 0) {
        parts.push(`${coverage.historyCommitsScanned} recent commits checked`);
      }
      if (coverage.treeTruncated) parts.push("file tree truncated by GitHub");
      if (coverage.skippedByCap) parts.push(`${coverage.skippedByCap} not read (file cap)`);
      if (coverage.skippedLarge) parts.push(`${coverage.skippedLarge} large files skipped`);
      if (coverage.skippedNonText) parts.push(`${coverage.skippedNonText} non-text skipped`);
      if (coverage.skippedUnreadable) parts.push(`${coverage.skippedUnreadable} unreadable`);
    } else {
      parts.push(`${coverage.tablesInspected ?? 0} tables inspected`);
      parts.push(coverage.rlsChecked ? "RLS inspected (heuristic)" : "RLS not checked");
      parts.push(coverage.storageChecked ? "storage checked" : "storage not checked");
    }
    return parts.join(" · ");
  };

  const scanTone = (status?: ScanStatus | null) =>
    status === "failed" ? "critical" : status === "partial" ? "medium" : "healthy";

  return (
    <>
      <section className="card setting-list">
        <div className="setting-title">
          <h3>Connected platforms</h3>
          <p>
            Read-only connections to GitHub and Supabase. Bulwark never writes to your
            repositories or projects. Signing in with GitHub is identity only; repository
            access comes from the read-only token you add here.
          </p>
          <div className="title-actions">
            <button
              type="button"
              className="button dark"
              onClick={() => setAddType("github")}
              disabled={addType !== null || busy !== null}
            >
              + Connect GitHub
            </button>
            <button
              type="button"
              className="button"
              onClick={() => setAddType("supabase")}
              disabled={addType !== null || busy !== null}
            >
              + Connect Supabase
            </button>
          </div>
        </div>
        {(error || localError) && <p className="modal-error">{localError ?? error}</p>}
        {notice && (
          <p className="save-note" role="status" aria-live="polite">
            {notice}
          </p>
        )}
        {loading ? (
          <p className="muted pad">Loading connections…</p>
        ) : connections.length === 0 ? (
          <div className="key-empty">
            <p>No platform connections yet.</p>
            <span className="key-empty-hint">Connect GitHub or Supabase to scan your repositories and projects.</span>
          </div>
        ) : (
          connections.map((c) => {
            const subject =
              c.label ||
              (c.type === "github" ? c.githubUsername : c.projectName) ||
              (c.type === "github" ? "GitHub" : "Supabase");
            const coverage = coverageSummary(c);
            const webhookUrl = apiUrl(`/api/webhooks/github/${c.id}`);
            return (
              <div className="record" key={c.id}>
                <div className="record-head">
                  <div className="record-title">
                    <h3>{c.type === "github" ? "GitHub" : "Supabase"}</h3>
                    <p>{subject}</p>
                  </div>
                  <span className="record-status">
                    <Dot tone={scanTone(c.lastScanStatus)} />
                    {c.lastScanStatus
                      ? `${c.lastScanStatus[0].toUpperCase()}${c.lastScanStatus.slice(1)}`
                      : "Connected"}
                  </span>
                </div>
                <dl className="record-facts">
                  <div>
                    <dt>Credential</dt>
                    <dd>
                      <code>{c.preview}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Last scan</dt>
                    <dd>{c.lastCheckedAt ? shortDate(c.lastCheckedAt) : "Never scanned"}</dd>
                  </div>
                  <div>
                    <dt>Added</dt>
                    <dd>{shortDate(c.createdAt)}</dd>
                  </div>
                  {c.type === "supabase" && (
                    <div>
                      <dt>Scheduled scans</dt>
                      <dd>
                        {c.autoScanEnabled === false
                          ? "Paused"
                          : c.nextScanAt
                            ? `${supabaseIntervalLabel(c.scanIntervalMinutes ?? 360)} · next ${shortDate(c.nextScanAt)}`
                            : supabaseIntervalLabel(c.scanIntervalMinutes ?? 360)}
                      </dd>
                    </div>
                  )}
                  {coverage && (
                    <div className="record-fact-wide">
                      <dt>Last scan coverage</dt>
                      <dd>{coverage}</dd>
                    </div>
                  )}
                  {c.lastScanError && (
                    <div className="record-fact-wide">
                      <dt>Last scan note</dt>
                      <dd>{c.lastScanError}</dd>
                    </div>
                  )}
                  {c.type === "github" && (
                    <div className="record-fact-wide">
                      <dt>Webhook URL</dt>
                      <dd className="record-url">
                        <code>{webhookUrl}</code>
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => void copyText(`url-${c.id}`, webhookUrl)}
                          disabled={busy !== null}
                        >
                          {copiedId === `url-${c.id}` ? "Copied" : "Copy URL"}
                        </button>
                      </dd>
                    </div>
                  )}
                </dl>
                <div className="record-actions">
                  <button
                    type="button"
                    className="button dark"
                    onClick={() => {
                      if (c.type === "supabase") {
                        void runScan(c.id, "supabase");
                      } else {
                        void loadRepos(c.id);
                      }
                    }}
                    disabled={busy !== null}
                  >
                    {busy === `scan-${c.id}`
                      ? "Scanning…"
                      : c.type === "github"
                        ? "Choose repository…"
                        : "Scan now"}
                  </button>
                  {c.type === "github" && (
                    <button
                      type="button"
                      className="button"
                      onClick={() => {
                        setWebhookId(c.id);
                        setWebhookSecretState("");
                      }}
                      disabled={busy !== null}
                    >
                      Webhook secret
                    </button>
                  )}
                  {c.type === "supabase" && (
                    <>
                      <select
                        className="status-select schedule-select"
                        aria-label={`Scan interval for ${subject}`}
                        value={c.scanIntervalMinutes ?? 360}
                        disabled={busy !== null}
                        onChange={(e) =>
                          void updateSchedule(c.id, {
                            scanIntervalMinutes: Number(e.target.value),
                            autoScanEnabled: c.autoScanEnabled ?? true,
                          })
                        }
                      >
                        {SUPABASE_INTERVAL_OPTIONS.map((option) => (
                          <option value={option.value} key={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        className="button"
                        disabled={busy !== null}
                        onClick={() =>
                          void updateSchedule(c.id, {
                            autoScanEnabled: c.autoScanEnabled === false,
                          })
                        }
                      >
                        {busy === `schedule-${c.id}`
                          ? "Saving…"
                          : c.autoScanEnabled === false
                            ? "Enable schedule"
                            : "Pause schedule"}
                      </button>
                    </>
                  )}
                  <Button onClick={() => removeConnection(c.id, c.type)} disabled={busy !== null}>
                    {busy === `remove-${c.id}` ? "Removing…" : "Remove"}
                  </Button>
                </div>
              </div>
            );
          })
        )}
      </section>

      {reposConnectionId && (
        <section className="card setting-list">
          <div className="setting-title">
            <h3>
              Repositories for{" "}
              {connections.find((c) => c.id === reposConnectionId)?.label ??
                connections.find((c) => c.id === reposConnectionId)?.githubUsername ??
                "this connection"}
            </h3>
            <p>
              Scan immediately or opt any repository into scheduled daily/weekly scans to catch new
              OSV advisories even without pushes.
            </p>
            <div className="title-actions">
              <button
                type="button"
                className="button"
                onClick={() => {
                  setReposConnectionId(null);
                  setRepos([]);
                  setReposError(null);
                }}
              >
                Close
              </button>
            </div>
          </div>
          {reposLoading && <p className="muted pad">Loading repositories…</p>}
          {reposError && <p className="modal-error">{reposError}</p>}
          {!reposLoading && !reposError && repos.length === 0 && (
            <div className="key-empty">
              <p>No repositories are visible to this token.</p>
              <span className="key-empty-hint">
                Confirm the token belongs to this account or organization and has Contents
                read access, then reconnect it.
              </span>
            </div>
          )}
          {repos.map((repo) => {
            const sched = repoSchedules[repo.full_name];
            const autoEnabled = sched?.autoScanEnabled === true;
            const interval = sched?.scanIntervalMinutes ?? 1440;
            const schedBusy = busy === `gh-schedule-${repo.full_name}`;
            return (
              <div className="record record-compact" key={repo.full_name}>
                <div className="record-head">
                  <div className="record-title">
                    <h3>{repo.name}</h3>
                    <p>
                      {repo.owner}/{repo.name} · {repo.private ? "Private" : "Public"}
                      {autoEnabled && sched?.nextScanAt
                        ? ` · scheduled ${githubIntervalLabel(interval).toLowerCase()} (next ${shortDate(sched.nextScanAt)})`
                        : ""}
                    </p>
                  </div>
                  <div className="record-actions inline-actions">
                    <select
                      className="status-select schedule-select"
                      aria-label={`Schedule interval for ${repo.full_name}`}
                      value={interval}
                      disabled={busy !== null}
                      onChange={(e) =>
                        void toggleRepoSchedule(
                          reposConnectionId,
                          repo.owner,
                          repo.name,
                          true,
                          Number(e.target.value),
                        )
                      }
                    >
                      {GITHUB_INTERVAL_OPTIONS.map((opt) => (
                        <option value={opt.value} key={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="button"
                      disabled={busy !== null}
                      onClick={() =>
                        void toggleRepoSchedule(
                          reposConnectionId,
                          repo.owner,
                          repo.name,
                          !autoEnabled,
                          interval,
                        )
                      }
                    >
                      {schedBusy
                        ? "Saving…"
                        : autoEnabled
                          ? "Pause schedule"
                          : "Enable schedule"}
                    </button>
                    <button
                      type="button"
                      className="button dark"
                      onClick={() => {
                        const [owner, name] = repo.full_name.split("/");
                        void runScan(reposConnectionId, "github", { owner, repo: name });
                      }}
                      disabled={busy !== null}
                    >
                      {busy === `scan-${reposConnectionId}-${repo.full_name}` ? "Scanning…" : "Scan now"}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </section>
      )}

      {addType === "github" && (
        <div className="modal-wrap">
          <button type="button" className="modal-scrim" onClick={closeAddForm} aria-label="Close" />
          <div
            className="modal card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="connect-github-title"
          >
            <div className="modal-head">
              <div>
                <h2 id="connect-github-title">Connect GitHub</h2>
                <p>
                  Read-only access to the repositories you choose. Bulwark never writes to them and
                  the token is encrypted at rest.
                </p>
              </div>
              <button type="button" className="modal-close" onClick={closeAddForm} aria-label="Close">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" /></svg>
              </button>
            </div>
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                void submitConnection();
              }}
            >
              <div className="field-block">
                <label htmlFor="gh-username">GitHub username or organization</label>
                <input
                  id="gh-username"
                  autoComplete="off"
                  autoFocus
                  value={ghUsername}
                  onChange={(e) => setGhUsername(e.target.value)}
                  placeholder="octocat"
                />
              </div>
              <div className="field-block">
                <label htmlFor="gh-token">Personal access token (read-only)</label>
                <input
                  id="gh-token"
                  type="password"
                  autoComplete="off"
                  value={ghToken}
                  onChange={(e) => setGhToken(e.target.value)}
                  placeholder="github_pat_…"
                />
                <small className="field-help">
                  A fine-grained token with Contents and Metadata read-only is enough. Create it in
                  GitHub under Settings → Developer settings → Personal access tokens.
                </small>
              </div>
              {localError && <p className="modal-error">{localError}</p>}
              <div className="modal-actions">
                <button type="button" className="button" onClick={closeAddForm}>
                  Cancel
                </button>
                <button type="submit" className="button dark" disabled={busy !== null}>
                  {busy !== null ? "Adding…" : "Connect"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {addType === "supabase" && (
        <div className="modal-wrap">
          <button type="button" className="modal-scrim" onClick={closeAddForm} aria-label="Close" />
          <div
            className="modal card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="connect-supabase-title"
          >
            <div className="modal-head">
              <div>
                <h2 id="connect-supabase-title">Connect Supabase</h2>
                <p>
                  Checks storage buckets, API connectivity and Row Level Security metadata.
                  Credentials are encrypted at rest and used read-only.
                </p>
              </div>
              <button type="button" className="modal-close" onClick={closeAddForm} aria-label="Close">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" /></svg>
              </button>
            </div>
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                void submitConnection();
              }}
            >
              <div className="field-block">
                <label htmlFor="sb-ref">Project ref</label>
                <input
                  id="sb-ref"
                  autoComplete="off"
                  autoFocus
                  value={sbRef}
                  onChange={(e) => setSbRef(e.target.value)}
                  placeholder="abcdefghijklmnop"
                />
                <small className="field-help">
                  The subdomain in https://&lt;ref&gt;.supabase.co.
                </small>
              </div>
              <div className="field-block">
                <label htmlFor="sb-name">Project name (optional)</label>
                <input
                  id="sb-name"
                  autoComplete="off"
                  value={sbName}
                  onChange={(e) => setSbName(e.target.value)}
                  placeholder="My Project"
                />
              </div>
              <div className="field-block">
                <label htmlFor="sb-key">Publishable (anon) key</label>
                <input
                  id="sb-key"
                  type="password"
                  autoComplete="off"
                  value={sbKey}
                  onChange={(e) => setSbKey(e.target.value)}
                  placeholder="sb_publishable_… or eyJ…"
                />
                <small className="field-help">
                  Service-role and sb_secret_ keys are refused. RLS inspection needs the helper at
                  supabase/customer/bulwark_check_rls.sql; without it, RLS is reported as not
                  checked rather than safe.
                </small>
              </div>
              {localError && <p className="modal-error">{localError}</p>}
              <div className="modal-actions">
                <button type="button" className="button" onClick={closeAddForm}>
                  Cancel
                </button>
                <button type="submit" className="button dark" disabled={busy !== null}>
                  {busy !== null ? "Adding…" : "Connect"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {webhookId && (
        <div className="modal-wrap">
          <button
            type="button"
            className="modal-scrim"
            onClick={() => setWebhookId(null)}
            aria-label="Close"
          />
          <div
            className="modal card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="webhook-title"
          >
            <div className="modal-head">
              <div>
                <h2 id="webhook-title">GitHub webhook secret</h2>
                <p>
                  GitHub signs each delivery with this secret, so unsigned or mismatched requests
                  are rejected. Deliveries are de-duplicated by delivery ID.
                </p>
              </div>
              <button
                type="button"
                className="modal-close"
                onClick={() => setWebhookId(null)}
                aria-label="Close"
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" /></svg>
              </button>
            </div>
            <form
              onSubmit={(e: FormEvent) => {
                e.preventDefault();
                if (webhookSecret.trim().length >= 16) void setWebhookSecret(webhookId, webhookSecret);
              }}
            >
              <div className="modal-url">
                <span>Webhook URL</span>
                <code>{apiUrl(`/api/webhooks/github/${webhookId}`)}</code>
              </div>
              <div className="field-block">
                <label htmlFor="webhook-secret">Webhook secret (at least 16 characters)</label>
                <input
                  id="webhook-secret"
                  type="password"
                  autoComplete="off"
                  autoFocus
                  value={webhookSecret}
                  onChange={(e) => setWebhookSecretState(e.target.value)}
                  placeholder="Enter a random secret string"
                />
                <small className="field-help">
                  Use each connection's own URL. Two connections sharing one secret make deliveries
                  ambiguous, so those requests are refused.
                </small>
              </div>
              {localError && <p className="modal-error">{localError}</p>}
              <div className="modal-actions">
                <button type="button" className="button" onClick={() => setWebhookId(null)}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="button dark"
                  disabled={busy !== null || webhookSecret.trim().length < 16}
                >
                  {busy !== null ? "Saving…" : "Save secret"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
