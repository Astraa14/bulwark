import { useEffect, useState } from "react";
import { Button, CodeCard, Dot } from "@/components/Ui";
import { buildFixPrompt } from "@/lib/fixPrompt";
import { safeExternalUrl, stackLabel } from "@/lib/scanOutcomes";
import {
  acceptBaseline,
  explainFinding,
  recheckFinding,
  relTime,
  shortDate,
  triageFinding,
  type FindingRow,
  type FindingStatus,
  type SiteRow,
} from "@/lib/workspace";

export function ThreatDetail({
  finding,
  site,
  back,
  onStatus,
  onRefresh,
}: {
  finding: FindingRow;
  site?: SiteRow;
  back: () => void;
  onStatus: (status: FindingStatus) => Promise<void>;
  onRefresh: () => void;
}) {
  const [explanation, setExplanation] = useState(finding.explanation ?? "");
  const [model, setModel] = useState(finding.explanation_model ?? "");
  const [cached, setCached] = useState(Boolean(finding.explanation));
  const [triageNote, setTriageNote] = useState(finding.triage_note ?? "");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [promptCopied, setPromptCopied] = useState(false);

  const targetLabel = site?.domain ?? finding.resource ?? "unknown target";

  useEffect(() => {
    setExplanation(finding.explanation ?? "");
    setModel(finding.explanation_model ?? "");
    setCached(Boolean(finding.explanation));
    setTriageNote(finding.triage_note ?? "");
    setError(null);
    setNotice(null);
    setPromptCopied(false);
  }, [finding.id, finding.explanation, finding.explanation_model, finding.triage_note]);

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label);
    setError(null);
    setNotice(null);
    try {
      await fn();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const explain = (refresh = false) =>
    run("explain", async () => {
      const res = await explainFinding(finding.id, refresh);
      setExplanation(res.explanation);
      setModel(res.model);
      setCached(res.cached);
      onRefresh();
    });

  const recheck = () =>
    run("recheck", async () => {
      const res = await recheckFinding(finding.id);
      onRefresh();
      if (res.resolved) {
        setNotice("Verified fixed — Bulwark re-scanned and marked this finding resolved.");
      } else if (res.scanStatus === "failed") {
        setError(res.error ?? "Re-check scan failed. Status was left unchanged.");
      } else if (res.scanStatus === "partial") {
        setNotice(
          "Re-check completed with partial coverage. The finding was not auto-resolved because some checks could not finish.",
        );
      } else {
        setNotice("Still detected on the latest scan.");
      }
    });

  const snooze = (days: number) =>
    run(`snooze-${days}`, async () => {
      await triageFinding(finding.id, {
        snoozeDays: days,
        triageNote: triageNote.trim() || null,
      });
      onRefresh();
      setNotice(`Snoozed for ${days} days. Bulwark will reopen it if still present after expiry.`);
    });

  const saveNote = () =>
    run("note", async () => {
      await triageFinding(finding.id, { triageNote: triageNote.trim() || null });
      onRefresh();
      setNotice("Triage note saved.");
    });

  const copyFixPrompt = async () => {
    setError(null);
    try {
      await navigator.clipboard.writeText(buildFixPrompt(finding, targetLabel, site?.stack));
      setPromptCopied(true);
      window.setTimeout(() => setPromptCopied(false), 2000);
    } catch {
      setError("Could not access the clipboard. Check browser clipboard permissions.");
    }
  };

  return (
    <div className="detail-layout">
      <div className="threat-detail">
        <button type="button" className="back" onClick={back}>
          ← All threats
        </button>
        <h1>{finding.title}</h1>
        <div className="threat-id">
          <code>
            THR-{finding.id.slice(0, 8).toUpperCase()} / {targetLabel}
          </code>
        </div>
        <div className="detail-meta">
          <span className="tag">
            <Dot tone={finding.severity} />
            {finding.severity}
          </span>
          <span className="tag">
            {finding.status === "ignored" && finding.ignored_until
              ? `snoozed until ${shortDate(finding.ignored_until)}`
              : finding.status}
          </span>
          {finding.platform && <span className="tag">{finding.platform}</span>}
          {site?.stack && <span className="tag">{stackLabel(site.stack)}</span>}
          <span>
            First seen {shortDate(finding.first_seen_at)} · last seen {relTime(finding.last_seen_at)}
          </span>
        </div>

        {notice && (
          <p className="save-note" role="status" aria-live="polite">
            {notice}
          </p>
        )}
        {error && (
          <p className="modal-error" role="alert">
            {error}
          </p>
        )}

        <section className="card meaning">
          <small>WHAT BULWARK FOUND</small>
          <h2>{`On ${targetLabel}`}</h2>
          <p>{finding.detail ?? "No extra detail was recorded for this finding."}</p>
          {safeExternalUrl(finding.url) && (
            <p className="detail-url">
              Affected URL:{" "}
              <a href={safeExternalUrl(finding.url) as string} target="_blank" rel="noreferrer">
                {finding.url}
              </a>
            </p>
          )}
        </section>

        {(finding.what_it_does_not_prove || finding.remediation) && (
          <section className="card meaning">
            <small>READ THIS CAREFULLY</small>
            <div className="finding-context">
              {finding.what_it_does_not_prove && (
                <div>
                  <h3>What this does not prove</h3>
                  <p>{finding.what_it_does_not_prove}</p>
                </div>
              )}
              {finding.remediation && (
                <div>
                  <h3>Suggested remediation</h3>
                  <p>{finding.remediation}</p>
                </div>
              )}
            </div>
          </section>
        )}

        {finding.evidence && (
          <CodeCard
            title="Evidence"
            label={finding.check_key}
            code={finding.evidence}
            footer={`Recorded by a scan on ${targetLabel}`}
          />
        )}

        <section className="card meaning ai-explanation">
          <div className="ai-head">
            <small>WHAT THIS MEANS</small>
            {model && <code>{model}</code>}
          </div>
          {explanation ? (
            <pre className="explanation">{explanation}</pre>
          ) : (
            <p>
              Generate a plain-English explanation of this finding using your own OpenAI, Anthropic,
              or Gemini key. It is cached, so you only pay for it once.
            </p>
          )}
          <div className="ai-actions">
            <Button dark onClick={() => explain(Boolean(explanation))} disabled={busy !== null}>
              {busy === "explain"
                ? "Thinking…"
                : explanation
                  ? "Regenerate explanation"
                  : "Explain with AI"}
            </Button>
            <Button onClick={() => void copyFixPrompt()}>
              {promptCopied ? "Copied fix prompt" : "Copy fix prompt for AI editor"}
            </Button>
            {cached && <span>Loaded from cache · no tokens spent</span>}
          </div>
        </section>

        <section className="card meaning triage-card">
          <small>VERIFY &amp; TRIAGE</small>
          <div className="detail-buttons">
            <Button dark onClick={recheck} disabled={busy !== null}>
              {busy === "recheck" ? "Re-checking…" : "Re-check now"}
            </Button>
            {finding.status !== "acknowledged" && (
              <Button onClick={() => run("ack", () => onStatus("acknowledged"))} disabled={busy !== null}>
                {busy === "ack" ? "Saving…" : "Acknowledge"}
              </Button>
            )}
            {finding.status !== "resolved" && (
              <Button onClick={() => run("resolve", () => onStatus("resolved"))} disabled={busy !== null}>
                {busy === "resolve" ? "Saving…" : "Mark resolved"}
              </Button>
            )}
            {finding.status !== "ignored" && (
              <Button onClick={() => run("ignore", () => onStatus("ignored"))} disabled={busy !== null}>
                {busy === "ignore" ? "Saving…" : "Ignore permanently"}
              </Button>
            )}
            {finding.status !== "open" && (
              <Button onClick={() => run("reopen", () => onStatus("open"))} disabled={busy !== null}>
                Reopen
              </Button>
            )}
            {finding.check_key === "content_replaced" && site && (
              <Button
                disabled={busy !== null}
                onClick={() =>
                  run("baseline", async () => {
                    await acceptBaseline(site.id);
                    await onStatus("resolved");
                    onRefresh();
                  })
                }
              >
                {busy === "baseline" ? "Capturing…" : "Accept current page as baseline"}
              </Button>
            )}
          </div>

          <div className="snooze-bar">
            <span className="snooze-label">Temporary snooze:</span>
            {[7, 30, 90].map((days) => (
              <Button key={days} onClick={() => snooze(days)} disabled={busy !== null}>
                {busy === `snooze-${days}` ? "Snoozing…" : `Snooze ${days}d`}
              </Button>
            ))}
          </div>

          <div className="triage-note-box">
            <label htmlFor="triage-note">Triage note (optional)</label>
            <textarea
              id="triage-note"
              rows={2}
              maxLength={500}
              value={triageNote}
              onChange={(e) => setTriageNote(e.target.value)}
              placeholder="Record why this risk is accepted, snoozed, or waiting on a deploy…"
            />
            <div className="triage-note-actions">
              <Button onClick={saveNote} disabled={busy !== null}>
                {busy === "note" ? "Saving…" : "Save note"}
              </Button>
            </div>
          </div>
        </section>
      </div>

      <aside className="copilot-panel">
        <div className="copilot-head">
          <h2>Finding facts</h2>
          <span>{finding.severity}</span>
        </div>
        <small>CONTEXT · THR-{finding.id.slice(0, 8).toUpperCase()}</small>
        <dl className="fact-list">
          <dt>Check</dt>
          <dd>
            <code>{finding.check_key}</code>
          </dd>
          <dt>{finding.platform ? "Resource" : "Site"}</dt>
          <dd>{targetLabel}</dd>
          {site?.stack && (
            <>
              <dt>Stack</dt>
              <dd>{stackLabel(site.stack)}</dd>
            </>
          )}
          {finding.platform && (
            <>
              <dt>Platform</dt>
              <dd>{finding.platform === "github" ? "GitHub" : "Supabase"}</dd>
            </>
          )}
          {finding.commit_sha && (
            <>
              <dt>Commit</dt>
              <dd>
                <code>{finding.commit_sha.slice(0, 7)}</code>
              </dd>
            </>
          )}
          <dt>Status</dt>
          <dd className="cap">{finding.status}</dd>
          {finding.ignored_until && (
            <>
              <dt>Snoozed until</dt>
              <dd>{shortDate(finding.ignored_until)}</dd>
            </>
          )}
          <dt>Confidence</dt>
          <dd className="cap">{finding.confidence ?? "—"}</dd>
          {finding.affected_resource && (
            <>
              <dt>Affected</dt>
              <dd>{finding.affected_resource}</dd>
            </>
          )}
          <dt>First seen</dt>
          <dd>{shortDate(finding.first_seen_at)}</dd>
          <dt>Last seen</dt>
          <dd>{shortDate(finding.last_seen_at)}</dd>
          <dt>Evidence</dt>
          <dd>{finding.evidence ?? "—"}</dd>
        </dl>
        <div className="copilot-copy">
          <h3>How to use this</h3>
          <p>
            Use <strong>Copy fix prompt for AI editor</strong> to paste the finding into Cursor,
            Claude Code, or your coding assistant. Once deployed, click{" "}
            <strong>Re-check now</strong> to confirm the fix immediately.
          </p>
          <p>
            Need time? Snooze for 7, 30, or 90 days with a note — Bulwark reopens it automatically
            if it is still present when the snooze expires.
          </p>
        </div>
        <small>AI can make mistakes. Verify before you change production.</small>
      </aside>
    </div>
  );
}
