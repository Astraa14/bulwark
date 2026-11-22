import { useState } from "react";
import { buildFixPrompt } from "@/lib/fixPrompt";
import { shortDate, type FindingRow, type FindingStatus } from "@/lib/workspace";
import { Dot } from "./Ui";

export function PlatformFindingsSection({
  findings,
  loading,
  onSetStatus,
  onOpenFinding,
}: {
  findings: FindingRow[];
  loading: boolean;
  onSetStatus: (id: string, status: FindingStatus) => Promise<void>;
  onOpenFinding: (finding: FindingRow) => void;
}) {
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);

  const githubFindings = findings.filter((f) => f.platform === "github");
  const supabaseFindings = findings.filter((f) => f.platform === "supabase");
  const unclassifiedFindings = findings.filter(
    (f) => f.platform !== "github" && f.platform !== "supabase",
  );

  const setStatus = async (id: string, status: FindingStatus) => {
    setBusyIds((prev) => new Set([...prev, id]));
    try {
      await onSetStatus(id, status);
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const copyPrompt = async (finding: FindingRow) => {
    try {
      await navigator.clipboard.writeText(
        buildFixPrompt(finding, finding.resource ?? finding.platform ?? "platform scan"),
      );
      setCopiedPromptId(finding.id);
      window.setTimeout(() => setCopiedPromptId(null), 1800);
    } catch {
      // Ignore clipboard failures in inline list actions.
    }
  };

  const renderFinding = (f: FindingRow) => (
    <div className="record" key={f.id}>
      <div className="record-head">
        <div className="record-title">
          <h3>{f.title}</h3>
          <p>
            <code>{f.resource ?? "—"}</code> · {f.check_key}
            {f.status === "ignored" && f.ignored_until
              ? ` · snoozed until ${shortDate(f.ignored_until)}`
              : ""}
          </p>
        </div>
        <span className="record-status">
          <span className="severity">
            <Dot tone={f.severity} />
            {f.severity}
          </span>
          <span className={`tag status-tag status-${f.status}`}>{f.status}</span>
        </span>
      </div>
      <dl className="record-facts">
        <div className="record-fact-wide">
          <dt>Evidence</dt>
          <dd>
            <code>{f.evidence ?? "—"}</code>
          </dd>
        </div>
        {f.confidence && (
          <div>
            <dt>Confidence</dt>
            <dd>{f.confidence}</dd>
          </div>
        )}
        {f.commit_sha && (
          <div>
            <dt>Commit</dt>
            <dd>
              <code>{f.commit_sha.slice(0, 7)}</code>
            </dd>
          </div>
        )}
        {f.detail && (
          <div className="record-fact-wide">
            <dt>Detail</dt>
            <dd>{f.detail}</dd>
          </div>
        )}
        {f.what_it_does_not_prove && (
          <div className="record-fact-wide">
            <dt>Does not prove</dt>
            <dd>{f.what_it_does_not_prove}</dd>
          </div>
        )}
        {f.remediation && (
          <div className="record-fact-wide">
            <dt>Suggested fix</dt>
            <dd>{f.remediation}</dd>
          </div>
        )}
      </dl>
      <div className="record-actions">
        <select
          value={f.status}
          onChange={(e) => setStatus(f.id, e.target.value as FindingStatus)}
          disabled={busyIds.has(f.id)}
          className="status-select"
          aria-label={`Status for ${f.title}`}
        >
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="ignored">Ignored</option>
        </select>
        <button type="button" className="button" onClick={() => onOpenFinding(f)}>
          View details →
        </button>
        <button type="button" className="button" onClick={() => void copyPrompt(f)}>
          {copiedPromptId === f.id ? "Copied prompt" : "Copy fix prompt"}
        </button>
        {f.url && (
          <a href={f.url} target="_blank" rel="noopener noreferrer" className="button">
            View source ↗
          </a>
        )}
      </div>
    </div>
  );

  return (
    <section className="card setting-list">
      <div className="setting-title">
        <h3>Platform findings</h3>
        <p>
          Findings from connected GitHub repositories and Supabase projects, separate from website
          scans. Dependency checks send only package names, ecosystems, and exact versions to OSV,
          never source code. Supabase policy analysis is heuristic and never proves data is safe.
        </p>
      </div>
      {loading ? (
        <p className="muted pad">Loading platform findings…</p>
      ) : findings.length === 0 ? (
        <div className="key-empty">
          <p>No platform findings yet.</p>
          <span className="key-empty-hint">Connect and scan a GitHub repo or Supabase project to see findings here.</span>
        </div>
      ) : (
        <>
          {githubFindings.length > 0 && (
            <>
              <div className="group-head">
                <h3>GitHub</h3>
                <p>Secrets, commit history, dependencies and configuration</p>
              </div>
              {githubFindings.map(renderFinding)}
            </>
          )}
          {supabaseFindings.length > 0 && (
            <>
              <div className="group-head">
                <h3>Supabase</h3>
                <p>Public storage and RLS coverage</p>
              </div>
              {supabaseFindings.map(renderFinding)}
            </>
          )}
          {unclassifiedFindings.length > 0 && (
            <>
              <div className="group-head">
                <h3>Unclassified</h3>
                <p>Legacy rows whose platform could not be established</p>
              </div>
              {unclassifiedFindings.map(renderFinding)}
            </>
          )}
        </>
      )}
    </section>
  );
}
