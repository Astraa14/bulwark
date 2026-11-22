import { useState } from "react";
import { Button, Dot, PageTitle, Stat } from "@/components/Ui";
import { siteLabel } from "@/lib/scanOutcomes";
import {
  getCopilotBrief,
  type ApiKeyRow,
  type CopilotBriefResult,
  type FindingRow,
  type SiteRow,
} from "@/lib/workspace";

export function AiCopilot({
  findings,
  sites,
  keys,
  onOpen,
  onGoKeys,
}: {
  findings: FindingRow[];
  sites: SiteRow[];
  keys: ApiKeyRow[];
  onOpen: (finding: FindingRow) => void;
  onGoKeys: () => void;
}) {
  const explained = findings.filter((f) => f.explanation).length;
  const open = findings.filter((f) => f.status === "open");
  const ready = keys.length > 0;
  const [brief, setBrief] = useState<CopilotBriefResult | null>(null);
  const [briefBusy, setBriefBusy] = useState(false);
  const [briefError, setBriefError] = useState<string | null>(null);

  const loadBrief = async (useAi: boolean) => {
    setBriefBusy(true);
    setBriefError(null);
    try {
      setBrief(await getCopilotBrief(useAi));
    } catch (err) {
      setBriefError((err as Error).message);
    } finally {
      setBriefBusy(false);
    }
  };

  return (
    <>
      <PageTitle
        title="AI Copilot"
        subtitle="Plain-English explanations and weekly priority briefs, generated with your own key."
        action={
          <Button dark onClick={onGoKeys}>
            {ready ? "Manage keys" : "Add an API key"}
          </Button>
        }
      />
      <div className="notice card">
        <strong>{ready ? `${keys[0].providerLabel} connected` : "No AI key connected"}</strong>
        <span>
          {ready
            ? `Explanations use ${keys[0].model}. Nothing is generated until you ask for it.`
            : "Add an OpenAI, Anthropic, or Gemini key to explain any finding or synthesize a priority brief."}
        </span>
      </div>
      <section className="stats">
        <Stat label="Explained findings" value={String(explained)} note="Cached on each finding" />
        <Stat label="Open findings" value={String(open.length)} note={ready ? "Ready to explain" : "Add a key to explain"} />
        <Stat label="Provider" value={ready ? keys[0].providerLabel : "Not set"} note={ready ? keys[0].model ?? "" : "OpenAI, Anthropic, or Gemini"} />
        <Stat label="Token markup" value="$0" note="You pay your provider directly" />
      </section>

      <section className="card setting-list brief-card">
        <div className="setting-title">
          <h3>Top 3 priorities this week</h3>
          <p>
            Focus on the highest-impact open findings first. Works deterministically without a key,
            or synthesized with your connected AI provider.
          </p>
          <div className="title-actions">
            <Button onClick={() => void loadBrief(false)} disabled={briefBusy}>
              {briefBusy ? "Building…" : "Quick summary (0 tokens)"}
            </Button>
            {ready && (
              <Button dark onClick={() => void loadBrief(true)} disabled={briefBusy}>
                {briefBusy ? "Generating…" : `Synthesize with ${keys[0].providerLabel}`}
              </Button>
            )}
          </div>
        </div>
        {briefError && <p className="modal-error">{briefError}</p>}
        {brief && (
          <div className="brief-output">
            <div className="ai-head">
              <small>{brief.generatedBy === "ai" ? "AI PRIORITY BRIEF" : "PRIORITY SUMMARY"}</small>
              {brief.model && <code>{brief.model}</code>}
            </div>
            <pre className="explanation">{brief.brief}</pre>
          </div>
        )}
      </section>

      <div className="split-content">
        <section className="card setting-list">
          <div className="setting-title">
            <h3>Open findings</h3>
            <p>Pick one to see the evidence, copy a fix prompt, or generate an explanation.</p>
          </div>
          {open.slice(0, 8).map((f) => (
            <div className="setting-row" key={f.id}>
              <span>
                <strong>
                  <Dot tone={f.severity} /> {f.title}
                </strong>
                <small>
                  {siteLabel(sites, f)} · {f.severity} ·{" "}
                  {f.explanation ? "explained" : "not explained"}
                </small>
              </span>
              <button
                type="button"
                onClick={() => onOpen(f)}
                aria-label={f.explanation ? `View explanation for ${f.title}` : `Open ${f.title}`}
              >
                {f.explanation ? "View →" : ready ? "Explain →" : "Open →"}
              </button>
            </div>
          ))}
          {open.length === 0 && <p className="muted pad">No open findings. Nothing to explain.</p>}
        </section>
        <section className="card side-setting">
          <h3>What the copilot does</h3>
          <ul className="coverage-list">
            <li>Explains what a finding means in plain language</li>
            <li>Tailors fix steps to your site's framework stack</li>
            <li>Generates copy-paste prompts for Cursor, Claude Code, and AI editors</li>
            <li>Caches answers so you never pay twice</li>
          </ul>
          <p>No automatic code edits, no write permissions. Guidance and verification only.</p>
        </section>
      </div>
    </>
  );
}
