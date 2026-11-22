import { useState } from "react";
import { Button, Dot, PageTitle } from "@/components/Ui";
import {
  CHECK_OUTCOME_ORDER,
  downloadCsv,
  outcomeLabel,
  outcomeText,
  scanOutcomeSummary,
  scanState,
} from "@/lib/scanOutcomes";
import { shortDate, type ScanRow, type SiteRow } from "@/lib/workspace";

export function Scans({
  scans,
  sites,
  onChanged,
}: {
  scans: ScanRow[];
  sites: SiteRow[];
  onChanged: () => void;
}) {
  const [siteFilter, setSiteFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const scanSubject = (scan: ScanRow) =>
    sites.find((site) => site.id === scan.site_id)?.domain ??
    scan.resource ??
    (scan.site_id ? "—" : "Platform scan");

  const filtered = scans.filter((s) => {
    if (siteFilter !== "all" && s.site_id !== siteFilter) return false;
    if (statusFilter !== "all" && s.status !== statusFilter) return false;
    return true;
  });

  const exportCsv = () => {
    downloadCsv(
      `bulwark-scans-${new Date().toISOString().slice(0, 10)}.csv`,
      [
        "Started",
        "Site",
        "Scan state",
        "HTTP",
        "Response ms",
        "Checks total",
        "Passed",
        "Findings",
        "Not checked",
        "Errors",
        "Outcome detail",
        "Scan error",
      ],
      filtered.map((s) => {
        const summary = scanOutcomeSummary(s);
        return [
          s.started_at,
          scanSubject(s),
          scanState(s, summary).label,
          s.http_status ?? "",
          s.response_ms ?? "",
          summary.detailed ? summary.total : s.checks_total,
          summary.detailed ? summary.passed : "",
          summary.detailed ? summary.finding : "",
          summary.detailed ? summary.not_checked : "",
          summary.detailed ? summary.error : "",
          summary.detailed
            ? `${summary.completed}/${summary.total} checks completed`
            : "Not recorded for this scan",
          s.error ?? "",
        ];
      }),
    );
  };

  return (
    <>
      <PageTitle
        title="Scans"
        subtitle="What each external posture scan completed, observed, or could not check."
        action={
          <div className="title-actions">
            <Button onClick={onChanged}>↻ Refresh</Button>
            <Button onClick={exportCsv} download>
              Export CSV
            </Button>
          </div>
        }
      />
      <div className="filters">
        <select value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)} aria-label="Site">
          <option value="all">Site: all</option>
          {sites.map((s) => (
            <option value={s.id} key={s.id}>
              {s.domain}
            </option>
          ))}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Status">
          <option value="all">Status: all</option>
          <option value="completed">Completed</option>
          <option value="partial">Partial</option>
          <option value="failed">Failed</option>
        </select>
        <span>
          {filtered.length} scan{filtered.length === 1 ? "" : "s"} shown
        </span>
      </div>
      <div className="card data-table scans-table">
        <div className="scan-row table-head">
          <span>Started</span>
          <span>Site</span>
          <span>Scan state</span>
          <span>Coverage</span>
          <span>Check outcomes</span>
        </div>
        {filtered.map((s) => {
          const summary = scanOutcomeSummary(s);
          const state = scanState(s, summary);
          const incompleteReason = [
            summary.not_checked ? outcomeText("not_checked", summary.not_checked) : null,
            summary.error ? outcomeText("error", summary.error) : null,
          ]
            .filter(Boolean)
            .join(" · ");

          return (
            <div className="scan-row" key={s.id}>
              <code>{shortDate(s.started_at)}</code>
              <code>{scanSubject(s)}</code>
              <span className={`scan-state ${state.tone}`}>
                <Dot tone={state.tone} />
                {state.label}
              </span>
              <span className="scan-coverage">
                {summary.detailed ? (
                  <>
                    <strong>
                      {summary.completed}/{summary.total} checked
                    </strong>
                    {incompleteReason && <small>{incompleteReason}</small>}
                  </>
                ) : (
                  <>
                    <strong>Outcome detail unavailable</strong>
                    <small>This older scan did not record check-level results.</small>
                  </>
                )}
              </span>
              <span
                className={`scan-outcomes ${summary.detailed ? "" : "unavailable"}`}
                aria-label={
                  summary.detailed
                    ? CHECK_OUTCOME_ORDER.map((outcome) => outcomeText(outcome, summary[outcome])).join(", ")
                    : "Check-level outcomes were not recorded for this scan"
                }
              >
                {summary.detailed ? (
                  CHECK_OUTCOME_ORDER.some((outcome) => summary[outcome] > 0) ? (
                    CHECK_OUTCOME_ORDER.filter((outcome) => summary[outcome] > 0).map((outcome) => (
                      <span className={`check-outcome ${outcome}`} key={outcome}>
                        <b>{summary[outcome]}</b> {outcomeLabel(outcome, summary[outcome])}
                      </span>
                    ))
                  ) : (
                    <span className="check-outcome not_checked">No outcomes recorded</span>
                  )
                ) : (
                  <span className="check-outcome not_checked">Not recorded</span>
                )}
              </span>
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="scan-row empty-row">
            <span>No scans yet. Verified sites are scanned automatically.</span>
          </div>
        )}
        <div className="table-footer">
          <span>{filtered.length} result{filtered.length === 1 ? "" : "s"}</span>
          <span>Newest first</span>
        </div>
      </div>
    </>
  );
}
