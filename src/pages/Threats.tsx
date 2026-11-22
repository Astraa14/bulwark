import { useMemo, useState } from "react";
import { Button, Dot, PageTitle } from "@/components/Ui";
import { SEVERITY_ORDER, downloadCsv, siteLabel } from "@/lib/scanOutcomes";
import { relTime, shortDate, type FindingRow, type SiteRow } from "@/lib/workspace";

export function Threats({
  onOpen,
  findings,
  sites,
}: {
  onOpen: (finding: FindingRow) => void;
  findings: FindingRow[];
  sites: SiteRow[];
}) {
  const [tab, setTab] = useState("All threats");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [siteFilter, setSiteFilter] = useState("all");

  const counts = {
    "All threats": findings.length,
    Open: findings.filter((f) => f.status === "open").length,
    Acknowledged: findings.filter((f) => f.status === "acknowledged").length,
    Resolved: findings.filter((f) => f.status === "resolved").length,
    Ignored: findings.filter((f) => f.status === "ignored").length,
  };

  const filtered = useMemo(
    () =>
      findings.filter((f) => {
        if (tab === "Open" && f.status !== "open") return false;
        if (tab === "Acknowledged" && f.status !== "acknowledged") return false;
        if (tab === "Resolved" && f.status !== "resolved") return false;
        if (tab === "Ignored" && f.status !== "ignored") return false;
        if (severity !== "all" && f.severity !== severity) return false;
        if (siteFilter !== "all" && f.site_id !== siteFilter) return false;
        const site = siteLabel(sites, f);
        const haystack = `${f.title} ${f.check_key} ${site}`.toLowerCase();
        return haystack.includes(query.toLowerCase());
      }),
    [findings, sites, tab, severity, siteFilter, query],
  );

  const exportCsv = () => {
    downloadCsv(
      `bulwark-threats-${new Date().toISOString().slice(0, 10)}.csv`,
      ["Title", "Site", "Severity", "Status", "Snoozed until", "Check", "First seen", "Last seen", "URL", "Evidence"],
      filtered.map((f) => [
        f.title,
        siteLabel(sites, f),
        f.severity,
        f.status,
        f.ignored_until ?? "",
        f.check_key,
        f.first_seen_at,
        f.last_seen_at,
        f.url ?? "",
        f.evidence ?? "",
      ]),
    );
  };

  return (
    <>
      <PageTitle
        title="Threats"
        subtitle="Know what matters. Understand what to do next."
        action={
          <div className="title-actions">
            <Button onClick={exportCsv} download>
              Export CSV
            </Button>
            {counts.Open > 0 && (
              <Button
                dark
                onClick={() => {
                  const worst = findings
                    .filter((f) => f.status === "open")
                    .sort(
                      (a, b) =>
                        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
                    )[0];
                  if (worst) onOpen(worst);
                }}
              >
                Highest priority
              </Button>
            )}
          </div>
        }
      />
      <div className="tabs" role="tablist" aria-label="Threat status">
        {(
          [
            ["All threats", "All"],
            ["Open", "Open"],
            ["Acknowledged", "Acknowledged"],
            ["Resolved", "Resolved"],
            ["Ignored", "Ignored"],
          ] as const
        ).map(([key, label]) => (
          <button
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? "selected" : ""}
            key={key}
            onClick={() => setTab(key)}
          >
            {label} <small>{counts[key]}</small>
          </button>
        ))}
      </div>
      <div className="filters threat-filters">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search threats..."
          aria-label="Search threats"
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="all">Severity: all</option>
          {SEVERITY_ORDER.map((s) => (
            <option value={s} key={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <select value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)} aria-label="Site">
          <option value="all">Site: all</option>
          {sites.map((s) => (
            <option value={s.id} key={s.id}>
              {s.domain}
            </option>
          ))}
        </select>
        <span className="date-filter">{filtered.length} shown</span>
      </div>
      <div className="card data-table threat-table">
        <div className="threat-row table-head">
          <span>Threat</span>
          <span>Site</span>
          <span>Severity</span>
          <span>Status</span>
          <span>Detected</span>
          <span />
        </div>
        {filtered.map((f) => (
          <button type="button" className="threat-row" key={f.id} onClick={() => onOpen(f)}>
            <strong className="table-title" title={f.title}>{f.title}</strong>
            <code className="table-domain" title={siteLabel(sites, f)}>{siteLabel(sites, f)}</code>
            <span>
              <Dot tone={f.severity} />
              {f.severity}
            </span>
            <span className={`tag status-tag status-${f.status}`}>
              {f.status === "ignored" && f.ignored_until
                ? `snoozed · ${shortDate(f.ignored_until)}`
                : f.status}
            </span>
            <code>{relTime(f.last_seen_at)}</code>
            <span>View threat →</span>
          </button>
        ))}
        {filtered.length === 0 && (
          <div className="threat-row empty-row">
            <span>No threats found. That is a good sign.</span>
          </div>
        )}
        <div className="table-footer">
          <span>{filtered.length} result{filtered.length === 1 ? "" : "s"}</span>
          <span>Live from your latest scans</span>
        </div>
      </div>
      <p className="page-note">
        Ordered by severity, then most recent. Each finding includes verified evidence, a 1-click AI
        editor fix prompt, and an optional plain-English explanation.
      </p>
    </>
  );
}
