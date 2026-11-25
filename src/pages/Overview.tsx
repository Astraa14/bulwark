import { Button, Dot, PageTitle, Stat } from "@/components/Ui";
import type { IntegrationTab, Page } from "@/lib/router";
import {
  SEVERITY_ORDER,
  findingImpactSummary,
  isShipBlocker,
  siteHealth,
  siteLabel,
  sortFindingsByPriority,
  stackLabel,
} from "@/lib/scanOutcomes";
import { PLAN_SITE_LIMIT, relTime, type FindingRow, type ScanRow, type SiteRow } from "@/lib/workspace";

export function Overview({
  go,
  openModal,
  sites,
  connectionCount = 0,
  findings,
  scans,
  scanCount,
  onOpenFinding,
}: {
  go: (p: Page, tab?: IntegrationTab) => void;
  openModal: () => void;
  sites: SiteRow[];
  connectionCount?: number;
  findings: FindingRow[];
  scans: ScanRow[];
  scanCount: number;
  onOpenFinding: (id: string) => void;
}) {
  const openFindings = findings.filter((f) => f.status === "open");
  const blockers = openFindings.filter(isShipBlocker);
  const hardening = openFindings.filter((f) => !isShipBlocker(f));
  const critical = openFindings.filter((f) => f.severity === "critical").length;
  const high = openFindings.filter((f) => f.severity === "high").length;
  const medium = openFindings.filter((f) => f.severity === "medium").length;
  const low = openFindings.filter((f) => f.severity === "low").length;
  const info = openFindings.filter((f) => f.severity === "info").length;
  const activeSites = sites.filter((site) => site.status === "verified").length;
  const pausedSites = sites.filter((site) => site.status === "paused").length;
  const pendingSites = sites.filter((site) => site.status === "pending").length;
  const priorityFindings = sortFindingsByPriority(openFindings);
  const hasMonitoredAssets = activeSites > 0 || connectionCount > 0;
  const isSetupRequired = !hasMonitoredAssets && (sites.length === 0 || pendingSites > 0);
  const isAllPaused = !hasMonitoredAssets && pausedSites > 0;

  const scanDays = Array.from({ length: 30 }, () => 0);
  for (const scan of scans) {
    const daysAgo = (Date.now() - new Date(scan.started_at).getTime()) / 86_400_000;
    if (daysAgo < 0 || daysAgo >= 30) continue;
    scanDays[29 - Math.floor(daysAgo)] += 1;
  }
  const scanDayPeak = Math.max(1, ...scanDays);
  const severityCounts = [critical, high, medium, low, info];
  const briefingState =
    blockers.length > 0 ? "has-findings" :
    isSetupRequired ? "needs-setup" :
    isAllPaused ? "is-paused" : "is-clear";
  const briefingTone =
    blockers.length > 0
      ? critical > 0 ? "critical" : "high"
      : isSetupRequired ? "medium" : isAllPaused ? "low" : "healthy";

  const buckets = Array.from({ length: 10 }, () => ({ d: 0, r: 0 }));
  for (const f of findings) {
    const daysAgo = (Date.now() - new Date(f.last_seen_at).getTime()) / 86_400_000;
    if (daysAgo < 0 || daysAgo > 30) continue;
    const idx = 9 - Math.min(9, Math.floor(daysAgo / 3));
    if (f.status === "resolved") buckets[idx].r += 1;
    else buckets[idx].d += 1;
  }
  const peak = Math.max(1, ...buckets.map((b) => b.d + b.r));

  const now = new Date();
  const chartDateFmt = (daysBack: number) => {
    const d = new Date(now);
    d.setDate(d.getDate() - daysBack);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  const yTop = Math.max(4, Math.ceil(peak / 2) * 2);
  const yMid = Math.round(yTop / 2);

  return (
    <>
      <PageTitle
        title="Overview"
        subtitle="A quieter way to keep your code safe."
      />
      <section className={`briefing card ${briefingState}`}>
        <div className="eyebrow-row">
          <span className="briefing-kicker">
            <Dot tone={briefingTone} />
            {blockers.length > 0
              ? "HOLD BEFORE SHARING · SHIP-BLOCKERS"
              : isSetupRequired
                ? "LAUNCH READINESS · SETUP REQUIRED"
                : isAllPaused
                  ? "MONITORING PAUSED"
                  : openFindings.length > 0
                    ? "SAFE TO SHIP · POLISH LATER"
                    : "SAFE TO SHIP · ALL CLEAR"}
          </span>
          <code>
            {new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" })} ·{" "}
            {new Date().toUTCString().slice(17, 22)} UTC
          </code>
        </div>
        <div className="briefing-main">
          <div className="briefing-copy">
            <h2>
              {blockers.length > 0
                ? `${blockers.length} ship-blocker${blockers.length === 1 ? "" : "s"} to fix before sharing your link`
                : isSetupRequired
                  ? pendingSites > 0
                    ? "Verify your domain to check launch readiness"
                    : "Connect your app to check if it is safe to ship"
                  : isAllPaused
                    ? "Monitoring is paused"
                    : hardening.length > 0
                      ? `Safe to ship — ${hardening.length} hardening item${hardening.length === 1 ? "" : "s"} for later`
                      : "Safe to ship — no open exposures"}
            </h2>
            <p className="briefing-summary">
              {blockers.length > 0
                ? `${blockers.length} launch-blocking exposure${blockers.length === 1 ? "" : "s"} (${critical} critical, ${high} high)${hardening.length > 0 ? ` · ${hardening.length} lower-urgency hardening item${hardening.length === 1 ? "" : "s"} can wait until after launch.` : " across your monitored sites, repos, and Supabase projects."}`
                : hardening.length > 0
                  ? `Zero leaked keys, open anon tables, or critical blockers found. ${medium} medium · ${low} low${info > 0 ? ` · ${info} info` : ""} defense-in-depth item${hardening.length === 1 ? "" : "s"} can be polished anytime.`
                  : sites.length === 0 && connectionCount === 0
                    ? "Add a live URL, GitHub repo, or Supabase project — Bulwark checks for leaked keys, open anon tables, and AI/billing footguns."
                    : isAllPaused
                      ? "Your connected sites are paused. Resume monitoring whenever you are ready."
                      : pendingSites > 0 && !hasMonitoredAssets
                        ? "Verify your pending site to run external checks."
                        : "Latest checks found no leaked credentials, open anon tables, or critical exposures."}
            </p>
          </div>
          {openFindings.length > 0 ? (
            <div className="title-actions">
              <Button onClick={() => go("AI Copilot")}>Weekly brief</Button>
              <Button dark onClick={() => go("Threats")}>
                {blockers.length > 0 ? "Fix blockers" : "Review items"}
              </Button>
            </div>
          ) : sites.length === 0 && connectionCount === 0 ? (
            <div className="title-actions">
              <Button onClick={() => go("Integrations", "platforms")}>Connect GitHub / Supabase</Button>
              <Button dark onClick={openModal}>+ Add site</Button>
            </div>
          ) : pendingSites > 0 || !hasMonitoredAssets ? (
            <Button onClick={() => go("Sites")}>{pendingSites > 0 ? "Verify site" : "Manage sites"}</Button>
          ) : null}
        </div>
        {openFindings.length > 0 && (
          <>
            <div className="section-head">
              <span className="attention-caption">
                {blockers.length > 0 ? "Fix before sharing publicly" : "Recommended hardening"}
              </span>
              <button type="button" onClick={() => go("Threats")}>
                View all ({openFindings.length}) →
              </button>
            </div>
            <div className="attention-grid">
              {priorityFindings.slice(0, 3).map((f) => (
                <button
                  type="button"
                  className="attention"
                  key={f.id}
                  onClick={() => onOpenFinding(f.id)}
                  title={`Open ${f.title}`}
                >
                  <div>
                    <span className="severity">
                      <Dot tone={f.severity} />
                      {isShipBlocker(f) ? `Ship-blocker · ${f.severity}` : `Polish later · ${f.severity}`}
                    </span>
                    <strong title={f.title}>{f.title}</strong>
                    <span className="attention-impact">{findingImpactSummary(f)}</span>
                    <code title={siteLabel(sites, f)}>
                      {siteLabel(sites, f)}
                    </code>
                  </div>
                </button>
              ))}
            </div>
          </>
        )}
      </section>
      <section className="stats" aria-label="Workspace metrics">
        <Stat
          label="Connected sites"
          value={String(sites.length)}
          onClick={() => go("Sites")}
          figure={
            <span className="stat-slots">
              {Array.from({ length: PLAN_SITE_LIMIT }, (_, i) => (
                <i key={i} className={i < sites.length ? "on" : ""} />
              ))}
            </span>
          }
        />
        <Stat
          label="Open threats"
          value={String(openFindings.length)}
          onClick={() => go("Threats")}
          figure={
            <span className="stat-severity">
              {openFindings.length === 0 ? (
                <i className="empty" />
              ) : (
                severityCounts.map((count, i) =>
                  count > 0 ? (
                    <i
                      key={SEVERITY_ORDER[i]}
                      style={{ flexGrow: count, opacity: 1 - i * 0.17 }}
                    />
                  ) : null,
                )
              )}
            </span>
          }
        />
        <Stat
          label="Scans completed"
          value={scanCount.toLocaleString()}
          onClick={() => go("Scans")}
          figure={
            <span className="stat-spark">
              {scanDays.map((count, i) => (
                <i key={i} style={{ height: `${Math.max(8, (count / scanDayPeak) * 100)}%` }} />
              ))}
            </span>
          }
        />
        <Stat
          label="Active monitors"
          value={String(activeSites)}
          onClick={() => go("Sites")}
          figure={
            <span className="stat-split">
              <i
                style={{
                  width: `${sites.length ? (activeSites / sites.length) * 100 : 0}%`,
                }}
              />
            </span>
          }
        />
      </section>
      <section className="overview-grid">
        <div className="card chart-card">
          <div className="card-heading">
            <h3>Threat activity</h3>
            <span className="chart-range" aria-label="Threat activity for the last 30 days">Last 30 days</span>
          </div>
          <div className="chart-count">
            <strong>{findings.length}</strong>
            <span>tracked</span>
            <div className="legend">
              <i /> Detected <i /> Resolved
            </div>
          </div>
          <div className="chart">
            <div className="grid-line l1" />
            <div className="grid-line l2" />
            <div className="grid-line l3" />
            <div className="y-axis">
              <span>{yTop}</span>
              <span>{yMid}</span>
              <span>0</span>
            </div>
            <div className="bars">
              {buckets.map((b, i) => (
                <span className="bar-slot" key={i}>
                  <i className="detected" style={{ height: `${(b.d / peak) * 54}px` }} />
                  <i className="resolved" style={{ height: `${(b.r / peak) * 54}px` }} />
                </span>
              ))}
            </div>
            <div className="chart-x">
              <span>{chartDateFmt(27)}</span>
              <span>{chartDateFmt(14)}</span>
              <span>{chartDateFmt(0)}</span>
            </div>
          </div>
        </div>
        <div className="card feed">
          <div className="card-heading">
            <h3>Live threat feed</h3>
            <span>
              <Dot /> Live
            </span>
          </div>
          {priorityFindings.slice(0, 3).map((f) => (
            <button
              type="button"
              className="feed-row"
              key={f.id}
              onClick={() => onOpenFinding(f.id)}
              title={`Open ${f.title}`}
            >
              <span>
                <Dot tone={f.severity} />
                {f.severity}
              </span>
              <div>
                <strong title={f.title}>{f.title}</strong>
                <code>
                  {siteLabel(sites, f)} · {relTime(f.last_seen_at)}
                </code>
              </div>
            </button>
          ))}
          {priorityFindings.length === 0 && <p className="feed-empty">No open threats. New findings will appear here.</p>}
        </div>
      </section>
      {sites.length > 0 && (
        <section className="card sites-health">
          <div className="card-heading">
            <h3>Sites health</h3>
            <button onClick={() => go("Sites")}>View all sites →</button>
          </div>
          <div className="table">
            <div className="tr th">
              <span>Domain</span>
              <span>Health</span>
              <span>Last scan</span>
              <span>Open threats</span>
              <span>Stack</span>
            </div>
            {sites.map((s) => {
              const health = siteHealth(s, findings);
              return (
                <div className="tr" key={s.id}>
                  <code className="table-domain" title={s.domain}>{s.domain}</code>
                  <span>
                    <Dot tone={health.tone} />
                    {health.label}
                  </span>
                  <code>{relTime(s.last_scan_at)}</code>
                  <span>{findings.filter((f) => f.site_id === s.id && f.status === "open").length}</span>
                  <span>{stackLabel(s.stack)}</span>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </>
  );
}
