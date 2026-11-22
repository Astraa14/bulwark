import { useState } from "react";
import { Button, Dot, PageTitle } from "@/components/Ui";
import { STACK_OPTIONS, healthKey, intervalLabel, siteHealth } from "@/lib/scanOutcomes";
import {
  PLAN_SITE_LIMIT,
  deleteSite,
  relTime,
  setSiteStack,
  setSiteStatus,
  type FindingRow,
  type SiteRow,
  type SiteStack,
} from "@/lib/workspace";

export function Sites({
  openModal,
  onVerify,
  sites,
  findings,
  onScan,
  onChanged,
}: {
  openModal: () => void;
  onVerify: (site: SiteRow) => void;
  sites: SiteRow[];
  findings: FindingRow[];
  onScan: (id: string) => void;
  onChanged: () => void;
}) {
  const [search, setSearch] = useState("");
  const [healthFilter, setHealthFilter] = useState("all");
  const [stackFilter, setStackFilter] = useState("all");
  const [busy, setBusy] = useState<string | null>(null);
  const filtered = sites.filter((site) => {
    const matchesSearch = site.domain.includes(search.trim().toLowerCase());
    const matchesHealth = healthFilter === "all" || healthKey(site, findings) === healthFilter;
    const matchesStack =
      stackFilter === "all" ||
      (stackFilter === "unset" ? !site.stack : site.stack === stackFilter);
    return matchesSearch && matchesHealth && matchesStack;
  });

  const healthCounts = sites.reduce<Record<string, number>>((totals, site) => {
    const key = healthKey(site, findings);
    totals[key] = (totals[key] ?? 0) + 1;
    return totals;
  }, {});

  const healthFilters = [
    { key: "all", label: "All sites" },
    { key: "healthy", label: "Healthy" },
    { key: "attention", label: "Needs attention" },
    { key: "at-risk", label: "At risk" },
    { key: "pending", label: "Awaiting verification" },
    { key: "paused", label: "Paused" },
  ];

  const act = async (id: string, fn: () => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn();
      onChanged();
    } catch (err) {
      window.alert((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const remove = (site: SiteRow) => {
    if (!window.confirm(`Delete ${site.domain}? Its scan history and findings are removed too.`)) {
      return;
    }
    void act(site.id, () => deleteSite(site.id));
  };

  return (
    <>
      <PageTitle
        title="Sites"
        subtitle="Your projects, protected around the clock."
        action={
          sites.length > 0 ? (
            <Button dark onClick={openModal}>+ Add site</Button>
          ) : undefined
        }
      />
      {sites.length === 0 ? (
        <div className="card empty-state sites-empty-state">
          <div className="empty-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <h2>Protect your first site</h2>
          <p>Add a domain you control, verify ownership with a DNS record or meta tag, and Bulwark will begin monitoring it.</p>
          <Button dark onClick={openModal}>+ Add your first site</Button>
          <span className="empty-state-note">Only domains you own or are authorized to manage can be monitored.</span>
        </div>
      ) : (
        <>
          <div className="summary-strip" aria-label="Site health summary">
            {healthFilters.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`summary-chip ${healthFilter === item.key ? "active" : ""}`}
                aria-pressed={healthFilter === item.key}
                onClick={() => setHealthFilter(item.key)}
              >
                {item.label}
                <strong>{item.key === "all" ? sites.length : (healthCounts[item.key] ?? 0)}</strong>
              </button>
            ))}
          </div>
          <div className="filters">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search domains..."
              aria-label="Search domains"
            />
            <select className="filter-select" value={healthFilter} onChange={(e) => setHealthFilter(e.target.value)} aria-label="Filter sites by health">
              <option value="all">Health: all</option>
              <option value="healthy">Healthy</option>
              <option value="attention">Needs attention</option>
              <option value="at-risk">At risk</option>
              <option value="pending">Awaiting verification</option>
              <option value="paused">Paused</option>
            </select>
            <select className="filter-select" value={stackFilter} onChange={(e) => setStackFilter(e.target.value)} aria-label="Filter sites by stack">
              <option value="all">Stack: all</option>
              <option value="unset">Not set</option>
              {STACK_OPTIONS.map((opt) => (
                <option value={opt.value} key={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <span>
              {sites.length} site{sites.length === 1 ? "" : "s"} ·{" "}
              {findings.filter((f) => f.status === "open").length} open threat
              {findings.filter((f) => f.status === "open").length === 1 ? "" : "s"}
            </span>
          </div>
          <div className="card data-table sites-table">
            <div className="site-row table-head">
              <span>Domain</span>
              <span>Health</span>
              <span>Last scan</span>
              <span>Threats</span>
              <span>Stack</span>
              <span>Actions</span>
            </div>
            {filtered.map((s) => {
              const health = siteHealth(s, findings);
              return (
                <div className="site-row" key={s.id}>
                  <code className="table-domain" title={s.domain}>{s.domain}</code>
                  <span>
                    <Dot tone={health.tone} />
                    {health.label}
                  </span>
                  <code>{relTime(s.last_scan_at)}</code>
                  <span>{findings.filter((f) => f.site_id === s.id && f.status === "open").length}</span>
                  <span>
                    <select
                      className="status-select stack-select"
                      aria-label={`Stack for ${s.domain}`}
                      value={s.stack ?? ""}
                      disabled={busy === s.id}
                      onChange={(e) => {
                        const value = (e.target.value || null) as SiteStack | null;
                        void act(s.id, () => setSiteStack(s.id, value));
                      }}
                    >
                      <option value="">Not set</option>
                      {STACK_OPTIONS.map((opt) => (
                        <option value={opt.value} key={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </span>
                  <span className="site-actions">
                    {s.status === "verified" && (
                      <button disabled={busy === s.id} onClick={() => onScan(s.id)}>
                        {busy === s.id ? "Working…" : "Scan"}
                      </button>
                    )}
                    {s.status === "verified" && (
                      <button disabled={busy === s.id} onClick={() => act(s.id, () => setSiteStatus(s.id, "pause"))}>
                        Pause
                      </button>
                    )}
                    {s.status === "paused" && (
                      <button disabled={busy === s.id} onClick={() => act(s.id, () => setSiteStatus(s.id, "resume"))}>
                        Resume
                      </button>
                    )}
                    {s.status === "pending" && (
                      <button disabled={busy === s.id} onClick={() => onVerify(s)}>
                        Verify
                      </button>
                    )}
                    <button className="danger" disabled={busy === s.id} onClick={() => remove(s)}>
                      Delete
                    </button>
                  </span>
                </div>
              );
            })}
            {filtered.length === 0 && (
              <div className="site-row empty-row">
                <span>No sites match these filters. Adjust the search or clear a filter.</span>
              </div>
            )}
            <div className="table-footer">
              <span>{sites.length} of {PLAN_SITE_LIMIT} site slots used</span>
              <span>{filtered.length} shown</span>
            </div>
          </div>
          <section className="card activity">
            <h3>Monitoring schedule</h3>
            {sites.map((s) => (
              <div key={s.id}>
                <code>{relTime(s.last_scan_at)}</code>
                <span>
                  <strong title={s.domain}>{s.domain}</strong>
                  <code>
                    {s.status === "verified"
                      ? `${intervalLabel(s.scan_interval_minutes)} · next ${relTime(s.next_scan_at)}`
                      : s.status === "paused"
                        ? "paused"
                        : "awaiting verification"}
                  </code>
                </span>
              </div>
            ))}
          </section>
        </>
      )}
      <p className="page-note">
        Tagging a site's stack tailors AI explanations and copied AI-editor fix prompts to your framework.
      </p>
    </>
  );
}
