import { fetchWithTimeout } from "./checks.mjs";
import { assertLeastPrivilegeKey, assertSupabaseProjectUrl } from "./supabase-config.mjs";

function finding(checkKey, title, severity, detail, extra = {}) {
  return { check_key: checkKey, title, severity, detail, ...extra };
}

function parseJson(body) {
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

function outcome(key, label, status, error = null) {
  return {
    key,
    label,
    status,
    complete: status === "pass" || status === "finding",
    ...(error ? { error } : {}),
  };
}

function failedResult(message) {
  const check = outcome("project_access", "Project access", "error", message);
  return {
    findings: [],
    status: "failed",
    error: message,
    checkResults: [check],
    checksTotal: 1,
    checksPassed: 0,
    checksErrored: 1,
    checksSkipped: 0,
    coverage: {
      tablesInspected: 0,
      storageBucketsVisible: 0,
      storageChecked: false,
      rlsChecked: false,
      policyAnalysis: "heuristic",
      notes: [`Project could not be checked: ${message}`],
    },
  };
}

async function request(baseUrl, apiKey, path, opts = {}) {
  const {
    method = "GET",
    body = null,
    headers: extraHeaders = {},
    fetchImpl = fetch,
    lookup,
    timeout = 12_000,
  } = opts;
  return fetchWithTimeout(`${baseUrl}${path}`, {
    method,
    body,
    timeout,
    maxBytes: 2_000_000,
    fetch: fetchImpl,
    ...(lookup ? { lookup } : {}),
    headers: {
      apikey: apiKey,
      authorization: `Bearer ${apiKey}`,
      ...(body ? { "content-type": "application/json" } : {}),
      ...extraHeaders,
    },
  });
}

const PERMISSION_STATUSES = new Set([400, 401, 403, 404]);
const MAX_ANON_TABLE_PROBES = 12;
const SENSITIVE_TABLE_RE =
  /^(?:users?|profiles?|accounts?|customers?|members?|admins?|api[_-]?keys?|keys?|secrets?|tokens?|sessions?|orders?|payments?|invoices?|subscriptions?|billing|messages?|chats?|emails?|leads?|waitlist|webhooks?|documents?|uploads?|wallets?|credits?)$/i;
const PRIVILEGED_RPC_RE =
  /(?:^|_)(?:admin|delete|drop|grant|revoke|exec|sql|truncate|reset|impersonate|bypass|secret)(?:_|$)/i;

export function parseOpenApiSurface(spec) {
  if (!spec || typeof spec !== "object" || (!spec.swagger && !spec.openapi)) {
    return { exposed: false, tables: [], rpcs: [] };
  }
  const paths = spec.paths;
  if (!paths || typeof paths !== "object") {
    return { exposed: false, tables: [], rpcs: [] };
  }

  const tables = [];
  const rpcs = [];
  for (const [routePath, methodsObj] of Object.entries(paths)) {
    if (!methodsObj || typeof methodsObj !== "object") continue;
    const methods = Object.keys(methodsObj)
      .map((m) => m.toLowerCase())
      .filter((m) => ["get", "post", "patch", "put", "delete"].includes(m));

    const tableMatch = routePath.match(/^\/([A-Za-z_][A-Za-z0-9_]*)$/);
    if (tableMatch) {
      tables.push({
        name: tableMatch[1],
        methods,
        sensitive: SENSITIVE_TABLE_RE.test(tableMatch[1]),
      });
      continue;
    }

    const rpcMatch = routePath.match(/^\/rpc\/([A-Za-z_][A-Za-z0-9_]*)$/);
    if (rpcMatch && rpcMatch[1].toLowerCase() !== "bulwark_check_rls") {
      rpcs.push({
        name: rpcMatch[1],
        privilegedName: PRIVILEGED_RPC_RE.test(rpcMatch[1]),
      });
    }
  }

  tables.sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || a.name.localeCompare(b.name));
  return { exposed: true, tables, rpcs };
}

function parseContentRangeTotal(headerValue) {
  if (!headerValue) return null;
  const match = String(headerValue).match(/\/(\d+)\s*$/);
  if (!match) return null;
  const count = Number(match[1]);
  return Number.isFinite(count) ? count : null;
}

/**
 * Zero-SQL-helper attacker-view check: inspects what an unauthenticated visitor
 * holding only the public anon/publishable key can enumerate via PostgREST's
 * OpenAPI spec and zero-row HEAD count probes (0 bytes of table data read).
 */
async function inspectAnonSurface(baseUrl, apiKey, specBody, dashboardBase, { fetchImpl, lookup }) {
  const spec = parseJson(specBody);
  const surface = parseOpenApiSurface(spec);
  if (!surface.exposed) {
    return {
      findings: [],
      errors: [],
      tablesExposed: 0,
      readableTables: 0,
      rpcsExposed: 0,
    };
  }

  const findings = [];
  const errors = [];
  const targets = surface.tables.slice(0, MAX_ANON_TABLE_PROBES);
  let readableTables = 0;

  const probeResults = await Promise.all(
    targets.map(async (table) => {
      const res = await request(
        baseUrl,
        apiKey,
        `/rest/v1/${encodeURIComponent(table.name)}?limit=1`,
        {
          method: "HEAD",
          headers: { prefer: "count=exact" },
          fetchImpl,
          lookup,
          timeout: 8_000,
        },
      );
      return { table, res };
    }),
  );

  for (const { table, res } of probeResults) {
    if (res.error) {
      errors.push(`Anon probe on ${table.name}: ${res.error}`);
      continue;
    }
    if (!res.ok) continue;
    const rowCount = parseContentRangeTotal(res.headers?.["content-range"]);
    if (rowCount !== null && rowCount > 0) {
      readableTables += 1;
      findings.push(
        finding(
          "supabase_anon_readable_table",
          `Unauthenticated anon key can read ${rowCount} row${rowCount === 1 ? "" : "s"} in \`${table.name}\``,
          table.sensitive ? "critical" : "high",
          `Using only the public publishable/anon key, an unauthenticated request to \`/rest/v1/${table.name}\` reported ${rowCount} visible row${rowCount === 1 ? "" : "s"}. Any visitor who extracts your frontend's Supabase key can query those rows right now unless this table is intentionally public.`,
          {
            url: `${dashboardBase}/auth/policies`,
            evidence: `HEAD /rest/v1/${table.name} · content-range total=${rowCount} · anon role`,
            affected_resource: `anon_table:${table.name}`,
            confidence: "high",
            what_it_does_not_prove:
              "Bulwark used a zero-row HEAD count probe and never read row contents. If this table is meant to be public (such as a public blog or catalog), acknowledge or snooze this finding.",
            remediation: `Enable Row Level Security on \`public.${table.name}\` and restrict SELECT policies to \`authenticated\` users (for example \`using (auth.uid() = user_id)\`).`,
          },
        ),
      );
    }
  }

  if (surface.rpcs.length > 0) {
    const privileged = surface.rpcs.some((r) => r.privilegedName);
    const names = surface.rpcs.map((r) => r.name);
    findings.push(
      finding(
        "supabase_anon_rpc_exposed",
        `Custom Postgres RPC callable by anon: ${names.slice(0, 3).join(", ")}${names.length > 3 ? "…" : ""}`,
        privileged ? "high" : "medium",
        `PostgREST lists ${names.length} custom \`/rest/v1/rpc/*\` function${names.length === 1 ? "" : "s"} in the public \`anon\` schema (${names.slice(0, 6).join(", ")}). Postgres grants EXECUTE to \`public\` and \`anon\` on new functions by default, which lets unauthenticated callers invoke them directly.`,
        {
          url: `${dashboardBase}/database/functions`,
          evidence: `Exposed RPCs (${names.length}): ${names.slice(0, 6).join(", ")}`,
          affected_resource: "project:anon_rpcs",
          confidence: "medium",
          what_it_does_not_prove:
            "Listing in OpenAPI proves the function is exposed to PostgREST, not that calling it mutates data or bypasses internal checks.",
          remediation:
            "Revoke public access on internal functions: `revoke all on function public.<name>(...) from public, anon;` and grant execute only to `authenticated` or `service_role`.",
        },
      ),
    );
  }

  return {
    findings,
    errors,
    tablesExposed: surface.tables.length,
    readableTables,
    rpcsExposed: surface.rpcs.length,
    tableNames: surface.tables.map((t) => t.name),
  };
}

function rlsFindings(rows, dashboardBase) {
  const findings = [];
  let permissivePolicies = 0;

  for (const row of rows) {
    const table = String(row.table_name ?? "").trim();
    if (!table) continue;
    const policies = Number(row.policy_count ?? 0);
    const editorUrl = `${dashboardBase}/editor`;

    if (row.row_security_enabled !== true) {
      findings.push(
        finding(
          "supabase_table_no_rls",
          `Table without RLS: ${table}`,
          "high",
          `Table \`${table}\` in the public schema does not have Row Level Security enabled. If it is exposed through the API, the publishable key can read or write rows according to table grants. Enable RLS and add policies that match your access rules.`,
          {
            url: editorUrl,
            evidence: `public.${table} · row_security_enabled=false`,
            affected_resource: `table:${table}`,
            confidence: "high",
            what_it_does_not_prove:
              "This does not prove the table contains sensitive rows or that it is reachable with your current grants. It does mean RLS is not restricting it.",
            remediation: `Enable RLS on public.${table}, then add policies for the operations your application needs.`,
          },
        ),
      );
    } else if (policies === 0) {
      findings.push(
        finding(
          "supabase_table_no_policies",
          `RLS enabled with no policies: ${table}`,
          "low",
          `Table \`${table}\` has RLS enabled but no policies. That is deny-by-default for anon/authenticated clients, which is safe from exposure but usually means your application cannot read the table directly.`,
          {
            url: editorUrl,
            evidence: `public.${table} · policies=0`,
            affected_resource: `table:${table}`,
            confidence: "high",
            what_it_does_not_prove:
              "No policies is not a data-exposure finding. It may be intentional if the table is only accessed by server code.",
            remediation: `If browser clients need this table, add scoped policies; otherwise no action is needed.`,
          },
        ),
      );
    } else if (row.has_permissive_policy === true) {
      permissivePolicies += 1;
      findings.push(
        finding(
          "supabase_table_permissive_policy",
          `Possibly permissive RLS policy: ${table}`,
          "medium",
          `At least one policy on \`${table}\` uses a literal \`true\` expression. That may expose every row to the role the policy targets. This is a heuristic, not a full policy review.`,
          {
            url: editorUrl,
            evidence: `public.${table} · ${policies} policies · literal true expression`,
            affected_resource: `table:${table}`,
            confidence: "low",
            what_it_does_not_prove:
              "A literal true expression does not by itself prove data is reachable: the policy's command, role, and other policies still matter. Bulwark does not evaluate policy logic.",
            remediation:
              "Review the policy in the Supabase dashboard and scope it to the authenticated user or the rows they own.",
          },
        ),
      );
    }
  }

  return { findings, permissivePolicies };
}

export async function scanSupabaseProject(projectUrl, apiKey, opts = {}) {
  const { fetchImpl = fetch, lookup } = opts;

  let baseUrl;
  try {
    baseUrl = assertSupabaseProjectUrl(projectUrl);
    assertLeastPrivilegeKey(apiKey);
  } catch (err) {
    return failedResult(err.message);
  }

  const projectRef = new URL(baseUrl).hostname.split(".")[0];
  const dashboardBase = `https://supabase.com/dashboard/project/${projectRef}`;

  const findings = [];
  const errors = [];
  const notes = [];
  const checkResults = [];

  const connectivity = await request(baseUrl, apiKey, "/rest/v1/", {
    headers: { accept: "application/openapi+json, application/json" },
    fetchImpl,
    lookup,
  });
  if (connectivity.error) {
    return failedResult(`Supabase connectivity failed: ${connectivity.error}`);
  }
  if (!connectivity.ok) {
    if (connectivity.status === 401 || connectivity.status === 403) {
      return failedResult(
        `Supabase rejected the credential (HTTP ${connectivity.status}). Check that the project URL and publishable key belong together.`,
      );
    }
    return failedResult(`Supabase API returned HTTP ${connectivity.status}.`);
  }
  checkResults.push(outcome("project_access", "Project access", "pass"));

  // -------------------------------------------------------------------------
  // Zero-helper PostgREST anon surface audit (OpenAPI + zero-row HEAD probes)
  // -------------------------------------------------------------------------
  const anonAudit = await inspectAnonSurface(
    baseUrl,
    apiKey,
    connectivity.body,
    dashboardBase,
    { fetchImpl, lookup },
  );
  findings.push(...anonAudit.findings);
  errors.push(...anonAudit.errors);
  if (anonAudit.errors.length > 0) {
    checkResults.push(
      outcome("anon_surface", "Public anon API surface", "error", anonAudit.errors[0]),
    );
  } else if (anonAudit.tablesExposed > 0 || anonAudit.rpcsExposed > 0) {
    checkResults.push(
      outcome(
        "anon_surface",
        "Public anon API surface",
        anonAudit.findings.length > 0 ? "finding" : "pass",
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Storage buckets
  // -------------------------------------------------------------------------
  let storageChecked = false;
  let storageBucketsVisible = 0;
  const storage = await request(baseUrl, apiKey, "/storage/v1/bucket", {
    fetchImpl,
    lookup,
  });

  if (storage.error) {
    checkResults.push(
      outcome("storage", "Storage buckets", "error", `Storage request failed: ${storage.error}`),
    );
    errors.push(`Storage bucket check: ${storage.error}`);
    notes.push("Storage bucket access could not be checked.");
  } else if (storage.ok) {
    const buckets = parseJson(storage.body);
    if (!Array.isArray(buckets)) {
      checkResults.push(
        outcome("storage", "Storage buckets", "error", "Storage returned an unexpected response."),
      );
      errors.push("Storage bucket check returned an unexpected response.");
    } else {
      storageChecked = true;
      storageBucketsVisible = buckets.length;
      let publicBuckets = 0;
      for (const bucket of buckets) {
        if (bucket?.public !== true) continue;
        publicBuckets += 1;
        const name = String(bucket.name ?? "unnamed");
        findings.push(
          finding(
            "supabase_public_storage",
            `Public storage bucket: ${name}`,
            "high",
            "The storage bucket is publicly readable. Anyone with the bucket URL can list and download files without authentication. Make it private unless public file sharing is intentional.",
            {
              url: `${dashboardBase}/storage/buckets/${encodeURIComponent(name)}`,
              evidence: `Bucket "${name}" is public`,
              affected_resource: `storage:${name}`,
              confidence: "high",
              what_it_does_not_prove:
                "Public read access does not prove the bucket contains sensitive files, but it does remove authentication as a control.",
              remediation: "Set the bucket to private and use signed URLs for intended sharing.",
            },
          ),
        );
      }
      checkResults.push(
        outcome(
          "storage",
          "Storage buckets",
          publicBuckets > 0 ? "finding" : "pass",
        ),
      );
      if (storageBucketsVisible === 0) {
        notes.push(
          "No storage buckets were visible to this key. That can mean the project has none, or that the key cannot list them.",
        );
      }
    }
  } else if (PERMISSION_STATUSES.has(storage.status)) {
    checkResults.push(
      outcome(
        "storage",
        "Storage buckets",
        "not_checked",
        `The publishable key cannot list storage buckets (HTTP ${storage.status}).`,
      ),
    );
    notes.push(
      "Storage buckets were not checked: listing them requires a service-role key, which Bulwark does not request.",
    );
  } else {
    checkResults.push(
      outcome("storage", "Storage buckets", "error", `HTTP ${storage.status}`),
    );
    errors.push(`Storage bucket listing: HTTP ${storage.status}`);
  }

  // -------------------------------------------------------------------------
  // RLS metadata (heuristic policy analysis only)
  // -------------------------------------------------------------------------
  let rlsChecked = false;
  let tablesInspected = 0;
  const rls = await request(baseUrl, apiKey, "/rest/v1/rpc/bulwark_check_rls", {
    method: "POST",
    body: "{}",
    fetchImpl,
    lookup,
  });

  if (rls.error) {
    checkResults.push(
      outcome("rls", "Row Level Security", "error", `RLS check failed: ${rls.error}`),
    );
    errors.push(`RLS introspection: ${rls.error}`);
  } else if (rls.ok) {
    const rows = parseJson(rls.body);
    if (!Array.isArray(rows)) {
      checkResults.push(
        outcome("rls", "Row Level Security", "error", "RLS helper returned an unexpected response."),
      );
      errors.push("RLS introspection returned an unexpected response.");
    } else {
      const publicRows = rows.filter(
        (row) => !row.table_schema || row.table_schema === "public",
      );
      rlsChecked = true;
      tablesInspected = publicRows.length;
      const analysis = rlsFindings(publicRows, dashboardBase);
      findings.push(...analysis.findings);
      checkResults.push(
        outcome(
          "rls",
          "Row Level Security",
          analysis.findings.length > 0 ? "finding" : "pass",
        ),
      );
      notes.push(
        "RLS policy analysis is heuristic: Bulwark reports literal `true` policies but does not evaluate policy expressions or role targeting.",
      );
      if (tablesInspected === 0) {
        notes.push("The RLS helper returned no public tables, so there was nothing to inspect.");
      }
    }
  } else if (PERMISSION_STATUSES.has(rls.status)) {
    checkResults.push(
      outcome(
        "rls",
        "Row Level Security",
        "not_checked",
        `The RLS helper is missing or not executable with this key (HTTP ${rls.status}).`,
      ),
    );
    findings.push(
      finding(
        "supabase_rls_not_checked",
        "RLS inspection is not configured",
        "info",
        "Bulwark could not inspect Row Level Security. Install the helper at `supabase/customer/bulwark_check_rls.sql` in this project's SQL editor, then re-scan. Until then, this check is reported as not checked, not as safe.",
        {
          url: `${dashboardBase}/sql/new`,
          evidence: `RPC bulwark_check_rls returned HTTP ${rls.status}`,
          affected_resource: "project:rls",
          confidence: "high",
          what_it_does_not_prove:
            "This says nothing about whether RLS is enabled or whether policies are safe; it only says Bulwark could not look.",
          remediation:
            "Run supabase/customer/bulwark_check_rls.sql in the project, then re-scan.",
        },
      ),
    );
    notes.push(
      "RLS was not checked: the customer-installed helper was missing or not executable.",
    );
  } else {
    checkResults.push(
      outcome("rls", "Row Level Security", "error", `HTTP ${rls.status}`),
    );
    errors.push(`RLS introspection: HTTP ${rls.status}`);
  }

  const checksPassed = checkResults.filter((check) => check.status === "pass").length;
  const checksErrored = checkResults.filter((check) => check.status === "error").length;
  const checksSkipped = checkResults.filter((check) => check.status === "not_checked").length;

  return {
    findings,
    status: errors.length > 0 || checksSkipped > 0 ? "partial" : "completed",
    error: errors.length ? errors.slice(0, 5).join("; ") : null,
    checkResults,
    checksTotal: checkResults.length,
    checksPassed,
    checksErrored,
    checksSkipped,
    coverage: {
      tablesInspected: Math.max(tablesInspected, anonAudit.tablesExposed),
      anonTablesExposed: anonAudit.tablesExposed,
      anonReadableTables: anonAudit.readableTables,
      anonRpcsExposed: anonAudit.rpcsExposed,
      storageBucketsVisible,
      storageChecked,
      rlsChecked,
      policyAnalysis: "heuristic",
      notes,
    },
  };
}
