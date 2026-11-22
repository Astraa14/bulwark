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
  const { method = "GET", body = null, fetchImpl = fetch, lookup, timeout = 12_000 } = opts;
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
    },
  });
}

const PERMISSION_STATUSES = new Set([400, 401, 403, 404]);

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
      tablesInspected,
      storageBucketsVisible,
      storageChecked,
      rlsChecked,
      policyAnalysis: "heuristic",
      notes,
    },
  };
}
