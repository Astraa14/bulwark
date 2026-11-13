import { decrypt, maskSecret } from "./crypto.mjs";

function finding(check_key, title, severity, detail, extra = {}) {
  return { check_key, title, severity, detail, ...extra };
}

function redactSecret(value) {
  const s = String(value);
  if (s.length <= 10) return "••••";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function supabaseFetch(baseUrl, apiKey, path, opts = {}) {
  const { timeout = 15000, method = "GET" } = opts;
  const url = baseUrl.replace(/\/$/, "") + path;
  return fetch(url, {
    method,
    headers: {
      apikey: apiKey,
      authorization: `Bearer ${apiKey}`,
      "user-agent": "BulwarkBot/0.4",
    },
    signal: AbortSignal.timeout(timeout),
  });
}

export async function scanSupabaseProject(projectUrl, apiKey) {
  const findings = [];
  const errors = [];

  // 1. Check basic connectivity.
  try {
    const res = await supabaseFetch(projectUrl, apiKey, "/rest/v1/");
    if (!res.ok) {
      errors.push(`Supabase API returned HTTP ${res.status}`);
    }
  } catch (err) {
    errors.push(`Supabase connectivity: ${err?.message ?? String(err)}`);
    return { findings, error: errors.join("; ") };
  }

  // 2. Check storage buckets for public access.
  try {
    const res = await supabaseFetch(projectUrl, apiKey, "/storage/v1/bucket");
    if (res.ok) {
      const buckets = await res.json().catch(() => []);
      for (const bucket of Array.isArray(buckets) ? buckets : []) {
        if (bucket.public === true) {
          findings.push(
            finding(
              "supabase_public_storage",
              `Public storage bucket: ${bucket.name}`,
              "high",
              "The storage bucket is publicly accessible. Anyone can list and download files without authentication. Set it to private unless you intend public file sharing.",
              {
                url: `${projectUrl.replace(/\/$/, "")}/storage/v1/bucket/${bucket.name}`,
                evidence: `Bucket "${bucket.name}" is public`,
                affected_resource: `storage:${bucket.name}`,
              },
            ),
          );
        }
      }
    } else {
      errors.push(`Storage bucket listing: HTTP ${res.status}`);
    }
  } catch (err) {
    errors.push(`Storage bucket check: ${err?.message ?? String(err)}`);
  }

  // 3. Check RLS on tables via the bulwark_check_rls RPC.
  //    The user must deploy this RPC in their Supabase project (see migration SQL).
  let rlsChecked = false;
  let rpcMissing = false;
  try {
    const res = await supabaseFetch(
      projectUrl,
      apiKey,
      "/rest/v1/rpc/bulwark_check_rls",
      { method: "POST", body: JSON.stringify({}) },
    );
    if (res.ok) {
      rlsChecked = true;
      const result = await res.json().catch(() => null);
      if (Array.isArray(result)) {
        for (const row of result) {
          if (row.table_schema === "public" && row.row_security_enabled !== true) {
            findings.push(
              finding(
                "supabase_table_no_rls",
                `Table without RLS: ${row.table_name}`,
                "high",
                `Table \`${row.table_name}\` does not have Row Level Security enabled. Without RLS, any authenticated user can read all rows. Enable RLS and add policies to restrict access.`,
                {
                  url: `${projectUrl.replace(/\/$/, "")}/editor`,
                  evidence: `Table ${row.table_schema}.${row.table_name}`,
                  affected_resource: `table:${row.table_name}`,
                },
              ),
            );
          }
        }
      }
    } else if (res.status === 404 || res.status === 400) {
      // RPC function doesn't exist yet.
      rpcMissing = true;
    } else {
      errors.push(`RLS introspection: HTTP ${res.status}`);
    }
  } catch {
    rpcMissing = true;
  }

  if (rpcMissing && !rlsChecked) {
    findings.push(
      finding(
        "supabase_rls_setup_needed",
        "RLS introspection not configured",
        "info",
        "Bulwark cannot check Row Level Security on your tables yet. Run the `bulwark_check_rls` SQL function in your Supabase project's SQL editor (included in the Bulwark migration), then re-scan.",
        {
          url: `${projectUrl.replace(/\/$/, "")}/editor`,
          evidence: "RPC function bulwark_check_rls not found",
          affected_resource: "project:rls",
        },
      ),
    );
  }

  return { findings, error: errors.length ? errors.join("; ") : null };
}

export { redactSecret };
