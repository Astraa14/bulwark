export const WEBSITE_CHECK_LABELS = {
  site_uptime: "HTTPS reachability",
  http_status: "Homepage HTTP status",
  response_time: "Homepage response time",
  tls: "TLS certificate",
  security_headers: "Security headers",
  csp_policy: "Content Security Policy",
  cookies: "Cookie security flags",
  mixed_content: "Mixed content",
  directory_listing: "Directory listing",
  defacement: "Homepage integrity",
  exposed_files: "Exposed sensitive files",
  cors: "CORS configuration",
  public_discovery: "Public discovery files",
  secrets: "Client bundle & secret scan",
  api_exposure: "API & GraphQL exposure",
  domain_registration: "Domain expiry (RDAP)",
  dns: "DNS & email authentication",
};

const WEBSITE_EXACT_GROUPS = new Map([
  ["site_unreachable", "site_uptime"],
  ["http_5xx", "http_status"],
  ["http_4xx", "http_status"],
  ["slow_response", "response_time"],
  ["tls_unavailable", "tls"],
  ["tls_expired", "tls"],
  ["tls_expiring", "tls"],
  ["tls_expiring_soon", "tls"],
  ["header_hsts", "security_headers"],
  ["header_csp", "security_headers"],
  ["header_nosniff", "security_headers"],
  ["header_referrer", "security_headers"],
  ["server_banner", "security_headers"],
  ["hsts_short_max_age", "security_headers"],
  ["xfo_allowall", "security_headers"],
  ["csp_unsafe_inline", "csp_policy"],
  ["csp_unsafe_eval", "csp_policy"],
  ["csp_wildcard", "csp_policy"],
  ["csp_frame_ancestors_wildcard", "csp_policy"],
  ["cookie_flags", "cookies"],
  ["mixed_content", "mixed_content"],
  ["directory_listing", "directory_listing"],
  ["defacement_marker", "defacement"],
  ["content_replaced", "defacement"],
  ["exposed_env", "exposed_files"],
  ["exposed_env_local", "exposed_files"],
  ["exposed_git", "exposed_files"],
  ["exposed_ds_store", "exposed_files"],
  ["exposed_backup_sql", "exposed_files"],
  ["exposed_db_sql", "exposed_files"],
  ["exposed_phpinfo", "exposed_files"],
  ["cors_wildcard_credentials", "cors"],
  ["cors_reflects_origin", "cors"],
  ["cors_wildcard", "cors"],
  ["robots_missing", "public_discovery"],
  ["robots_sensitive_paths", "public_discovery"],
  ["sitemap_missing", "public_discovery"],
  ["sitemap_invalid", "public_discovery"],
  ["security_txt_missing", "public_discovery"],
  ["security_txt_invalid", "public_discovery"],
  ["stripe_test_key_in_production", "secrets"],
  ["site_supabase_anon_exposure", "secrets"],
  ["exposed_source_map", "secrets"],
  ["exposed_api_docs", "api_exposure"],
  ["graphql_introspection_enabled", "api_exposure"],
  ["domain_expired", "domain_registration"],
  ["domain_expiring", "domain_registration"],
  ["domain_expiring_soon", "domain_registration"],
  ["dns_no_ns", "dns"],
  ["dns_no_mx", "dns"],
  ["dns_no_spf", "dns"],
  ["dns_no_dmarc", "dns"],
  ["dns_dmarc_monitor_only", "dns"],
  ["dns_dangling_cname", "dns"],
]);

const GITHUB_CONFIG_CHECK_KEYS = new Set([
  "vercel_wildcard_cors_credentials",
  "vercel_missing_security_headers",
  "netlify_wildcard_cors_credentials",
  "dockerfile_runs_as_root",
  "dockerfile_secret_in_build_env",
  "workflow_pull_request_target",
  "workflow_write_all_permissions",
  "workflow_unpinned_third_party_action",
  "ai_route_without_auth",
  "webhook_missing_signature_verification",
  "ssrf_unvalidated_fetch",
  "jwt_decode_without_verify",
  "supabase_migration_missing_rls",
  "supabase_function_unverified_jwt",
  "gitignore_missing_env",
]);

const GITHUB_TREE_DEPENDENT_GROUPS = new Set([
  "secrets",
  "sensitive_files",
  "dependencies",
  "config_checks",
]);

export function websiteCheckGroupForFinding(checkKey) {
  const key = String(checkKey ?? "");
  if (WEBSITE_EXACT_GROUPS.has(key)) return WEBSITE_EXACT_GROUPS.get(key);
  if (key.startsWith("secret_")) return "secrets";
  return null;
}

export function platformCheckGroupForFinding(platform, checkKey) {
  const key = String(checkKey ?? "");
  if (platform === "supabase") {
    if (key === "supabase_anon_readable_table" || key === "supabase_anon_rpc_exposed") {
      return "anon_surface";
    }
    if (key === "supabase_public_storage") return "storage";
    if (
      key === "supabase_table_no_rls" ||
      key === "supabase_table_rls_no_policies" ||
      key === "supabase_table_permissive_policy" ||
      key === "supabase_rls_not_checked"
    ) {
      return "rls";
    }
    return null;
  }

  if (platform === "github") {
    if (key.startsWith("history_")) return "commit_history";
    if (key.startsWith("secret_") || key === "client_exposed_secret_env") return "secrets";
    if (key === "exposed_config_file") return "sensitive_files";
    if (key === "dep_unpinned" || key.startsWith("dep_vuln_")) return "dependencies";
    if (GITHUB_CONFIG_CHECK_KEYS.has(key)) return "config_checks";
    return null;
  }

  return null;
}

function isCompletedStatus(status, complete) {
  if (complete === false) return false;
  const norm = String(status ?? "")
    .trim()
    .toLowerCase();
  return norm === "pass" || norm === "passed" || norm === "finding" || norm === "findings";
}

export function completedCheckGroups({
  platform = "website",
  checkResults,
  coverage = null,
  findingsCount = 0,
}) {
  const completed = new Set();
  if (platform === "github" && findingsCount >= 250) {
    // Findings hit MAX_FINDINGS cap; unseen findings might simply have been truncated.
    return completed;
  }

  if (Array.isArray(checkResults)) {
    for (const item of checkResults) {
      if (!item || typeof item !== "object" || !item.key) continue;
      if (isCompletedStatus(item.status, item.complete)) {
        completed.add(String(item.key));
      }
    }
  } else if (checkResults && typeof checkResults === "object") {
    for (const [key, value] of Object.entries(checkResults)) {
      if (isCompletedStatus(value, undefined)) {
        completed.add(key);
      }
    }
  }

  if (platform === "github" && coverage?.scanTruncated) {
    for (const group of GITHUB_TREE_DEPENDENT_GROUPS) {
      completed.delete(group);
    }
  }

  return completed;
}

/**
 * When a scan finishes as `partial` because an unrelated check was skipped or
 * errored (for example, optional Supabase RLS SQL helper not installed, or
 * external RDAP timeout), resolve open findings belonging to check groups that
 * DID complete cleanly and no longer observed the finding.
 */
export async function resolvePartialScanFindings(
  db,
  {
    userId,
    siteId = null,
    platform = null,
    connectionId = null,
    resource = null,
    checkResults,
    coverage = null,
    findings = [],
  },
) {
  if (!userId) return 0;
  const kind = siteId ? "website" : platform;
  if (!kind) return 0;

  const completed = completedCheckGroups({
    platform: kind,
    checkResults,
    coverage,
    findingsCount: Array.isArray(findings) ? findings.length : 0,
  });
  if (completed.size === 0) return 0;

  const seen = new Set(
    (Array.isArray(findings) ? findings : []).map(
      (f) => `${f.check_key}\u0000${f.affected_resource ?? ""}`,
    ),
  );

  let query = db
    .from("findings")
    .select("id, check_key, affected_resource")
    .eq("user_id", userId)
    .eq("status", "open");

  if (siteId) {
    query = query.eq("site_id", siteId);
  } else {
    query = query
      .eq("platform", platform)
      .eq("connection_id", connectionId)
      .eq("resource", resource);
  }

  const { data: openRows, error } = await query;
  if (error) throw new Error(`load open findings for partial resolution: ${error.message}`);

  const idsToResolve = [];
  for (const row of openRows ?? []) {
    const group = siteId
      ? websiteCheckGroupForFinding(row.check_key)
      : platformCheckGroupForFinding(platform, row.check_key);
    if (!group || !completed.has(group)) continue;
    const identity = `${row.check_key}\u0000${row.affected_resource ?? ""}`;
    if (!seen.has(identity)) {
      idsToResolve.push(row.id);
    }
  }

  if (idsToResolve.length === 0) return 0;

  const { error: updateError } = await db
    .from("findings")
    .update({ status: "resolved" })
    .eq("user_id", userId)
    .in("id", idsToResolve);

  if (updateError) throw new Error(`resolve partial scan findings: ${updateError.message}`);
  return idsToResolve.length;
}
