import { findingImpactSummary, isShipBlocker } from "./scanOutcomes.ts";
import type { FindingRow, SiteStack } from "./workspace.ts";

const STACK_PROMPT_NAMES: Record<SiteStack, string> = {
  "nextjs-vercel": "Next.js on Vercel (next.config / vercel.json)",
  "vite-render": "Vite + Node on Render (vite.config / Express middleware)",
  cloudflare: "Cloudflare Pages / Workers (_headers / wrangler.toml)",
  nginx: "Nginx reverse proxy",
  express: "Node.js / Express",
  supabase: "Supabase backend (migrations + RLS policies)",
  other: "Custom web stack",
};

function sourceKind(finding: FindingRow): string {
  if (finding.platform === "github") return "GitHub repository scan";
  if (finding.platform === "supabase") return "Supabase project scan";
  return "External website scan";
}

/**
 * Formats a finding into a structured, safe prompt ready to paste into an AI
 * coding editor (Cursor, Claude Code, Windsurf, Antigravity). Never includes
 * raw credentials — only the already-redacted evidence stored on the finding.
 */
export function buildFixPrompt(
  finding: FindingRow,
  targetLabel: string,
  stack?: SiteStack | null,
): string {
  const lines: string[] = [
    `Fix this security finding detected by Bulwark (${sourceKind(finding)}):`,
    "",
    `Finding: ${finding.title}`,
    `Priority: ${isShipBlocker(finding) ? "Ship-blocker (fix before public launch)" : "Post-launch hardening"}`,
    `Severity: ${finding.severity}`,
    `Real-world risk: ${findingImpactSummary(finding)}`,
    `Target: ${targetLabel}`,
    `Check: ${finding.check_key}`,
  ];

  if (stack && STACK_PROMPT_NAMES[stack]) {
    lines.push(`Stack: ${STACK_PROMPT_NAMES[stack]}`);
  }
  if (finding.affected_resource) {
    lines.push(`Affected resource: ${finding.affected_resource}`);
  }
  if (finding.commit_sha) {
    lines.push(`Commit: ${finding.commit_sha.slice(0, 12)}`);
  }
  if (finding.url) {
    lines.push(`Reference URL: ${finding.url}`);
  }
  if (finding.detail) {
    lines.push("", "What Bulwark observed:", finding.detail);
  }
  if (finding.evidence) {
    lines.push("", "Evidence (redacted):", finding.evidence);
  }
  if (finding.what_it_does_not_prove) {
    lines.push("", "Important caveat:", finding.what_it_does_not_prove);
  }
  if (finding.remediation) {
    lines.push("", "Suggested remediation:", finding.remediation);
  }
  if (finding.explanation) {
    lines.push("", "Existing explanation:", finding.explanation);
  }

  lines.push(
    "",
    "Instructions:",
    "1. Inspect the relevant files or configuration in this workspace first to confirm the root cause.",
    stack && STACK_PROMPT_NAMES[stack]
      ? `2. Apply the smallest idiomatic fix for ${STACK_PROMPT_NAMES[stack]} without weakening security controls or hardcoding any secrets.`
      : "2. Apply the smallest safe fix without weakening security controls or hardcoding any secrets.",
  );

  if (finding.check_key === "ai_route_without_auth") {
    lines.push(
      "3. Require an authenticated session (e.g. `supabase.auth.getUser()` or `auth()`) and add per-user/IP rate limiting before calling the AI provider.",
    );
  } else if (finding.check_key === "webhook_missing_signature_verification") {
    lines.push(
      "3. Read the raw request body (`await req.text()`) and verify the webhook provider's cryptographic signature header (e.g. `stripe.webhooks.constructEvent`) before parsing JSON or updating database state.",
    );
  } else if (finding.check_key === "ssrf_unvalidated_fetch") {
    lines.push(
      "3. Validate the parsed `URL` protocol (`https:` only), allowlist expected hostnames (or resolve DNS and block loopback, RFC1918, CGNAT, and `169.254.0.0/16` metadata IPs), and re-validate every redirect hop.",
    );
  } else if (finding.check_key === "jwt_decode_without_verify") {
    lines.push(
      "3. Replace `jwt.decode` / `decodeJwt` with cryptographic signature verification (`jwt.verify`, `jose.jwtVerify`, or `supabase.auth.getUser`) before trusting any token claims.",
    );
  } else if (finding.check_key === "sql_raw_interpolation") {
    lines.push(
      "3. Replace string-interpolated raw SQL (`$queryRawUnsafe`, `sql.raw`, `f\"SELECT ...\"`) with parameterized query bindings so user input is never concatenated into SQL syntax.",
    );
  } else if (finding.check_key === "command_injection_exec") {
    lines.push(
      "3. Replace `exec` / `execSync` / `shell=True` with `execFile` or `spawn(binary, [arg1, arg2])` without a shell, and validate inputs against a strict allowlist.",
    );
  } else if (
    finding.check_key === "site_firebase_open_db" ||
    finding.check_key === "firestore_open_rules"
  ) {
    lines.push(
      "3. Lock down Firebase Security Rules (`firestore.rules` / Realtime Database rules) so reads and writes require `request.auth != null` and match the owning `request.auth.uid`.",
    );
  } else if (
    finding.check_key === "supabase_auth_autoconfirm_enabled" ||
    finding.check_key === "supabase_anonymous_auth_enabled"
  ) {
    lines.push(
      "3. Enable email confirmation (or disable unused Anonymous Sign-Ins) in Supabase Auth settings, and ensure RLS policies targeting `authenticated` restrict `(auth.jwt() ->> 'is_anonymous')::boolean` where appropriate.",
    );
  } else if (finding.check_key === "dns_dangling_cname") {
    lines.push(
      "3. Remove the dangling DNS `CNAME` record in your DNS provider immediately (or bind the subdomain to your active hosting project) so an attacker cannot claim the target resource.",
    );
  } else if (finding.check_key === "supabase_function_unverified_jwt") {
    lines.push(
      "3. Re-enable `verify_jwt = true` in `supabase/config.toml` (or verify `Authorization` / webhook HMAC signatures inside the function) before calling `SUPABASE_SERVICE_ROLE_KEY`.",
    );
  } else if (finding.check_key === "stripe_test_key_in_production") {
    lines.push(
      "3. Ensure production environment config uses `pk_live_...` for the client publishable key while keeping `sk_live_...` server-only.",
    );
  } else if (finding.check_key === "gitignore_missing_env") {
    lines.push(
      "3. Add `.env` and `.env*.local` (keeping `!.env.example` if needed) to `.gitignore` and verify no `.env` files are currently tracked.",
    );
  } else if (
    finding.platform === "supabase" ||
    finding.check_key.includes("rls") ||
    finding.check_key === "site_supabase_anon_exposure"
  ) {
    lines.push(
      "3. Write an idempotent SQL migration enabling RLS, scoping SELECT/INSERT/UPDATE/DELETE policies to `auth.uid()`, and revoking `public`/`anon` execute grants on internal RPCs.",
    );
  } else if (finding.platform === "github" && finding.check_key.startsWith("dep_")) {
    lines.push(
      "3. Update the affected dependency to a patched version, regenerate the lockfile, and verify tests/build still pass.",
    );
  } else if (
    finding.check_key.startsWith("secret_") ||
    finding.check_key.startsWith("history_secret_") ||
    finding.check_key === "client_exposed_secret_env" ||
    finding.check_key === "exposed_config_file"
  ) {
    lines.push(
      "3. Move the credential to a server-only environment variable (no NEXT_PUBLIC_/VITE_ prefix), update references, and remind me to rotate the exposed key.",
    );
  } else {
    lines.push(
      "3. Explain the exact change made and verify it with the project's test suite or build.",
    );
  }

  return lines.join("\n");
}
