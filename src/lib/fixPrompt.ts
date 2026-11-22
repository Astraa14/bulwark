import type { FindingRow } from "./workspace";

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
export function buildFixPrompt(finding: FindingRow, targetLabel: string): string {
  const lines: string[] = [
    `Fix this security finding detected by Bulwark (${sourceKind(finding)}):`,
    "",
    `Finding: ${finding.title}`,
    `Severity: ${finding.severity}`,
    `Target: ${targetLabel}`,
    `Check: ${finding.check_key}`,
  ];

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
    "2. Apply the smallest safe fix without weakening security controls or hardcoding any secrets.",
  );

  if (finding.platform === "supabase" || finding.check_key.includes("rls")) {
    lines.push(
      "3. Write an idempotent SQL migration for any RLS or policy changes, and verify access rules stay least-privilege.",
    );
  } else if (finding.platform === "github" && finding.check_key.startsWith("dep_")) {
    lines.push(
      "3. Update the affected dependency to a patched version, regenerate the lockfile, and verify tests/build still pass.",
    );
  } else if (
    finding.check_key.startsWith("secret_") ||
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
