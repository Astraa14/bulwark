// Static configuration for GitHub repository scanning.
//
// Dependency vulnerability detection is NOT configured here. It is queried
// from OSV at scan time so the rules cannot go stale. Supported lockfiles:
// npm (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) and Python
// (`requirements.txt`, `poetry.lock`, `uv.lock`). Other lockfiles are counted
// as unanalyzed so coverage remains explicit.

export const GITHUB_API = "https://api.github.com";
export const OSV_API = "https://api.osv.dev/v1/querybatch";

export const MAX_FILE_BYTES = 500_000;
export const MAX_LOCKFILE_BYTES = 3_000_000;
export const MAX_FILES_SCANNED = 500;
export const MAX_HISTORY_COMMITS = 10;
export const MAX_SECRET_MATCHES_PER_PATTERN_PER_FILE = 20;
export const MAX_FINDINGS = 1_000;
export const GITHUB_FETCH_CONCURRENCY = 6;
export const GITHUB_REQUEST_TIMEOUT_MS = 20_000;

export const CONFIG_CHECKS = [
  {
    path: "Dockerfile",
    check: "dockerfile_root_user",
    title: "Dockerfile runs as root",
    severity: "medium",
    test: (content) => !/^\s*USER\s+/m.test(content),
    detail:
      "The Dockerfile does not set a non-root USER. Containers running as root have more privileges than necessary if compromised.",
    remediation: "Add a non-root USER directive to the image or service.",
  },
  {
    path: "docker-compose.yml",
    check: "compose_root_user",
    title: "Docker Compose service runs as root",
    severity: "medium",
    test: (content) => !/^\s*user:\s*[^0\s]/m.test(content),
    detail: "A Docker Compose service does not set a non-root user.",
    remediation: "Add a non-root user setting to each service in Docker Compose.",
  },
  {
    path: "docker-compose.yaml",
    check: "compose_root_user",
    title: "Docker Compose service runs as root",
    severity: "medium",
    test: (content) => !/^\s*user:\s*[^0\s]/m.test(content),
    detail: "A Docker Compose service does not set a non-root user.",
    remediation: "Add a non-root user setting to each service in Docker Compose.",
  },
  {
    path: ".github/workflows/",
    check: "workflow_pull_request_target",
    title: "GitHub Action uses pull_request_target",
    severity: "high",
    test: (content) =>
      /pull_request_target/.test(content) &&
      /github\.event\.pull_request\.(head|title|body)|github\.head_ref|refs\/pull\/[^\s]+\/merge/.test(
        content,
      ),
    detail:
      "A workflow runs on `pull_request_target` and also references untrusted pull-request content. That combination can expose repository write permissions. Prefer `pull_request`, or never run untrusted code in this workflow.",
    remediation: "Remove untrusted pull-request input from pull_request_target workflows.",
  },
  {
    path: ".github/workflows/",
    check: "workflow_write_all_permissions",
    title: "GitHub Action grants write-all permissions",
    severity: "high",
    test: (content) => /^\s*permissions:\s*write-all\b/m.test(content),
    detail:
      "This workflow sets `permissions: write-all`, granting the GITHUB_TOKEN broad write access across repository contents, packages, and actions.",
    remediation:
      "Replace `permissions: write-all` with least-privilege scopes such as `permissions: { contents: read }`.",
  },
  {
    path: ".github/workflows/",
    check: "workflow_unpinned_action",
    title: "GitHub Action pinned to a mutable branch",
    severity: "medium",
    test: (content) =>
      /^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@(?:main|master|latest|dev|develop)\b/m.test(
        content,
      ),
    detail:
      "This workflow runs a GitHub Action referenced by a mutable branch (`@main`/`@master`/`@latest`). Upstream changes or a compromised repo can execute arbitrary code in CI.",
    remediation:
      "Pin the action to a full 40-character commit SHA (or at minimum a version tag).",
  },
  {
    path: "vercel.json",
    check: "vercel_wildcard_cors_credentials",
    title: "Vercel config pairs wildcard CORS with credentials",
    severity: "high",
    test: (content) => {
      try {
        const parsed = JSON.parse(content);
        const rules = Array.isArray(parsed?.headers) ? parsed.headers : [];
        for (const rule of rules) {
          const entries = Array.isArray(rule?.headers) ? rule.headers : [];
          let wildcardOrigin = false;
          let allowCredentials = false;
          for (const entry of entries) {
            const key = String(entry?.key ?? "").trim().toLowerCase();
            const val = String(entry?.value ?? "").trim().toLowerCase();
            if (key === "access-control-allow-origin" && val === "*") wildcardOrigin = true;
            if (key === "access-control-allow-credentials" && val === "true") {
              allowCredentials = true;
            }
          }
          if (wildcardOrigin && allowCredentials) return true;
        }
      } catch {
        // Fall through to textual heuristic for JSONC/non-strict configs.
      }
      return (
        /Access-Control-Allow-Origin["']?\s*:\s*["']\*["']/i.test(content) &&
        /Access-Control-Allow-Credentials["']?\s*:\s*["']true["']/i.test(content)
      );
    },
    detail:
      "vercel.json sets Access-Control-Allow-Origin to `*` alongside Access-Control-Allow-Credentials: true. Explicitly allow only trusted origins instead of a wildcard.",
    remediation:
      "Replace the `*` origin with your exact frontend origin(s), or remove Access-Control-Allow-Credentials if the route is public.",
  },
  {
    path: "firestore.rules",
    check: "firestore_open_rules",
    title: "Firestore security rules allow unauthenticated public writes (`if true`)",
    severity: "critical",
    test: (content) =>
      /\ballow\s+[^;]*\b(?:write|create|update|delete)\b[^;]*:\s*if\s+true\b/.test(
        String(content ?? "").replace(/\/\/.*$/gm, ""),
      ),
    detail:
      "`firestore.rules` permits unauthenticated write access (`allow write: if true` — Firebase Test Mode). Any visitor on the internet can overwrite, delete, or inject arbitrary documents into your production database.",
    remediation:
      "Replace `if true` with authenticated owner checks such as `if request.auth != null && request.auth.uid == userId`.",
  },
  {
    path: "storage.rules",
    check: "firestore_open_rules",
    title: "Firebase Storage rules allow unauthenticated public writes (`if true`)",
    severity: "critical",
    test: (content) =>
      /\ballow\s+[^;]*\b(?:write|create|update|delete)\b[^;]*:\s*if\s+true\b/.test(
        String(content ?? "").replace(/\/\/.*$/gm, ""),
      ),
    detail:
      "`storage.rules` permits unauthenticated file writes (`allow write: if true`), allowing anyone to overwrite hosted files or upload malicious payloads into your Firebase bucket.",
    remediation:
      "Require `request.auth != null` and restrict upload paths, file sizes, and content types.",
  },
];

/**
 * Frontend build tools inline env variables starting with these prefixes into
 * the public JavaScript bundle sent to every visitor's browser.
 */
export const CLIENT_EXPOSED_ENV_PREFIXES = [
  "NEXT_PUBLIC_",
  "VITE_",
  "REACT_APP_",
  "NUXT_PUBLIC_",
  "PUBLIC_",
];

/**
 * Env variable suffixes that are intentionally safe in browsers and should
 * never be flagged by the client-exposed secret heuristic.
 */
export const SAFE_CLIENT_ENV_SUFFIX_RE =
  /(?:^|_)(?:ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY|SITE_KEY|CLIENT_ID|APP_ID|PROJECT_ID|MEASUREMENT_ID|DSN|GA_ID)$/;

/**
 * Variable name fragments that represent server-only secrets or privileged
 * credentials. Order matters: first match determines severity.
 */
export const DANGEROUS_CLIENT_ENV_PATTERNS = [
  {
    re: /(?:^|_)(?:SERVICE_ROLE(?:_KEY)?|SUPABASE_SECRET(?:_KEY)?)$/,
    severity: "critical",
    label: "Supabase service-role / secret key",
  },
  {
    re: /(?:^|_)(?:PRIVATE_KEY|PEM_KEY|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY)$/,
    severity: "critical",
    label: "private or encryption key",
  },
  {
    re: /(?:^|_)(?:DATABASE_URL|POSTGRES_URL|POSTGRES_PRISMA_URL|MYSQL_URL|MONGO(?:DB)?_URI|REDIS_URL|DB_PASS(?:WORD)?)$/,
    severity: "critical",
    label: "database connection string or password",
  },
  {
    re: /(?:^|_)(?:STRIPE_SECRET(?:_KEY)?|STRIPE_WEBHOOK_SECRET|AWS_SECRET(?:_ACCESS_KEY)?|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_AI_API_KEY|RESEND_API_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|CLERK_SECRET_KEY|GITHUB_TOKEN|GH_TOKEN|OPENAI_KEY|ANTHROPIC_KEY)$/,
    severity: "critical",
    label: "server-only provider secret",
  },
  {
    re: /(?:^|_)(?:API_SECRET|CLIENT_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|JWT_SECRET|SESSION_SECRET|WEBHOOK_SECRET|SECRET_KEY|SECRET_TOKEN|ACCESS_TOKEN|ADMIN_TOKEN|ADMIN_PASSWORD|SMTP_PASS(?:WORD)?)$/,
    severity: "high",
    label: "server-only secret or token",
  },
];

export const SECRET_PATTERNS = [
  {
    key: "secret_openai",
    name: "OpenAI API key",
    severity: "critical",
    re: /\bsk-(?:proj-|svcacct-|live-)?[A-Za-z0-9_-]{32,}\b/g,
  },
  {
    key: "secret_anthropic",
    name: "Anthropic API key",
    severity: "critical",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    key: "secret_google",
    name: "Google API key",
    severity: "high",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    key: "secret_github",
    name: "GitHub token",
    severity: "critical",
    re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  },
  {
    key: "secret_aws",
    name: "AWS access key id",
    severity: "critical",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    key: "secret_stripe",
    name: "Stripe live secret key",
    severity: "critical",
    re: /\bsk_live_[0-9A-Za-z]{20,}\b/g,
  },
  {
    key: "secret_stripe_restricted",
    name: "Stripe live restricted key",
    severity: "critical",
    re: /\brk_live_[0-9A-Za-z]{20,}\b/g,
  },
  {
    key: "secret_supabase_secret_key",
    name: "Supabase secret key",
    severity: "critical",
    re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    key: "secret_groq",
    name: "Groq API key",
    severity: "critical",
    re: /\bgsk_[A-Za-z0-9]{40,}\b/g,
  },
  {
    key: "secret_huggingface",
    name: "Hugging Face access token",
    severity: "high",
    re: /\bhf_[A-Za-z0-9]{30,}\b/g,
  },
  {
    key: "secret_resend",
    name: "Resend API key",
    severity: "high",
    re: /\bre_(?=[A-Za-z0-9_]{24,}\b)(?=[A-Za-z0-9_]*[A-Z])(?=[A-Za-z0-9_]*\d)[A-Za-z0-9]{6,12}_?[A-Za-z0-9]{16,}\b/g,
  },
  {
    key: "secret_sendgrid",
    name: "SendGrid API key",
    severity: "critical",
    re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b/g,
  },
  {
    key: "secret_linear",
    name: "Linear API key",
    severity: "high",
    re: /\blin_api_[A-Za-z0-9]{32,}\b/g,
  },
  {
    key: "secret_database_url",
    name: "Database connection string with credentials",
    severity: "critical",
    re: /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|rediss):\/\/(?!(?:user|username|postgres|root|admin|your[_-]?user|\$\{[^}]+\}|<[^>]+>):(?:pass|password|secret|postgres|root|admin|xxxx+|\*+|your[_-]?password|\$\{[^}]+\}|<[^>]+>)@)[^:\s/"'<>]{1,64}:[^@\s/"'<>]{6,128}@(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|host\b|example\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
  },
  {
    key: "secret_slack",
    name: "Slack token",
    severity: "critical",
    re: /\bxox[baprs]-[0-9A-Za-z-]{12,}\b/g,
  },
  {
    key: "secret_private_key",
    name: "Private key block",
    severity: "critical",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    key: "secret_generic_password",
    name: "Possible hardcoded password",
    severity: "medium",
    re: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
  },
  {
    key: "secret_generic_api_key",
    name: "Possible hardcoded API key",
    severity: "high",
    re: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/gi,
  },
];

// Template files like .env.example and .env.sample are intentionally excluded
// here so clean repos with tracked env templates are not flagged by filename
// alone; their contents are still scanned for real credentials and dangerous
// client-exposed env variable names.
export const SENSITIVE_FILENAMES = new Set([
  ".env",
  ".env.local",
  ".env.development",
  ".env.production",
  "config.json",
  "config.yaml",
  "config.yml",
  "settings.json",
  "secrets.json",
  "credentials.json",
  "service-account.json",
  "id_rsa",
  "id_ecdsa",
  "id_ed25519",
  "id_dsa",
  ".netrc",
  ".pgpass",
  ".my.cnf",
]);

export const ANALYZED_LOCKFILES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "poetry.lock",
  "uv.lock",
]);

export const UNANALYZED_LOCKFILES = new Set([
  "gemfile.lock",
  "cargo.lock",
  "go.sum",
  "composer.lock",
  "podfile.lock",
  "pipfile.lock",
  "bun.lock",
]);

export const DEPENDENCY_FILES = new Set([
  "package.json",
  ...ANALYZED_LOCKFILES,
  ...UNANALYZED_LOCKFILES,
]);

export const TEXT_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
  ".svelte",
  ".vue",
  ".astro",
  ".py",
  ".go",
  ".rs",
  ".java",
  ".rb",
  ".php",
  ".cs",
  ".cpp",
  ".c",
  ".h",
  ".hpp",
  ".swift",
  ".kt",
  ".scala",
  ".clj",
  ".ex",
  ".exs",
  ".erl",
  ".hs",
  ".ml",
  ".fs",
  ".vb",
  ".fsproj",
  ".csproj",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".lock",
  ".sql",
  ".prisma",
  ".xml",
  ".ini",
  ".cfg",
  ".conf",
  ".md",
  ".txt",
  ".env",
  ".gitignore",
  ".dockerignore",
  ".sh",
  ".bash",
  ".zsh",
  ".fish",
  ".ps1",
  ".bat",
  ".cmd",
  ".dockerfile",
  ".gitmodules",
  ".rules",
]);
