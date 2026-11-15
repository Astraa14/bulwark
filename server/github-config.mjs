// Static configuration for GitHub repository scanning.
//
// Dependency vulnerability detection is NOT configured here. It is queried
// from OSV at scan time so the rules cannot go stale. Only npm lockfiles
// are currently analyzed; other ecosystems are not supported.

export const GITHUB_API = "https://api.github.com";
export const OSV_API = "https://api.osv.dev/v1/querybatch";

export const MAX_FILE_BYTES = 500_000;
export const MAX_FILES_SCANNED = 500;
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
  },
  {
    path: "docker-compose.yml",
    check: "compose_root_user",
    title: "Docker Compose service runs as root",
    severity: "medium",
    test: (content) => !/^\s*user:\s*[^0\s]/m.test(content),
    detail: "A Docker Compose service does not set a non-root user.",
  },
  {
    path: "docker-compose.yaml",
    check: "compose_root_user",
    title: "Docker Compose service runs as root",
    severity: "medium",
    test: (content) => !/^\s*user:\s*[^0\s]/m.test(content),
    detail: "A Docker Compose service does not set a non-root user.",
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

export const SENSITIVE_FILENAMES = new Set([
  ".env",
  ".env.local",
  ".env.development",
  ".env.production",
  ".env.example",
  ".env.sample",
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

export const DEPENDENCY_FILES = new Set([
  "package.json",
  "package-lock.json",
]);

export const TEXT_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
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
]);
