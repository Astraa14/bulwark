import { decrypt, maskSecret } from "./crypto.mjs";

const GITHUB_API = "https://api.github.com";
const MAX_FILE_BYTES = 200_000;
const MAX_FILES_SCANNED = 40;

// Same secret patterns as the external scanner, applied to repo file contents.
const SECRET_PATTERNS = [
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

const SENSITIVE_FILENAMES = new Set([
  ".env", ".env.local", ".env.development", ".env.production", ".env.example",
  ".env.sample", "config.json", "config.yaml", "config.yml", "settings.json",
  "secrets.json", "credentials.json", "service-account.json", "id_rsa", "id_ecdsa",
  "id_ed25519", "id_dsa", ".netrc", ".pgpass", ".my.cnf",
]);

const DEPENDENCY_FILES = new Set([
  "package.json", "package-lock.json", "requirements.txt", "Pipfile", "Pipfile.lock",
  "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
  "composer.json", "composer.lock", "pom.xml", "build.gradle", "build.gradle.kts",
]);

function finding(check_key, title, severity, detail, extra = {}) {
  return { check_key, title, severity, detail, ...extra };
}

function redactSecret(value) {
  const s = String(value);
  if (s.length <= 10) return "••••";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function scanTextForSecrets(text, path) {
  const out = [];
  if (!text) return out;
  for (const pattern of SECRET_PATTERNS) {
    pattern.re.lastIndex = 0;
    const match = pattern.re.exec(text);
    if (!match) continue;
    out.push(
      finding(
        pattern.key,
        `${pattern.name} in ${path}`,
        pattern.severity,
        "A secret is committed to the repository. Anyone with read access can use it. Rotate it and remove it from git history.",
        {
          url: `https://github.com/${encodeURIComponent(path)}`,
          evidence: `${redactSecret(match[0])} · found in ${path}`,
          affected_resource: path,
        },
      ),
    );
  }
  return out;
}

function isTextFile(name) {
  const textExts = new Set([
    ".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rs", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".kt", ".scala", ".clj",
    ".ex", ".exs", ".erl", ".hs", ".ml", ".fs", ".vb", ".fsproj", ".csproj",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf",
    ".md", ".txt", ".env", ".gitignore", ".dockerignore", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".Dockerfile", ".gitmodules",
    ".github/workflows", ".circleci", ".gitlab-ci",
  ]);
  const lower = name.toLowerCase();
  if (SENSITIVE_FILENAMES.has(lower)) return true;
  const dot = lower.lastIndexOf(".");
  if (dot === -1) return false;
  return textExts.has(lower.slice(dot)) || lower.endsWith("dockerfile") || lower.endsWith("makefile");
}

async function githubFetch(token, path, opts = {}) {
  const { timeout = 15000 } = opts;
  const url = `${GITHUB_API}${path}`;
  const res = await fetch(url, {
    headers: {
      authorization: `Bearer ${token}`,
      "user-agent": "BulwarkBot/0.4",
      accept: "application/vnd.github+json",
    },
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

async function getRepoContents(token, owner, repo, path = "") {
  const data = await githubFetch(token, `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`);
  if (Array.isArray(data)) return data;
  return [data];
}

async function getFileContent(token, owner, repo, path) {
  const data = await githubFetch(token, `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`);
  if (data.encoding === "base64" && data.content) {
    return Buffer.from(data.content, "base64").toString("utf8");
  }
  return null;
}

export async function scanGitHubRepo(token, owner, repo) {
  const findings = [];
  const errors = [];
  const scannedFiles = new Set();
  const queue = [""];
  let filesScanned = 0;

  while (queue.length > 0 && filesScanned < MAX_FILES_SCANNED) {
    const current = queue.shift();
    try {
      const items = await getRepoContents(token, owner, repo, current);
      for (const item of items) {
        if (filesScanned >= MAX_FILES_SCANNED) break;

        if (item.type === "dir") {
          queue.push(item.path);
        } else if (item.type === "file") {
          if (scannedFiles.has(item.path)) continue;
          scannedFiles.add(item.path);
          filesScanned += 1;

          const lower = item.path.toLowerCase();

          // Skip binary and very large files.
          if (item.size > MAX_FILE_BYTES) continue;
          if (!isTextFile(item.path)) continue;

          // Check sensitive filenames.
          if (SENSITIVE_FILENAMES.has(lower)) {
            findings.push(
              finding(
                "exposed_config_file",
                `Sensitive file committed: ${item.path}`,
                "high",
                "A potentially sensitive configuration or credential file is committed to the repository. Move secrets out of git and into environment variables or a secrets manager.",
                {
                  url: `https://github.com/${owner}/${repo}/blob/main/${item.path}`,
                  evidence: `${item.size} bytes`,
                  affected_resource: item.path,
                },
              ),
            );
          }

          // Fetch and scan file content.
          try {
            const content = await getFileContent(token, owner, repo, item.path);
            if (content) {
              const secretFindings = scanTextForSecrets(content, item.path);
              findings.push(...secretFindings);
            }
          } catch (err) {
            errors.push(`${item.path}: ${err?.message ?? String(err)}`);
          }
        }
      }
    } catch (err) {
      errors.push(`${current || "(root)"}: ${err?.message ?? String(err)}`);
    }
  }

  // Check dependency files for known issues.
  for (const depFile of DEPENDENCY_FILES) {
    try {
      const content = await getFileContent(token, owner, repo, depFile);
      if (content) {
        const depFindings = scanDependencyFile(depFile, content, owner, repo);
        findings.push(...depFindings);
      }
    } catch {
      // File doesn't exist or can't be read — skip.
    }
  }

  return { findings, error: errors.length ? errors.join("; ") : null, filesScanned };
}

function scanDependencyFile(path, content, owner, repo) {
  const findings = [];
  const lower = path.toLowerCase();

  try {
    if (lower === "package.json") {
      const json = JSON.parse(content);
      const deps = { ...json.dependencies, ...json.devDependencies };
      for (const [name, version] of Object.entries(deps)) {
        const v = String(version);
        if (v.includes("*") || v === "latest") {
          findings.push(
            finding(
              "dep_unpinned",
              `Unpinned dependency: ${name}`,
              "medium",
              `Dependency ${name} uses an unpinned version (${v}), which can introduce breaking or malicious updates.`,
              {
                url: `https://github.com/${owner}/${repo}/blob/main/package.json`,
                evidence: `${name}@${v}`,
                affected_resource: `package.json:${name}`,
              },
            ),
          );
        }
      }
    }
  } catch {
    // Invalid JSON — skip.
  }

  return findings;
}

export { redactSecret };
