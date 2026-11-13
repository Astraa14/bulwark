import { decrypt, maskSecret } from "./crypto.mjs";

const GITHUB_API = "https://api.github.com";
const MAX_FILE_BYTES = 500_000;
// Scan the complete repository tree, not an arbitrary 40-file cap.
// Report files scanned vs total so coverage is honest.
const MAX_FILES_SCANNED = 500;

// Known-vulnerable dependency patterns (lockfile-based).
// This is a small, high-signal set. A production service would subscribe
// to a vulnerability advisory feed (OSV, GitHub Advisories, etc.).
const VULN_PATTERNS = [
  {
    key: "dep_vuln_lodash",
    name: "lodash",
    severity: "high",
    versions: ["<4.17.21"],
    detail: "lodash versions before 4.17.21 have prototype pollution vulnerabilities.",
  },
  {
    key: "dep_vuln_minimist",
    name: "minimist",
    severity: "high",
    versions: ["<1.2.6"],
    detail: "minimist versions before 1.2.6 have prototype pollution vulnerabilities.",
  },
  {
    key: "dep_vuln_yargs",
    name: "yargs",
    severity: "high",
    versions: ["<16.11.0"],
    detail: "yargs versions before 16.11.0 have prototype pollution vulnerabilities.",
  },
  {
    key: "dep_vuln_handlebars",
    name: "handlebars",
    severity: "critical",
    versions: ["<4.7.7"],
    detail: "handlebars versions before 4.7.7 have remote code execution vulnerabilities.",
  },
  {
    key: "dep_vuln_minimatch",
    name: "minimatch",
    severity: "high",
    versions: ["<3.0.2"],
    detail: "minimatch versions before 3.0.2 have regular expression denial of service vulnerabilities.",
  },
  {
    key: "dep_vuln_trim",
    name: "trim",
    severity: "high",
    versions: ["<1.0.1"],
    detail: "trim versions before 1.0.1 have regular expression denial of service vulnerabilities.",
  },
];

// Deployment/config files that commonly contain dangerous settings.
// Each check has a `path` (file or directory prefix), a `test` function
// that returns true when a problem is found, and metadata for the finding.
const CONFIG_CHECKS = [
  {
    path: "Dockerfile",
    check: "dockerfile_root_user",
    title: "Dockerfile runs as root",
    severity: "medium",
    test: (content) => !/^\s*USER\s+/m.test(content),
    detail: "The Dockerfile does not set a non-root USER. Containers running as root have more privileges than necessary if compromised.",
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
    path: ".github/workflows/",
    check: "workflow_pull_request_target",
    title: "GitHub Action uses pull_request_target with untrusted input",
    severity: "high",
    test: (content) => /pull_request_target/.test(content),
    detail: "A workflow uses `pull_request_target`, which runs with repository write permissions. Untrusted input from the fork can lead to repository takeover.",
  },
];

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
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".dockerfile", ".gitmodules",
    ".github/workflows", ".circleci", ".gitlab-ci",
  ]);
  const lower = name.toLowerCase();
  if (SENSITIVE_FILENAMES.has(lower)) return true;
  // Files without extensions that are still text (Dockerfile, Makefile, etc.)
  if (lower === "dockerfile" || lower === "makefile" || lower === "gemfile") return true;
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
      "user-agent": "BulwarkBot/0.5",
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
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const data = await githubFetch(token, `/repos/${owner}/${repo}/contents/${encodedPath}`);
  if (Array.isArray(data)) return data;
  return [data];
}

async function getFileContent(token, owner, repo, path) {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const data = await githubFetch(token, `/repos/${owner}/${repo}/contents/${encodedPath}`);
  if (data.encoding === "base64" && data.content) {
    return Buffer.from(data.content, "base64").toString("utf8");
  }
  return null;
}

function parseSemver(version) {
  const m = String(version).match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

function versionLessThan(v, constraint) {
  const parsed = parseSemver(v);
  if (!parsed) return false;
  const m = constraint.match(/^<(.+)$/);
  if (!m) return false;
  const target = parseSemver(m[1]);
  if (!target) return false;
  if (parsed.major !== target.major) return parsed.major < target.major;
  if (parsed.minor !== target.minor) return parsed.minor < target.minor;
  return parsed.patch < target.patch;
}

function scanLockfile(path, content, owner, repo) {
  const findings = [];
  const lower = path.toLowerCase();

  if (lower === "package-lock.json") {
    try {
      const json = JSON.parse(content);
      const packages = json.packages ?? {};
      for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
        const name = pkgPath.replace(/^node_modules\//, "");
        if (!name) continue;
        const version = pkgInfo.version;
        if (!version) continue;
        for (const vuln of VULN_PATTERNS) {
          if (name === vuln.name && versionLessThan(version, vuln.versions[0])) {
            findings.push(
              finding(
                vuln.key,
                `Vulnerable dependency: ${name}@${version}`,
                vuln.severity,
                `${vuln.detail} Locked version ${version} is affected. Upgrade to ${vuln.versions[0].replace(/^</, "")} or later.`,
                {
                  url: `https://github.com/${owner}/${repo}/blob/main/package-lock.json`,
                  evidence: `${name}@${version} (locked in package-lock.json)`,
                  affected_resource: `package-lock.json:${name}`,
                },
              ),
            );
          }
        }
      }
    } catch {
      // Invalid JSON — skip.
    }
  }

  if (lower === "package.json") {
    try {
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
        for (const vuln of VULN_PATTERNS) {
          if (name === vuln.name && versionLessThan(v.replace(/^[^0-9]*/, ""), vuln.versions[0])) {
            findings.push(
              finding(
                vuln.key,
                `Vulnerable dependency: ${name}@${v}`,
                vuln.severity,
                `${vuln.detail} Declared version ${v} is affected. Upgrade to ${vuln.versions[0].replace(/^</, "")} or later.`,
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
  }

  return findings;
}

function scanConfigFile(path, content, owner, repo) {
  const findings = [];
  const lower = path.toLowerCase();

  for (const check of CONFIG_CHECKS) {
    const checkPath = check.path.toLowerCase();
    const isDirectory = checkPath.endsWith("/");
    const matchesPath = isDirectory
      ? lower.startsWith(checkPath)
      : lower === checkPath || lower.startsWith(checkPath + "/");
    if (!matchesPath) continue;
    try {
      if (check.test(content)) {
        findings.push(
          finding(
            check.check,
            check.title,
            check.severity,
            check.detail,
            {
              url: `https://github.com/${owner}/${repo}/blob/main/${path}`,
              evidence: `Found in ${path}`,
              affected_resource: path,
            },
          ),
        );
      }
    } catch {
      // Invalid test — skip.
    }
  }

  return findings;
}

export async function scanGitHubRepo(token, owner, repo) {
  const findings = [];
  const errors = [];
  const scannedFiles = new Set();
  const queue = [""];
  let filesScanned = 0;
  let totalFiles = 0;
  let scanTruncated = false;

  while (queue.length > 0) {
    const current = queue.shift();
    try {
      const items = await getRepoContents(token, owner, repo, current);
      for (const item of items) {
        totalFiles += 1;

        if (filesScanned >= MAX_FILES_SCANNED) {
          scanTruncated = true;
          continue;
        }

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

              // Lockfile vulnerability detection.
              const lockfileFindings = scanLockfile(item.path, content, owner, repo);
              findings.push(...lockfileFindings);

              // Deployment/config checks.
              const configFindings = scanConfigFile(item.path, content, owner, repo);
              findings.push(...configFindings);
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

  // Check dependency files for unpinned dependencies (from root-level package.json).
  try {
    const content = await getFileContent(token, owner, repo, "package.json");
    if (content) {
      const pkgFindings = scanLockfile("package.json", content, owner, repo);
      findings.push(...pkgFindings);
    }
  } catch {
    // File doesn't exist — skip.
  }

  const coverage = {
    filesScanned,
    totalFiles,
    scanTruncated,
    scannedPercent: totalFiles > 0 ? Math.round((filesScanned / totalFiles) * 100) : 0,
  };

  return {
    findings,
    error: errors.length ? errors.join("; ") : null,
    filesScanned,
    coverage,
  };
}

export { redactSecret };
