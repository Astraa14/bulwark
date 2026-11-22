import {
  ANALYZED_LOCKFILES,
  CLIENT_EXPOSED_ENV_PREFIXES,
  CONFIG_CHECKS,
  DANGEROUS_CLIENT_ENV_PATTERNS,
  GITHUB_API,
  GITHUB_FETCH_CONCURRENCY,
  GITHUB_REQUEST_TIMEOUT_MS,
  MAX_FILES_SCANNED,
  MAX_FILE_BYTES,
  MAX_FINDINGS,
  MAX_HISTORY_COMMITS,
  MAX_SECRET_MATCHES_PER_PATTERN_PER_FILE,
  OSV_API,
  SAFE_CLIENT_ENV_SUFFIX_RE,
  SECRET_PATTERNS,
  SENSITIVE_FILENAMES,
  TEXT_EXTENSIONS,
  UNANALYZED_LOCKFILES,
} from "./github-config.mjs";

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const EXACT_VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const PEP440_EXACT_RE = /^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev|post|dev)\d+)?(?:\+[0-9A-Za-z.]+)?$/i;
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CLIENT_ENV_RE = new RegExp(
  `\\b((?:${CLIENT_EXPOSED_ENV_PREFIXES.join("|")})[A-Z0-9_]{2,80})\\b`,
  "g",
);

function finding(checkKey, title, severity, detail, extra = {}) {
  return { check_key: checkKey, title, severity, detail, ...extra };
}

function redactSecret(value) {
  const s = String(value);
  if (s.length <= 10) return "••••";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

export function assertRepoCoordinates(owner, repo) {
  if (!OWNER_RE.test(String(owner ?? ""))) throw new Error("Invalid GitHub repository owner.");
  if (!REPO_RE.test(String(repo ?? ""))) throw new Error("Invalid GitHub repository name.");
}

function isTextFile(filePath) {
  const lower = String(filePath ?? "").toLowerCase();
  const base = lower.slice(lower.lastIndexOf("/") + 1);
  if (SENSITIVE_FILENAMES.has(base)) return true;
  if (ANALYZED_LOCKFILES.has(base) || UNANALYZED_LOCKFILES.has(base)) return true;
  if (base === "dockerfile" || base === "makefile" || base === "gemfile") return true;
  const dot = base.lastIndexOf(".");
  if (dot === -1) return false;
  return TEXT_EXTENSIONS.has(base.slice(dot));
}

const MAX_GITHUB_RESPONSE_BYTES = 8_000_000;

/** Reads a response body with a hard byte cap, then parses it as JSON. */
async function readJsonBounded(res, maxBytes) {
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(`GitHub response exceeds the ${maxBytes} byte limit.`);
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // Already released after cancel.
      }
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }

  const text = await res.text();
  if (Buffer.byteLength(text) > maxBytes) {
    throw new Error(`GitHub response exceeds the ${maxBytes} byte limit.`);
  }
  return JSON.parse(text);
}

async function githubFetch(
  token,
  path,
  { fetchImpl = fetch, timeout = GITHUB_REQUEST_TIMEOUT_MS, maxBytes = MAX_GITHUB_RESPONSE_BYTES } = {},
) {
  const res = await fetchImpl(`${GITHUB_API}${path}`, {
    headers: {
      authorization: `Bearer ${token}`,
      "user-agent": "BulwarkBot/0.7",
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
    },
    redirect: "manual",
    signal: AbortSignal.timeout(timeout),
  });

  if (res.status >= 300 && res.status < 400) {
    throw new Error("GitHub API redirected the request, so it was not followed.");
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const err = new Error(`GitHub API ${res.status}${body ? `: ${body.slice(0, 200)}` : ""}`);
    err.status = res.status;
    throw err;
  }

  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`GitHub response exceeds the ${maxBytes} byte limit.`);
  }

  return readJsonBounded(res, maxBytes);
}

export async function listGitHubRepos(token, { fetchImpl = fetch, maxPages = 10 } = {}) {
  const repos = [];
  for (let page = 1; page <= maxPages; page += 1) {
    const batch = await githubFetch(
      token,
      `/user/repos?per_page=100&page=${page}&sort=updated&affiliation=owner,collaborator,organization_member`,
      { fetchImpl },
    );
    const items = Array.isArray(batch) ? batch : [];
    repos.push(...items);
    if (items.length < 100) break;
  }
  return repos.map((repo) => ({
    full_name: repo.full_name,
    owner: repo.owner?.login,
    name: repo.name,
    private: repo.private === true,
    default_branch: repo.default_branch ?? null,
  }));
}

/**
 * Verify that the token can actually read the repository named in a webhook.
 * 404/403 means "not authorized"; network or GitHub outage errors are rethrown
 * so the delivery can be retried rather than silently rejected.
 */
export async function checkRepoAccess(token, owner, repo, { fetchImpl = fetch, timeout = 5000 } = {}) {
  assertRepoCoordinates(owner, repo);
  try {
    await githubFetch(token, `/repos/${owner}/${repo}`, { fetchImpl, timeout });
    return true;
  } catch (err) {
    if (err.status === 403 || err.status === 404) return false;
    throw err;
  }
}

async function resolveTarget(token, owner, repo, { fetchImpl, sha = null, ref = null }) {
  if (sha) {
    if (!/^[0-9a-f]{7,64}$/i.test(String(sha))) throw new Error("Invalid commit SHA.");
    const commit = await githubFetch(token, `/repos/${owner}/${repo}/git/commits/${sha}`, {
      fetchImpl,
    });
    return {
      commitSha: commit.sha,
      treeSha: commit.tree?.sha,
      ref: ref ?? null,
    };
  }

  const info = await githubFetch(token, `/repos/${owner}/${repo}`, { fetchImpl });
  let branch = ref || info.default_branch;
  if (String(branch).startsWith("refs/heads/")) branch = String(branch).slice("refs/heads/".length);
  if (!branch) throw new Error("Repository has no default branch.");

  const branchInfo = await githubFetch(
    token,
    `/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}`,
    { fetchImpl },
  );
  return {
    commitSha: branchInfo.commit?.sha,
    treeSha: branchInfo.commit?.commit?.tree?.sha,
    ref: `refs/heads/${branch}`,
  };
}

function blobUrl(owner, repo, commitSha, filePath, line = null) {
  const encodedPath = String(filePath)
    .split("/")
    .map(encodeURIComponent)
    .join("/");
  const base = `https://github.com/${owner}/${repo}/blob/${commitSha}/${encodedPath}`;
  return line ? `${base}#L${line}` : base;
}

function scanTextForSecrets(text, path, { owner, repo, commitSha }) {
  const out = [];
  if (!text) return out;

  for (const pattern of SECRET_PATTERNS) {
    const flags = pattern.re.flags.includes("g") ? pattern.re.flags : `${pattern.re.flags}g`;
    const re = new RegExp(pattern.re.source, flags);
    let occurrence = 0;

    for (const match of text.matchAll(re)) {
      if (occurrence >= MAX_SECRET_MATCHES_PER_PATTERN_PER_FILE) break;
      if (match.index === undefined) continue;
      occurrence += 1;

      const line = text.slice(0, match.index).split("\n").length;
      const specific = !pattern.key.startsWith("secret_generic_");
      out.push(
        finding(
          pattern.key,
          `${pattern.name} in ${path}`,
          pattern.severity,
          "A credential-like value is committed to the repository. Anyone with read access can use it. Rotate it, remove it from the file, and purge it from git history if it was ever pushed.",
          {
            url: blobUrl(owner, repo, commitSha, path, line),
            evidence: `${redactSecret(match[0])} · ${owner}/${repo}/${path}:${line}`,
            affected_resource: `${path}:${line}:${occurrence}`,
            confidence: specific ? "high" : "medium",
            what_it_does_not_prove:
              "A pattern match does not prove the credential is live, privileged, or still valid.",
            remediation:
              "Rotate the credential, remove it from the repository, and purge it from git history if it was pushed.",
          },
        ),
      );
    }
  }
  return out;
}

export function packagesFromPackageLock(path, content) {
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }

  const out = [];
  const seen = new Set();
  const add = (name, version) => {
    if (!name || !version) return;
    const normalized = String(version).trim().replace(/^v/, "");
    if (!EXACT_VERSION_RE.test(normalized)) return;
    const key = `${name}@${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version: normalized, ecosystem: "npm", lockPath: path });
  };

  if (json.packages && typeof json.packages === "object") {
    for (const [packagePath, info] of Object.entries(json.packages)) {
      if (!packagePath || !info || info.link) continue;
      const marker = "node_modules/";
      const index = packagePath.lastIndexOf(marker);
      if (index < 0) continue;
      const name = packagePath.slice(index + marker.length);
      if (!name || name.includes(marker)) continue;
      add(name, info.version);
    }
  } else if (json.dependencies && typeof json.dependencies === "object") {
    const walk = (dependencies) => {
      for (const [name, info] of Object.entries(dependencies ?? {})) {
        if (!info || typeof info !== "object") continue;
        add(name, info.version);
        if (info.dependencies) walk(info.dependencies);
      }
    };
    walk(json.dependencies);
  }

  return out;
}

export function packagesFromPnpmLock(path, content) {
  if (!content) return [];
  const out = [];
  const seen = new Set();
  const add = (name, version) => {
    if (!name || !version) return;
    const normalized = String(version).trim().replace(/^v/, "");
    if (!EXACT_VERSION_RE.test(normalized)) return;
    const key = `${name}@${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version: normalized, ecosystem: "npm", lockPath: path });
  };

  let inPackages = false;
  for (const rawLine of String(content).split(/\r?\n/)) {
    if (/^[a-zA-Z0-9_-]+:/.test(rawLine)) {
      inPackages = /^packages:\s*$/.test(rawLine);
      continue;
    }
    if (!inPackages) continue;
    // Match 2-space indented package entries under `packages:`.
    const entry = rawLine.match(/^  ([^#\s][^:]*):\s*$/);
    if (!entry) continue;

    let spec = entry[1].trim().replace(/^['"]|['"]$/g, "");
    // Strip peer-dependency suffixes such as `(react@18.2.0)` or `_react@18.2.0`.
    const paren = spec.indexOf("(");
    if (paren > 0) spec = spec.slice(0, paren);
    const underscore = spec.indexOf("_");
    if (underscore > 0 && /@\d/.test(spec.slice(0, underscore))) {
      spec = spec.slice(0, underscore);
    }
    if (spec.startsWith("/")) spec = spec.slice(1);

    // Format A (pnpm v6/v9): `lodash@4.17.20` or `@scope/pkg@2.3.4`
    const atIndex = spec.lastIndexOf("@");
    if (atIndex > 0) {
      const name = spec.slice(0, atIndex);
      const version = spec.slice(atIndex + 1);
      if (EXACT_VERSION_RE.test(version)) {
        add(name, version);
        continue;
      }
    }

    // Format B (pnpm v5): `lodash/4.17.20` or `@scope/pkg/2.3.4`
    const slashIndex = spec.lastIndexOf("/");
    if (slashIndex > 0) {
      const name = spec.slice(0, slashIndex);
      const version = spec.slice(slashIndex + 1);
      if (EXACT_VERSION_RE.test(version)) {
        add(name, version);
      }
    }
  }

  return out;
}

export function packagesFromYarnLock(path, content) {
  if (!content) return [];
  const out = [];
  const seen = new Set();
  const add = (name, version) => {
    if (!name || !version) return;
    const normalized = String(version).trim().replace(/^v/, "");
    if (!EXACT_VERSION_RE.test(normalized)) return;
    const key = `${name}@${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version: normalized, ecosystem: "npm", lockPath: path });
  };

  const extractName = (headerLine) => {
    // Take the first descriptor before comma or trailing colon.
    const first = headerLine
      .replace(/:\s*$/, "")
      .split(",")[0]
      .trim()
      .replace(/^['"]|['"]$/g, "");
    if (!first || first === "__metadata") return null;
    // Skip workspace resolutions.
    if (first.includes("@workspace:")) return null;
    const atIndex = first.startsWith("@") ? first.indexOf("@", 1) : first.indexOf("@");
    if (atIndex <= 0) return null;
    return first.slice(0, atIndex).trim() || null;
  };

  let currentName = null;
  let currentVersion = null;
  let skipBlock = false;
  const flush = () => {
    if (currentName && currentVersion && !skipBlock) add(currentName, currentVersion);
    currentName = null;
    currentVersion = null;
    skipBlock = false;
  };

  for (const rawLine of String(content).split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      if (!trimmed) flush();
      continue;
    }

    if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t")) {
      flush();
      if (trimmed.endsWith(":")) {
        currentName = extractName(trimmed);
      }
      continue;
    }

    if (!currentName) continue;
    if (/^resolution:\s*["']?[^"']*@workspace:/i.test(trimmed)) {
      skipBlock = true;
      continue;
    }
    // Yarn v1: `  version "4.17.20"` | Yarn Berry: `  version: 4.17.20`
    const verMatch = trimmed.match(/^version(?:\s*:\s*|\s+)["']?([^"'\s]+)["']?$/);
    if (verMatch && !currentVersion) {
      currentVersion = verMatch[1];
    }
  }
  flush();

  return out;
}

export function packagesFromRequirementsTxt(path, content) {
  if (!content) return [];
  const out = [];
  const seen = new Set();

  for (const rawLine of String(content).split(/\r?\n/)) {
    const noComment = rawLine.split("#")[0].trim();
    if (!noComment || noComment.startsWith("-")) continue;
    // Strip environment markers (`; python_version < "3.12"`) and hashes (`--hash=...`).
    const clean = noComment.split(";")[0].split(/\s+--/)[0].trim();
    const match = clean.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9.+_-]+)$/);
    if (!match) continue;
    const name = match[1];
    const version = match[2];
    if (!PEP440_EXACT_RE.test(version)) continue;
    const key = `${name.toLowerCase()}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name, version, ecosystem: "PyPI", lockPath: path });
  }

  return out;
}

export function packagesFromTomlLock(path, content) {
  if (!content) return [];
  const out = [];
  const seen = new Set();
  let inPackage = false;
  let inSubtable = false;
  let name = null;
  let version = null;
  let isLocal = false;

  const flush = () => {
    if (inPackage && !isLocal && name && version && PEP440_EXACT_RE.test(version)) {
      const key = `${name.toLowerCase()}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ name, version, ecosystem: "PyPI", lockPath: path });
      }
    }
    name = null;
    version = null;
    isLocal = false;
    inSubtable = false;
  };

  for (const rawLine of String(content).split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (trimmed === "[[package]]") {
      flush();
      inPackage = true;
      inSubtable = false;
      continue;
    }

    if (trimmed.startsWith("[")) {
      if (trimmed.startsWith("[package.") || trimmed.startsWith("[[package.")) {
        inSubtable = true;
      } else {
        flush();
        inPackage = false;
      }
      continue;
    }

    if (!inPackage || inSubtable) continue;

    const nameMatch = trimmed.match(/^name\s*=\s*["']([^"']+)["']/);
    if (nameMatch) {
      name = nameMatch[1];
      continue;
    }
    const verMatch = trimmed.match(/^version\s*=\s*["']([^"']+)["']/);
    if (verMatch) {
      version = verMatch[1];
      continue;
    }
    if (/^source\s*=\s*\{[^}]*(?:editable|virtual)\s*=/.test(trimmed)) {
      isLocal = true;
    }
  }
  flush();

  return out;
}

export function scanClientExposedEnvVars(text, path, { owner, repo, commitSha }) {
  const out = [];
  if (!text) return out;

  const seenOnFile = new Set();
  const re = new RegExp(CLIENT_ENV_RE.source, "g");
  for (const match of text.matchAll(re)) {
    if (match.index === undefined) continue;
    const varName = match[1];
    if (seenOnFile.has(varName)) continue;

    const prefix = CLIENT_EXPOSED_ENV_PREFIXES.find((p) => varName.startsWith(p));
    if (!prefix) continue;
    const suffix = varName.slice(prefix.length);
    if (!suffix || SAFE_CLIENT_ENV_SUFFIX_RE.test(suffix)) continue;

    const rule = DANGEROUS_CLIENT_ENV_PATTERNS.find((entry) => entry.re.test(suffix));
    if (!rule) continue;

    seenOnFile.add(varName);
    const line = text.slice(0, match.index).split("\n").length;
    out.push(
      finding(
        "client_exposed_secret_env",
        `Client-exposed secret variable: ${varName}`,
        rule.severity,
        `Environment variables prefixed with \`${prefix}\` are bundled into public browser JavaScript. Naming a ${rule.label} with \`${prefix}\` exposes it to every visitor.`,
        {
          url: blobUrl(owner, repo, commitSha, path, line),
          evidence: `${varName} · ${owner}/${repo}/${path}:${line}`,
          affected_resource: `${path}:${varName}`,
          confidence: "high",
          what_it_does_not_prove:
            "This checks the variable name, not whether a live secret is currently set in your deployment environment.",
          remediation: `Remove the ${prefix} prefix, move code using ${varName} into a server route or edge function, and rotate the credential if it was ever deployed.`,
        },
      ),
    );
  }
  return out;
}

export function scanSupabaseMigrationsForRls(sqlFiles, { owner, repo, commitSha }) {
  if (!sqlFiles.length) return [];

  const rlsEnabledTables = new Set();
  const createdTables = [];

  for (const file of sqlFiles) {
    const content = file.content ?? "";
    const enableRe =
      /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:["']?public["']?\.)?["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s+enable\s+row\s+level\s+security/gi;
    for (const match of content.matchAll(enableRe)) {
      rlsEnabledTables.add(match[1].toLowerCase());
    }

    const createRe =
      /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:["']?public["']?\.)?["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*\(/gi;
    for (const match of content.matchAll(createRe)) {
      const table = match[1].toLowerCase();
      // Ignore schema-qualified non-public tables such as auth.users or storage.objects.
      const before = content.slice(Math.max(0, match.index - 40), match.index + match[0].length);
      if (/\b(?:auth|storage|realtime|vault|pg_catalog)\s*\./i.test(before)) continue;
      const line = content.slice(0, match.index).split("\n").length;
      createdTables.push({ table, path: file.path, line });
    }
  }

  const out = [];
  const seen = new Set();
  for (const entry of createdTables) {
    if (rlsEnabledTables.has(entry.table) || seen.has(entry.table)) continue;
    seen.add(entry.table);
    out.push(
      finding(
        "supabase_migration_missing_rls",
        `Migration creates table without RLS: ${entry.table}`,
        "high",
        `\`${entry.path}\` creates table \`public.${entry.table}\`, and none of the scanned SQL migrations enable Row Level Security on it.`,
        {
          url: blobUrl(owner, repo, commitSha, entry.path, entry.line),
          evidence: `public.${entry.table} · ${entry.path}:${entry.line}`,
          affected_resource: `migration_table:${entry.table}`,
          confidence: "medium",
          what_it_does_not_prove:
            "RLS may have been enabled directly in the Supabase dashboard or in a migration outside the scanned file cap.",
          remediation: `Add \`alter table public.${entry.table} enable row level security;\` and owner-scoped RLS policies in a migration.`,
        },
      ),
    );
  }
  return out;
}

function unpinnedFindings(path, content, { owner, repo, commitSha }) {
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }

  const out = [];
  const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
  for (const [name, version] of Object.entries(deps)) {
    const value = String(version ?? "").trim();
    if (!["*", "latest", ""].includes(value)) continue;
    out.push(
      finding(
        "dep_unpinned",
        `Unpinned dependency: ${name}`,
        "medium",
        `Dependency ${name} uses an unpinned version (${value || "empty"}), which can introduce breaking or malicious updates.`,
        {
          url: blobUrl(owner, repo, commitSha, path),
          evidence: `${name}@${value || "(empty)"}`,
          affected_resource: `${path}:${name}`,
          confidence: "high",
          what_it_does_not_prove:
            "An unpinned range is a supply-chain risk, not proof that a malicious version is installed today.",
          remediation: `Pin ${name} to an exact version and commit the lockfile.`,
        },
      ),
    );
  }
  return out;
}

function scanConfigFile(path, content, { owner, repo, commitSha }) {
  const out = [];
  const lower = path.toLowerCase();

  for (const check of CONFIG_CHECKS) {
    const checkPath = check.path.toLowerCase();
    const isDirectory = checkPath.endsWith("/");
    const matchesPath = isDirectory
      ? lower.startsWith(checkPath)
      : lower === checkPath || lower.startsWith(`${checkPath}/`);
    if (!matchesPath) continue;
    try {
      if (check.test(content)) {
        out.push(
          finding(check.check, check.title, check.severity, check.detail, {
            url: blobUrl(owner, repo, commitSha, path),
            evidence: `Found in ${path}`,
            affected_resource: path,
            confidence: "medium",
            what_it_does_not_prove:
              "This is a static configuration heuristic; it does not prove the container or workflow is exploitable.",
            remediation:
              check.remediation ??
              (check.check.includes("docker")
                ? "Add a non-root USER directive to the image or service."
                : "Review and harden this configuration."),
          }),
        );
      }
    } catch {
      // Invalid test — skip.
    }
  }
  return out;
}

function severityFromOsv(vuln) {
  const raw =
    vuln?.database_specific?.severity ??
    vuln?.affected?.[0]?.database_specific?.severity ??
    null;
  const value = String(raw ?? "").toLowerCase();
  if (value === "moderate") return "medium";
  if (["low", "medium", "high", "critical"].includes(value)) return value;
  return "medium";
}

function fixedVersions(vuln) {
  const fixed = [];
  for (const affected of vuln?.affected ?? []) {
    for (const range of affected?.ranges ?? []) {
      for (const event of range?.events ?? []) {
        if (event?.fixed) fixed.push(String(event.fixed));
      }
    }
  }
  return [...new Set(fixed)];
}

function worstSeverity(values) {
  return values.reduce(
    (worst, value) =>
      (SEVERITY_RANK[value] ?? 0) > (SEVERITY_RANK[worst] ?? 0) ? value : worst,
    "info",
  );
}

async function queryOsv(packages, { fetchImpl = fetch } = {}) {
  if (!packages.length) return [];

  const unique = [];
  const seen = new Set();
  for (const pkg of packages) {
    const eco = pkg.ecosystem || "npm";
    const key = `${pkg.lockPath}:${eco}:${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({ ...pkg, ecosystem: eco });
  }

  const out = [];
  for (let offset = 0; offset < unique.length; offset += 500) {
    const chunk = unique.slice(offset, offset + 500);
    const res = await fetchImpl(OSV_API, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((pkg) => ({
          package: { name: pkg.name, ecosystem: pkg.ecosystem },
          version: pkg.version,
        })),
      }),
      signal: AbortSignal.timeout(20_000),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`OSV advisory lookup returned HTTP ${res.status}${body ? `: ${body.slice(0, 120)}` : ""}`);
    }

    const json = await res.json();
    const results = Array.isArray(json?.results) ? json.results : [];
    for (let i = 0; i < chunk.length; i += 1) {
      out.push({ pkg: chunk[i], vulns: results[i]?.vulns ?? [] });
    }
  }
  return out;
}

function osvFindings(results, { owner, repo, commitSha }) {
  const findings = [];
  for (const { pkg, vulns } of results) {
    if (!vulns.length) continue;

    const ids = [...new Set(vulns.map((v) => v.id).filter(Boolean))];
    const severity = worstSeverity(vulns.map(severityFromOsv));
    const fixed = [...new Set(vulns.flatMap(fixedVersions))];
    const summary = vulns.find((v) => v.summary)?.summary ?? "See the linked advisory.";
    const firstId = ids[0] ?? null;

    findings.push(
      finding(
        `dep_vuln_${pkg.name}`,
        `Vulnerable dependency: ${pkg.name}@${pkg.version}`,
        severity,
        `${vulns.length} advisory${vulns.length === 1 ? "" : "ies"} affect the locked version. ${summary}`,
        {
          url: firstId
            ? `https://osv.dev/vulnerability/${encodeURIComponent(firstId)}`
            : `https://osv.dev/list?q=${encodeURIComponent(pkg.name)}`,
          evidence: [
            ids.length ? `OSV ${ids.slice(0, 4).join(", ")}${ids.length > 4 ? "…" : ""}` : "OSV advisory",
            fixed.length ? `fixed in ${fixed.join(", ")}` : null,
          ]
            .filter(Boolean)
            .join(" · "),
          affected_resource: `${pkg.lockPath}:${pkg.name}@${pkg.version}`,
          confidence: "high",
          what_it_does_not_prove:
            "An advisory match does not prove the vulnerable code path is reachable in this application.",
          remediation: fixed.length
            ? `Upgrade ${pkg.name} to ${fixed[0]} or later and regenerate the lockfile.`
            : `Upgrade ${pkg.name} to a version outside the affected range and regenerate the lockfile.`,
          url_path: blobUrl(owner, repo, commitSha, pkg.lockPath),
        },
      ),
    );
  }
  return findings;
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await fn(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function checkOutcome(label, findings, errors) {
  if (errors.length && findings.length) {
    return {
      key: label,
      label,
      status: "finding",
      complete: false,
      error: errors.slice(0, 3).join("; "),
    };
  }
  if (errors.length) {
    return { key: label, label, status: "error", complete: false, error: errors.slice(0, 3).join("; ") };
  }
  if (findings.length) return { key: label, label, status: "finding", complete: true };
  return { key: label, label, status: "pass", complete: true };
}

function failedResult(error) {
  const message = error?.message ?? String(error);
  return {
    findings: [],
    status: "failed",
    error: message,
    checkResults: [
      {
        key: "repo_access",
        label: "Repository access",
        status: "error",
        complete: false,
        error: message,
      },
    ],
    checksTotal: 1,
    checksPassed: 0,
    checksErrored: 1,
    checksSkipped: 0,
    coverage: {
      filesScanned: 0,
      filesRead: 0,
      totalFiles: 0,
      skippedByCap: 0,
      skippedNonText: 0,
      skippedLarge: 0,
      skippedUnreadable: 0,
      treeTruncated: false,
      scanTruncated: false,
      scannedPercent: 0,
      notes: [`Repository could not be scanned: ${message}`],
    },
  };
}

/**
 * Scan the repository at an exact commit when one is supplied (webhook), or
 * the default branch head (manual scan). Coverage is explicit: capped,
 * truncated, skipped, and unreadable files are all reported.
 */
export async function scanGitHubRepo(
  token,
  owner,
  repo,
  { fetchImpl = fetch, osvFetchImpl = fetch, sha = null, ref = null } = {},
) {
  assertRepoCoordinates(owner, repo);

  let target;
  try {
    target = await resolveTarget(token, owner, repo, { fetchImpl, sha, ref });
  } catch (err) {
    return failedResult(err);
  }

  if (!target.commitSha || !target.treeSha) return failedResult(new Error("Could not resolve a commit tree."));

  let tree;
  try {
    tree = await githubFetch(
      token,
      `/repos/${owner}/${repo}/git/trees/${target.treeSha}?recursive=1`,
      { fetchImpl },
    );
  } catch (err) {
    return failedResult(err);
  }

  const blobs = (Array.isArray(tree?.tree) ? tree.tree : []).filter((entry) => entry.type === "blob");
  const treeTruncated = tree?.truncated === true;

  const candidates = [];
  let skippedNonText = 0;
  let skippedLarge = 0;
  for (const blob of blobs) {
    if (!isTextFile(blob.path)) {
      skippedNonText += 1;
      continue;
    }
    if (Number(blob.size ?? 0) > MAX_FILE_BYTES) {
      skippedLarge += 1;
      continue;
    }
    candidates.push(blob);
  }

  const toScan = candidates.slice(0, MAX_FILES_SCANNED);
  const skippedByCap = candidates.length - toScan.length;

  const secretFindings = [];
  const historyFindings = [];
  const sensitiveFindings = [];
  const dependencyFindings = [];
  const configFindings = [];
  const secretErrors = [];
  const historyErrors = [];
  const dependencyErrors = [];
  const configErrors = [];
  const lockfiles = [];
  const unsupportedDependencyFiles = new Set();
  const migrationSqlFiles = [];
  let filesRead = 0;
  let skippedUnreadable = 0;
  let historyCommitsScanned = 0;

  const results = await mapLimit(toScan, GITHUB_FETCH_CONCURRENCY, async (blob) => {
    try {
      const data = await githubFetch(
        token,
        `/repos/${owner}/${repo}/git/blobs/${blob.sha}`,
        { fetchImpl },
      );
      const content =
        data?.encoding === "base64" && data?.content
          ? Buffer.from(data.content, "base64").toString("utf8")
          : null;
      return { blob, content, error: null };
    } catch (err) {
      return { blob, content: null, error: err?.message ?? String(err) };
    }
  });

  for (const item of results) {
    if (item.error || item.content === null) {
      skippedUnreadable += 1;
      secretErrors.push(`${item.blob.path}: ${item.error ?? "no content"}`);
      continue;
    }

    filesRead += 1;
    const path = item.blob.path;
    const lower = path.toLowerCase();
    const base = lower.slice(lower.lastIndexOf("/") + 1);

    if (SENSITIVE_FILENAMES.has(base) || SENSITIVE_FILENAMES.has(lower)) {
      sensitiveFindings.push(
        finding(
          "exposed_config_file",
          `Sensitive file committed: ${path}`,
          "high",
          "A potentially sensitive configuration or credential file is committed to the repository. Move secrets out of git and into environment variables or a secrets manager.",
          {
            url: blobUrl(owner, repo, target.commitSha, path),
            evidence: `${item.blob.size ?? "?"} bytes`,
            affected_resource: path,
            confidence: "high",
            what_it_does_not_prove:
              "The file may contain placeholders rather than live credentials; inspect and rotate anything real.",
            remediation:
              "Remove the file from the repository, move its values to environment variables, and rotate exposed secrets.",
          },
        ),
      );
    }

    secretFindings.push(
      ...scanTextForSecrets(item.content, path, {
        owner,
        repo,
        commitSha: target.commitSha,
      }),
      ...scanClientExposedEnvVars(item.content, path, {
        owner,
        repo,
        commitSha: target.commitSha,
      }),
    );

    if (base === "package.json") {
      dependencyFindings.push(
        ...unpinnedFindings(path, item.content, {
          owner,
          repo,
          commitSha: target.commitSha,
        }),
      );
    }

    if (base === "package-lock.json") {
      lockfiles.push(...packagesFromPackageLock(path, item.content));
    } else if (base === "pnpm-lock.yaml") {
      lockfiles.push(...packagesFromPnpmLock(path, item.content));
    } else if (base === "yarn.lock") {
      lockfiles.push(...packagesFromYarnLock(path, item.content));
    } else if (base === "requirements.txt") {
      lockfiles.push(...packagesFromRequirementsTxt(path, item.content));
    } else if (base === "poetry.lock" || base === "uv.lock") {
      lockfiles.push(...packagesFromTomlLock(path, item.content));
    } else if (UNANALYZED_LOCKFILES.has(base)) {
      unsupportedDependencyFiles.add(path);
    }

    if (lower.startsWith("supabase/migrations/") && lower.endsWith(".sql")) {
      migrationSqlFiles.push({ path, content: item.content });
    }

    configFindings.push(
      ...scanConfigFile(path, item.content, {
        owner,
        repo,
        commitSha: target.commitSha,
      }),
    );
  }

  if (migrationSqlFiles.length) {
    configFindings.push(
      ...scanSupabaseMigrationsForRls(migrationSqlFiles, {
        owner,
        repo,
        commitSha: target.commitSha,
      }),
    );
  }

  if (lockfiles.length) {
    try {
      const osvResults = await queryOsv(lockfiles, { fetchImpl: osvFetchImpl });
      dependencyFindings.push(
        ...osvFindings(osvResults, {
          owner,
          repo,
          commitSha: target.commitSha,
        }),
      );
    } catch (err) {
      dependencyErrors.push(err?.message ?? String(err));
    }
  }

  // Bounded recent commit-history secret scan: checks added lines in up to
  // MAX_HISTORY_COMMITS-1 prior commits for high-confidence provider secrets
  // (catches leaked keys deleted in a follow-up commit without rotation).
  const highConfidencePatterns = SECRET_PATTERNS.filter(
    (pattern) => !pattern.key.startsWith("secret_generic_"),
  );
  let historyChecked = false;
  try {
    const commitList = await githubFetch(
      token,
      `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(target.commitSha)}&per_page=${MAX_HISTORY_COMMITS}`,
      { fetchImpl },
    );
    const priorCommits = (Array.isArray(commitList) ? commitList : [])
      .filter((entry) => entry?.sha && entry.sha !== target.commitSha)
      .slice(0, MAX_HISTORY_COMMITS - 1);
    historyChecked = true;

    const commitDetails = await mapLimit(priorCommits, GITHUB_FETCH_CONCURRENCY, async (entry) => {
      try {
        const detail = await githubFetch(
          token,
          `/repos/${owner}/${repo}/commits/${encodeURIComponent(entry.sha)}`,
          { fetchImpl },
        );
        return { sha: entry.sha, detail, error: null };
      } catch (err) {
        return { sha: entry.sha, detail: null, error: err?.message ?? String(err) };
      }
    });

    for (const item of commitDetails) {
      if (item.error || !item.detail) {
        historyErrors.push(`${item.sha.slice(0, 7)}: ${item.error ?? "unreadable commit"}`);
        continue;
      }
      historyCommitsScanned += 1;
      const files = Array.isArray(item.detail.files) ? item.detail.files : [];
      for (const file of files) {
        if (!file?.patch || !file?.filename) continue;
        const addedLines = String(file.patch)
          .split("\n")
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .map((line) => line.slice(1))
          .join("\n");
        if (!addedLines) continue;

        for (const pattern of highConfidencePatterns) {
          const flags = pattern.re.flags.includes("g") ? pattern.re.flags : `${pattern.re.flags}g`;
          const re = new RegExp(pattern.re.source, flags);
          let count = 0;
          for (const match of addedLines.matchAll(re)) {
            if (count >= 5) break;
            count += 1;
            const shortSha = item.sha.slice(0, 7);
            historyFindings.push(
              finding(
                `history_${pattern.key}`,
                `Historical ${pattern.name} in commit ${shortSha} (${file.filename})`,
                pattern.severity,
                `A high-confidence credential pattern was added in recent commit \`${shortSha}\`. Even if deleted in a later commit, anyone who can clone or read git history can still retrieve it.`,
                {
                  url: `https://github.com/${owner}/${repo}/commit/${item.sha}`,
                  evidence: `${redactSecret(match[0])} · ${owner}/${repo}@${shortSha} (${file.filename})`,
                  affected_resource: `history:${item.sha.slice(0, 12)}:${file.filename}:${count}`,
                  confidence: "high",
                  what_it_does_not_prove:
                    "Only the most recent commits were inspected; matching a pattern does not prove the key is still active.",
                  remediation:
                    "Rotate/revoke the exposed credential immediately, and rewrite git history if the repository is or was public.",
                },
              ),
            );
          }
        }
      }
    }
  } catch (err) {
    historyErrors.push(`Commit history lookup: ${err?.message ?? String(err)}`);
  }

  const scanTruncated =
    treeTruncated || skippedByCap > 0 || skippedLarge > 0 || skippedUnreadable > 0;
  const notes = [];
  if (skippedByCap > 0) {
    notes.push(
      `Scanned the first ${MAX_FILES_SCANNED} text files; ${skippedByCap} additional candidate files were not read.`,
    );
  }
  if (treeTruncated) {
    notes.push("GitHub truncated the repository tree, so file coverage is incomplete.");
  }
  if (skippedLarge > 0) {
    notes.push(`${skippedLarge} file(s) exceeded ${MAX_FILE_BYTES} bytes and were not read.`);
  }
  if (skippedUnreadable > 0) {
    notes.push(`${skippedUnreadable} file(s) could not be read.`);
  }
  if (unsupportedDependencyFiles.size > 0) {
    notes.push(
      `Dependency advisories currently cover npm (package-lock.json, pnpm-lock.yaml, yarn.lock) and Python (requirements.txt, poetry.lock, uv.lock). Not analyzed: ${[...unsupportedDependencyFiles]
        .slice(0, 8)
        .join(", ")}${unsupportedDependencyFiles.size > 8 ? "…" : ""}.`,
    );
  }

  const checkResults = [
    { key: "repo_access", label: "Repository access", status: "pass", complete: true },
    checkOutcome("secrets", secretFindings, secretErrors),
    historyChecked
      ? checkOutcome("commit_history", historyFindings, historyErrors)
      : {
          key: "commit_history",
          label: "commit_history",
          status: "error",
          complete: false,
          error: historyErrors.slice(0, 3).join("; "),
        },
    checkOutcome("sensitive_files", sensitiveFindings, []),
    checkOutcome("dependencies", dependencyFindings, dependencyErrors),
    checkOutcome("config_checks", configFindings, configErrors),
  ];

  const collectedFindings = [
    ...secretFindings,
    ...historyFindings,
    ...sensitiveFindings,
    ...dependencyFindings,
    ...configFindings,
  ];
  const allFindings = collectedFindings.slice(0, MAX_FINDINGS);
  if (collectedFindings.length > MAX_FINDINGS) {
    notes.push(
      `${collectedFindings.length - MAX_FINDINGS} finding(s) were omitted after the ${MAX_FINDINGS}-finding cap.`,
    );
  }

  const hasErrors =
    secretErrors.length > 0 ||
    historyErrors.length > 0 ||
    dependencyErrors.length > 0 ||
    configErrors.length > 0;
  const status =
    hasErrors || scanTruncated || collectedFindings.length > MAX_FINDINGS
      ? "partial"
      : "completed";
  const errors = [...secretErrors, ...historyErrors, ...dependencyErrors, ...configErrors];

  const coverage = {
    commitSha: target.commitSha,
    ref: target.ref,
    filesScanned: toScan.length,
    filesRead,
    totalFiles: blobs.length,
    historyCommitsScanned,
    skippedByCap,
    skippedNonText,
    skippedLarge,
    skippedUnreadable,
    treeTruncated,
    scanTruncated,
    scannedPercent:
      candidates.length > 0 ? Math.round((toScan.length / candidates.length) * 100) : 100,
    notes,
  };

  return {
    findings: allFindings,
    status,
    error: errors.length ? errors.slice(0, 5).join("; ") : null,
    commitSha: target.commitSha,
    ref: target.ref,
    checkResults,
    checksTotal: checkResults.length,
    checksPassed: checkResults.filter((check) => check.status === "pass").length,
    checksErrored: checkResults.filter((check) => check.status === "error").length,
    checksSkipped: checkResults.filter((check) => check.status === "not_checked").length,
    coverage,
    filesScanned: toScan.length,
  };
}

export { redactSecret };
