import test from "node:test";
import assert from "node:assert/strict";
import {
  packagesFromPackageLock,
  packagesFromPnpmLock,
  packagesFromRequirementsTxt,
  packagesFromTomlLock,
  packagesFromYarnLock,
  scanClientExposedEnvVars,
  scanGitHubRepo,
  scanSupabaseMigrationsForRls,
} from "./github.mjs";
import { OSV_API, createGitHubFetch, commitSha } from "./test-support/github-fixtures.mjs";

const TOKEN = "ghp_faketoken1234567890";
const OWNER = "octocat";
const REPO = "Hello-World";

function scan(fixture, options = {}) {
  return scanGitHubRepo(TOKEN, OWNER, REPO, {
    fetchImpl: fixture.fetchImpl,
    osvFetchImpl: fixture.fetchImpl,
    ...options,
  });
}

test("reports every credential match and links to the exact commit line", async () => {
  const content = [
    "const stripe = 'sk_live_ABCdef1234567890abcdef';",
    "const google = 'AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';",
  ].join("\n");
  const fixture = createGitHubFetch({ files: [{ path: "src/config.js", content }] });

  const result = await scan(fixture);

  const stripe = result.findings.filter((finding) => finding.check_key === "secret_stripe");
  const google = result.findings.filter((finding) => finding.check_key === "secret_google");
  assert.equal(stripe.length, 1);
  assert.equal(google.length, 1);
  assert.equal(stripe[0].severity, "critical");
  assert.equal(
    stripe[0].url,
    `https://github.com/${OWNER}/${REPO}/blob/${fixture.headSha}/src/config.js#L1`,
  );
  assert.ok(stripe[0].evidence.includes("sk_l…cdef"), "evidence is redacted");
  assert.ok(!stripe[0].evidence.includes("sk_live_ABCdef1234567890abcdef"));
  assert.equal(stripe[0].confidence, "high");
  assert.match(stripe[0].what_it_does_not_prove, /does not prove/i);
});

test("reports all matches of one pattern per file, not just the first", async () => {
  const key = (suffix) => `AIza${suffix.padEnd(35, "0")}`;
  const content = `a=${key("A")}\nb=${key("B")}`;
  const fixture = createGitHubFetch({ files: [{ path: "app.js", content }] });

  const result = await scan(fixture);
  const google = result.findings.filter((finding) => finding.check_key === "secret_google");

  assert.equal(google.length, 2);
  assert.deepEqual(
    google.map((finding) => finding.affected_resource).sort(),
    ["app.js:1:1", "app.js:2:2"],
  );
});

test("flags sensitive filenames and unpinned dependencies", async () => {
  const fixture = createGitHubFetch({
    files: [
      { path: ".env", content: "DB_PASSWORD=secret123" },
      {
        path: "package.json",
        content: JSON.stringify({ dependencies: { lodash: "*", react: "19.0.0" } }),
      },
    ],
  });

  const result = await scan(fixture);

  assert.ok(result.findings.some((finding) => finding.check_key === "exposed_config_file"));
  const unpinned = result.findings.filter((finding) => finding.check_key === "dep_unpinned");
  assert.equal(unpinned.length, 1);
  assert.match(unpinned[0].title, /lodash/);
});

test("sends only package names and exact versions to OSV", async () => {
  const lock = {
    packages: {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/@scope/pkg": { version: "2.3.4" },
      "packages/workspace": { version: "9.9.9" },
    },
  };
  const fixture = createGitHubFetch({
    files: [{ path: "package-lock.json", content: JSON.stringify(lock) }],
    osv: () => [
      {
        vulns: [
          {
            id: "GHSA-test-1234",
            summary: "Prototype pollution",
            database_specific: { severity: "HIGH" },
            affected: [{ ranges: [{ events: [{ fixed: "4.17.21" }] }] }],
          },
        ],
      },
      { vulns: [] },
    ],
  });

  const result = await scan(fixture);

  const osvRequest = fixture.requests.find((request) => request.url === OSV_API);
  assert.ok(osvRequest, "OSV was called");
  const body = JSON.parse(osvRequest.body);
  assert.deepEqual(body.queries, [
    { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" },
    { package: { name: "@scope/pkg", ecosystem: "npm" }, version: "2.3.4" },
  ]);
  assert.ok(!osvRequest.body.includes(TOKEN), "token never leaves for OSV");
  assert.ok(!osvRequest.body.includes("lockPath"), "lockfile path is not sent");
  assert.ok(!osvRequest.body.includes("Prototype"), "source content is not sent");

  const vuln = result.findings.find((finding) => finding.check_key === "dep_vuln_lodash");
  assert.ok(vuln);
  assert.equal(vuln.severity, "high");
  assert.equal(vuln.url, "https://osv.dev/vulnerability/GHSA-test-1234");
  assert.match(vuln.evidence, /fixed in 4\.17\.21/);
});

test("dependency lookup failure is partial and never silently passes", async () => {
  const fixture = createGitHubFetch({
    files: [
      {
        path: "package-lock.json",
        content: JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.20" } } }),
      },
    ],
    osvStatus: 503,
  });

  const result = await scan(fixture);

  assert.equal(result.status, "partial");
  assert.match(result.error, /OSV advisory lookup returned HTTP 503/);
  const dependencyCheck = result.checkResults.find((check) => check.key === "dependencies");
  assert.equal(dependencyCheck.status, "error");
  assert.equal(dependencyCheck.complete, false);
});

test("flags container and workflow configuration risks", async () => {
  const fixture = createGitHubFetch({
    files: [
      { path: "Dockerfile", content: 'FROM node:20\nCMD ["node", "index.js"]' },
      {
        path: ".github/workflows/release.yml",
        content:
          "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}",
      },
    ],
  });

  const result = await scan(fixture);

  assert.ok(result.findings.some((finding) => finding.check_key === "dockerfile_root_user"));
  assert.ok(
    result.findings.some((finding) => finding.check_key === "workflow_pull_request_target"),
  );
});

test("scans an exact webhook commit instead of the branch head", async () => {
  const exact = commitSha("pushed-commit");
  const fixture = createGitHubFetch({
    exactSha: exact,
    files: [{ path: "README.md", content: "# hi" }],
  });

  const result = await scan(fixture, { sha: exact, ref: "refs/heads/main" });

  assert.equal(result.commitSha, exact);
  assert.ok(
    fixture.requests.some((request) => request.url.endsWith(`/git/commits/${exact}`)),
    "resolved the supplied commit",
  );
  assert.ok(
    !fixture.requests.some((request) => request.url.includes("/branches/")),
    "did not resolve a moving branch",
  );
});

test("reports honest coverage for skipped large and non-text files", async () => {
  const fixture = createGitHubFetch({
    files: [
      { path: "README.md", content: "# hi" },
      { path: "big.txt", content: "x", size: 600_000 },
      { path: "logo.png", content: "binary" },
    ],
  });

  const result = await scan(fixture);

  assert.equal(result.coverage.filesScanned, 1);
  assert.equal(result.coverage.skippedLarge, 1);
  assert.equal(result.coverage.skippedNonText, 1);
  assert.equal(result.coverage.scannedPercent, 100);
  assert.equal(result.coverage.scanTruncated, true);
  assert.equal(result.status, "partial");
  assert.ok(result.coverage.notes.some((note) => /exceeded/.test(note)));
});

test("reports GitHub tree truncation instead of claiming full coverage", async () => {
  const fixture = createGitHubFetch({
    files: [{ path: "README.md", content: "# hi" }],
    treeTruncated: true,
  });

  const result = await scan(fixture);

  assert.equal(result.coverage.treeTruncated, true);
  assert.equal(result.coverage.scanTruncated, true);
  assert.equal(result.status, "partial");
});

test("a repository access failure is a failed scan, not a clean one", async () => {
  const fixture = createGitHubFetch({ repoStatus: 404 });

  const result = await scan(fixture);

  assert.equal(result.status, "failed");
  assert.match(result.error, /GitHub API 404/);
  assert.equal(result.findings.length, 0);
});

test("rejects invalid repository coordinates before making a request", async () => {
  const fixture = createGitHubFetch();
  await assert.rejects(
    scanGitHubRepo(TOKEN, "bad owner", "repo", { fetchImpl: fixture.fetchImpl }),
    /Invalid GitHub repository owner/,
  );
  assert.equal(fixture.requests.length, 0);
});

test("package lock parsing skips workspace entries and non-exact versions", () => {
  const packages = packagesFromPackageLock(
    "package-lock.json",
    JSON.stringify({
      packages: {
        "": { name: "root", version: "1.0.0" },
        "packages/app": { version: "1.0.0" },
        "node_modules/a": { version: "1.2.3" },
        "node_modules/b": { version: "^2.0.0" },
      },
    }),
  );

  assert.deepEqual(packages, [
    { name: "a", version: "1.2.3", ecosystem: "npm", lockPath: "package-lock.json" },
  ]);
});

test("parses pnpm-lock.yaml, yarn.lock, requirements.txt, poetry.lock, and uv.lock", () => {
  const pnpm = packagesFromPnpmLock(
    "pnpm-lock.yaml",
    [
      "lockfileVersion: '9.0'",
      "packages:",
      "  lodash@4.17.20:",
      "    resolution: {integrity: sha512-abc}",
      "  '@scope/pkg@2.3.4(react@18.2.0)':",
      "    resolution: {integrity: sha512-def}",
      "  /express/4.18.2:",
      "    dev: false",
      "snapshots:",
      "  ignored@1.0.0: {}",
    ].join("\n"),
  );
  assert.deepEqual(pnpm, [
    { name: "lodash", version: "4.17.20", ecosystem: "npm", lockPath: "pnpm-lock.yaml" },
    { name: "@scope/pkg", version: "2.3.4", ecosystem: "npm", lockPath: "pnpm-lock.yaml" },
    { name: "express", version: "4.18.2", ecosystem: "npm", lockPath: "pnpm-lock.yaml" },
  ]);

  const yarn = packagesFromYarnLock(
    "yarn.lock",
    [
      "# yarn lockfile v1",
      'lodash@^4.17.0:',
      '  version "4.17.20"',
      "",
      '"@scope/ui@npm:^1.2.0":',
      "  version: 1.2.5",
      '  resolution: "@scope/ui@npm:1.2.5"',
      "",
      '"local-pkg@workspace:packages/local":',
      "  version: 0.0.0-use.local",
      '  resolution: "local-pkg@workspace:packages/local"',
    ].join("\n"),
  );
  assert.deepEqual(yarn, [
    { name: "lodash", version: "4.17.20", ecosystem: "npm", lockPath: "yarn.lock" },
    { name: "@scope/ui", version: "1.2.5", ecosystem: "npm", lockPath: "yarn.lock" },
  ]);

  const reqs = packagesFromRequirementsTxt(
    "requirements.txt",
    [
      "# production deps",
      "-r base.txt",
      "requests==2.31.0",
      "uvicorn[standard]==0.29.0 ; python_version >= '3.10' # comment",
      "fastapi>=0.110.0",
    ].join("\n"),
  );
  assert.deepEqual(reqs, [
    { name: "requests", version: "2.31.0", ecosystem: "PyPI", lockPath: "requirements.txt" },
    { name: "uvicorn", version: "0.29.0", ecosystem: "PyPI", lockPath: "requirements.txt" },
  ]);

  const toml = packagesFromTomlLock(
    "uv.lock",
    [
      "[[package]]",
      'name = "django"',
      'version = "4.2.10"',
      "[package.dependencies]",
      'name = "should-not-overwrite"',
      'version = "9.9.9"',
      "",
      "[[package]]",
      'name = "local-app"',
      'version = "0.1.0"',
      'source = { editable = "." }',
    ].join("\n"),
  );
  assert.deepEqual(toml, [
    { name: "django", version: "4.2.10", ecosystem: "PyPI", lockPath: "uv.lock" },
  ]);
});

test("queries OSV for both npm (pnpm/yarn) and PyPI lockfiles and notes unanalyzed lockfiles", async () => {
  const fixture = createGitHubFetch({
    files: [
      { path: "pnpm-lock.yaml", content: "packages:\n  lodash@4.17.20:\n    dev: false\n" },
      { path: "requirements.txt", content: "django==4.2.10\n" },
      { path: "Cargo.lock", content: '[[package]]\nname = "serde"\nversion = "1.0.0"\n' },
    ],
    osv: (queries) =>
      queries.map((q) =>
        q.package.name === "django"
          ? {
              vulns: [
                {
                  id: "GHSA-django-test",
                  summary: "SQL injection",
                  database_specific: { severity: "CRITICAL" },
                  affected: [{ ranges: [{ events: [{ fixed: "4.2.11" }] }] }],
                },
              ],
            }
          : { vulns: [] },
      ),
  });

  const result = await scan(fixture);

  const osvReq = fixture.requests.find((request) => request.url === OSV_API);
  assert.ok(osvReq);
  const body = JSON.parse(osvReq.body);
  assert.deepEqual(body.queries, [
    { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" },
    { package: { name: "django", ecosystem: "PyPI" }, version: "4.2.10" },
  ]);

  const vuln = result.findings.find((finding) => finding.check_key === "dep_vuln_django");
  assert.ok(vuln);
  assert.equal(vuln.severity, "critical");
  assert.ok(
    result.coverage.notes.some((note) => note.includes("Cargo.lock")),
    "unanalyzed lockfiles remain explicitly reported",
  );
});

test("flags client-exposed NEXT_PUBLIC_/VITE_ secret env names without flagging safe public keys", async () => {
  const code = [
    "const ok1 = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;",
    "const ok2 = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;",
    "const ok3 = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;",
    "const bad1 = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;",
    "const bad2 = import.meta.env.VITE_OPENAI_API_KEY;",
    "const bad3 = process.env.REACT_APP_DATABASE_URL;",
  ].join("\n");

  const direct = scanClientExposedEnvVars(code, "src/client.ts", {
    owner: OWNER,
    repo: REPO,
    commitSha: commitSha("env-test"),
  });
  assert.deepEqual(
    direct.map((f) => f.affected_resource),
    [
      "src/client.ts:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
      "src/client.ts:VITE_OPENAI_API_KEY",
      "src/client.ts:REACT_APP_DATABASE_URL",
    ],
  );
  assert.ok(direct.every((f) => f.severity === "critical"));

  const fixture = createGitHubFetch({
    files: [
      { path: "src/client.ts", content: code },
      {
        path: "vercel.json",
        content: JSON.stringify({
          headers: [
            {
              source: "/api/(.*)",
              headers: [
                { key: "Access-Control-Allow-Origin", value: "*" },
                { key: "Access-Control-Allow-Credentials", value: "true" },
              ],
            },
          ],
        }),
      },
    ],
  });

  const result = await scan(fixture);
  assert.equal(
    result.findings.filter((f) => f.check_key === "client_exposed_secret_env").length,
    3,
  );
  assert.ok(result.findings.some((f) => f.check_key === "vercel_wildcard_cors_credentials"));
});

test("checks supabase/migrations/*.sql across files for tables missing RLS", async () => {
  const findings = scanSupabaseMigrationsForRls(
    [
      {
        path: "supabase/migrations/001_init.sql",
        content: [
          "create table public.orders (id uuid primary key);",
          "create table public.invoices (id uuid primary key);",
        ].join("\n"),
      },
      {
        path: "supabase/migrations/002_enable_rls.sql",
        content: "alter table public.orders enable row level security;",
      },
    ],
    { owner: OWNER, repo: REPO, commitSha: commitSha("sql-test") },
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].check_key, "supabase_migration_missing_rls");
  assert.equal(findings[0].affected_resource, "migration_table:invoices");
  assert.equal(findings[0].confidence, "medium");
});

test("scans bounded recent commit history for leaked secrets and flags workflow write-all / unpinned actions", async () => {
  const oldSha = commitSha("old-leak-commit");
  const fixture = createGitHubFetch({
    files: [
      { path: "README.md", content: "# clean head" },
      {
        path: ".github/workflows/deploy.yml",
        content: [
          "on: push",
          "permissions: write-all",
          "jobs:",
          "  deploy:",
          "    steps:",
          "      - uses: thirdparty/deploy-action@main",
        ].join("\n"),
      },
    ],
    commits: [
      {
        sha: oldSha,
        files: [
          {
            filename: "src/payments.ts",
            patch: "@@ -0,0 +1,2 @@\n+const stripe = 'sk_live_ABCdef1234567890abcdef';\n",
          },
        ],
      },
    ],
  });

  const result = await scan(fixture);

  const hist = result.findings.find((f) => f.check_key === "history_secret_stripe");
  assert.ok(hist, "should detect Stripe key in recent commit history");
  assert.equal(hist.severity, "critical");
  assert.equal(hist.url, `https://github.com/${OWNER}/${REPO}/commit/${oldSha}`);
  assert.ok(!hist.evidence.includes("sk_live_ABCdef1234567890abcdef"), "historical evidence redacted");
  assert.equal(result.coverage.historyCommitsScanned, 1);

  assert.ok(result.findings.some((f) => f.check_key === "workflow_write_all_permissions"));
  assert.ok(result.findings.some((f) => f.check_key === "workflow_unpinned_action"));
});
