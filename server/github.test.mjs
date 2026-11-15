import test from "node:test";
import assert from "node:assert/strict";
import { packagesFromPackageLock, scanGitHubRepo } from "./github.mjs";
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
