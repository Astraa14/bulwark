import { createHash } from "node:crypto";

export const GITHUB_API = "https://api.github.com";
export const OSV_API = "https://api.osv.dev/v1/querybatch";

export function commitSha(seed = "head") {
  return createHash("sha1").update(seed).digest("hex");
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Fake the small GitHub API surface the scanner uses: repo metadata, branch
 * head, recursive tree, and blob contents. Every request is captured so tests
 * can assert exactly what left the process.
 */
export function createGitHubFetch({
  owner = "octocat",
  repo = "Hello-World",
  files = [],
  branch = "main",
  treeTruncated = false,
  exactSha = null,
  repoStatus = 200,
  osv = null,
  osvStatus = 200,
} = {}) {
  const requests = [];
  const headSha = exactSha ?? commitSha("branch-head");
  const treeSha = commitSha("tree");
  const entries = files.map((file, index) => ({
    path: file.path,
    type: "blob",
    sha: createHash("sha1").update(`${file.path}:${index}`).digest("hex"),
    size: file.size ?? Buffer.byteLength(String(file.content ?? ""), "utf8"),
  }));
  const contentBySha = new Map(entries.map((entry, index) => [entry.sha, files[index].content ?? ""]));

  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    requests.push({
      url,
      method: init.method ?? "GET",
      headers: init.headers ?? {},
      body: init.body ?? null,
    });

    if (url === OSV_API) {
      if (osvStatus !== 200) return json({ error: "osv down" }, osvStatus);
      const body = JSON.parse(String(init.body ?? "{}"));
      const queries = Array.isArray(body.queries) ? body.queries : [];
      const results = typeof osv === "function" ? osv(queries) : (osv ?? []);
      return json({ results });
    }

    if (url === `${GITHUB_API}/repos/${owner}/${repo}`) {
      if (repoStatus !== 200) return json({ message: "Not Found" }, repoStatus);
      return json({ default_branch: branch });
    }

    if (exactSha && url === `${GITHUB_API}/repos/${owner}/${repo}/git/commits/${exactSha}`) {
      return json({ sha: exactSha, tree: { sha: treeSha } });
    }

    if (!exactSha && url === `${GITHUB_API}/repos/${owner}/${repo}/branches/${branch}`) {
      return json({
        commit: { sha: headSha, commit: { tree: { sha: treeSha } } },
      });
    }

    if (url === `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`) {
      return json({ tree: entries, truncated: treeTruncated });
    }

    if (url.startsWith(`${GITHUB_API}/repos/${owner}/${repo}/git/blobs/`)) {
      const sha = url.slice(url.lastIndexOf("/") + 1);
      if (!contentBySha.has(sha)) return json({ message: "Not Found" }, 404);
      return json({
        encoding: "base64",
        content: Buffer.from(contentBySha.get(sha), "utf8").toString("base64"),
      });
    }

    throw new Error(`Unexpected fetch: ${url}`);
  };

  return { fetchImpl, requests, headSha, treeSha, entries };
}
