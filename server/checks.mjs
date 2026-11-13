import { connect } from "node:tls";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const UA = "BulwarkBot/0.3 (+https://bulwark.app/bot)";

// ============================================================================
// SSRF / outbound network safety
// ============================================================================

const BLOCKED_PRIVATE_PREFIXES = [
  "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
  "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
  "::1", "fc", "fd", "fe80:", "fe9", "fea", "feb", "::ffff:",
];

const ALLOWED_PORTS = new Set([80, 443]);

function isBlockedIpAddress(ip) {
  const value = String(ip ?? "").trim().toLowerCase();
  if (!value) return false;
  if (value === "localhost") return true;
  if (value.startsWith("::ffff:")) return true;
  if (value.startsWith("127.") || value === "::1") return true;
  if (value.startsWith("10.") || value.startsWith("192.168.")) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(value)) return true;
  if (value.startsWith("169.254.") || value.startsWith("fc") || value.startsWith("fd")) return true;
  if (value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) return true;
  return false;
}

export function isBlockedOutboundHost(hostname) {
  const value = String(hostname ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!value) return true;
  if (value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local")) return true;
  if (isIP(value)) return isBlockedIpAddress(value);
  return false;
}

export function isUnsafeIp(ip) {
  return isBlockedIpAddress(ip);
}

async function resolvePublicAddresses(hostname) {
  const value = String(hostname ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!value || isBlockedOutboundHost(value)) return [];
  const results = await lookup(value, { all: true });
  return results.map((entry) => entry.address);
}

/** True when the hostname resolves to a blocked/private address, or DNS fails. */
export async function hasUnsafeDns(hostname) {
  try {
    const addrs = await resolvePublicAddresses(hostname);
    return addrs.some((addr) => isBlockedIpAddress(addr));
  } catch {
    return true;
  }
}

async function ensureSafeFetchUrl(urlString) {
  const parsed = new URL(urlString);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Blocked outbound target: unsupported protocol ${parsed.protocol}`);
  }

  const host = parsed.hostname.replace(/\.$/, "").toLowerCase();
  if (isBlockedOutboundHost(host)) {
    throw new Error(`Blocked outbound target: ${host}`);
  }

  const port = Number(parsed.port) || (parsed.protocol === "https:" ? 443 : 80);
  if (!ALLOWED_PORTS.has(port)) {
    throw new Error(`Blocked outbound target: port ${port} is not allowed`);
  }

  const resolved = await resolvePublicAddresses(host);
  if (resolved.some((addr) => isBlockedIpAddress(addr))) {
    throw new Error(`Blocked outbound target: ${host}`);
  }

  return parsed.toString();
}

const MAX_BODY_BYTES = 4_000_000;

/** @typedef {Object} FetchResult
 * @property {boolean} ok
 * @property {number|null} status
 * @property {Record<string,string>} headers
 * @property {string|null} body
 * @property {string|null} url
 * @property {string|null} error
 * @property {boolean} redirected
 */

async function readBodyBounded(res, maxBytes = MAX_BODY_BYTES) {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > maxBytes) {
        reader.releaseLock();
        throw new Error(`Response body exceeds ${maxBytes} byte limit`);
      }
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  return buffer.toString("utf8");
}

/**
 * @param {string} urlString
 * @param {{timeout?:number, method?:string, headers?:Object, maxRedirects?:number}} opts
 * @returns {Promise<FetchResult>}
 */
async function fetchWithTimeout(urlString, opts = {}) {
  const { timeout = 15000, method = "GET", headers = {}, maxRedirects = 3 } = opts;

  let current = await ensureSafeFetchUrl(urlString);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let redirected = false;

  try {
    let redirectCount = 0;
    while (true) {
      const res = await fetch(current, {
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": UA, accept: "*/*", ...headers },
      });

      const headerList = {};
      res.headers.forEach((value, key) => {
        headerList[key] = value;
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (location && redirectCount < maxRedirects) {
          redirectCount += 1;
          redirected = true;
          current = await ensureSafeFetchUrl(new URL(location, current).toString());
          await res.body?.cancel();
          continue;
        }
        // Consume and discard the redirect response body.
        try {
          await readBodyBounded(res);
        } catch {
          // Ignore body read errors on terminal redirect responses.
        }
        return {
          ok: res.ok,
          status: res.status,
          headers: headerList,
          body: null,
          url: res.url,
          error: null,
          redirected,
        };
      }

      const body = await readBodyBounded(res);
      return {
        ok: res.ok,
        status: res.status,
        headers: headerList,
        body,
        url: res.url,
        error: null,
        redirected,
      };
    }
  } catch (err) {
    return {
      ok: false,
      status: null,
      headers: {},
      body: null,
      url: current,
      error: err?.message ?? String(err),
      redirected,
    };
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// Check outcome model
// ============================================================================

// outcome: "pass" | "finding" | "error" | "not_checked"
// A check must never infer "pass" from an empty findings array when it errored.

function checkResult(key, outcome, findings = [], error = null) {
  return { key, outcome, findings, error };
}

async function runCheck(key, fn) {
  try {
    const { findings, error } = await fn();
    const outcome = error ? "error" : findings.length ? "finding" : "pass";
    return checkResult(key, outcome, findings, error ?? null);
  } catch (err) {
    return checkResult(key, "error", [], err?.message ?? String(err));
  }
}

// ============================================================================
// Detectors
// ============================================================================

const SECURITY_HEADERS = [
  {
    key: "strict-transport-security",
    check: "header_hsts",
    title: "Missing HSTS header",
    severity: "medium",
    detail:
      "Strict-Transport-Security is not set, so browsers may fall back to plain HTTP on the first visit.",
  },
  {
    key: "content-security-policy",
    check: "header_csp",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    detail: "No CSP means injected scripts run freely. It is the strongest single defence against XSS.",
  },
  {
    key: "x-content-type-options",
    check: "header_nosniff",
    title: "Missing X-Content-Type-Options",
    severity: "low",
    detail: "Without 'nosniff', browsers may MIME-sniff responses and execute unexpected content.",
  },
  {
    key: "referrer-policy",
    check: "header_referrer",
    title: "Missing Referrer-Policy",
    severity: "low",
    detail: "URLs can leak to third parties through the Referer header.",
  },
];

const EXPOSED_FILES = [
  {
    path: "/.env",
    check: "exposed_env",
    title: "Exposed .env file",
    severity: "critical",
    detail: "Your environment file is publicly readable. Rotate every secret it contains.",
    matches: (body) => /^[A-Z0-9_]+=/m.test(body),
  },
  {
    path: "/.env.local",
    check: "exposed_env_local",
    title: "Exposed .env.local file",
    severity: "critical",
    detail: "Local environment secrets are publicly readable. Rotate them now.",
    matches: (body) => /^[A-Z0-9_]+=/m.test(body),
  },
  {
    path: "/.git/config",
    check: "exposed_git",
    title: "Exposed .git directory",
    severity: "critical",
    detail:
      "Your repository metadata is public. Attackers can reconstruct source code and find credentials in history.",
    matches: (body) => body.includes("[core]"),
  },
  {
    path: "/.DS_Store",
    check: "exposed_ds_store",
    title: "Exposed .DS_Store file",
    severity: "low",
    detail: "macOS metadata leaks directory and file names.",
    matches: (body) => body.startsWith("Bud1") || body.includes("\u0000\u0000\u0000\u0001Bud1"),
  },
  {
    path: "/backup.sql",
    check: "exposed_backup_sql",
    title: "Exposed database backup",
    severity: "critical",
    detail: "A SQL dump is downloadable. Assume the data is already compromised.",
    matches: (body) => /create table|insert into/i.test(body),
  },
  {
    path: "/db.sql",
    check: "exposed_db_sql",
    title: "Exposed database dump",
    severity: "critical",
    detail: "A SQL dump is downloadable. Assume the data is already compromised.",
    matches: (body) => /create table|insert into/i.test(body),
  },
  {
    path: "/phpinfo.php",
    check: "exposed_phpinfo",
    title: "Exposed phpinfo() page",
    severity: "high",
    detail: "phpinfo() discloses server paths, modules, and environment values.",
    matches: (body) => /php version|phpinfo\(\)/i.test(body),
  },
];

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
];

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
  "co.jp", "com.br", "co.in", "com.sg", "com.mx", "co.za", "com.tr", "com.hk", "co.kr",
]);

function finding(check_key, title, severity, detail, extra = {}) {
  return { check_key, title, severity, detail, ...extra };
}

function normalizeDomain(input) {
  return String(input || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
}

function registrableDomain(domain) {
  const parts = String(domain).split(".").filter(Boolean);
  if (parts.length <= 2) return domain;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function isIpOrLocal(domain) {
  return /^((\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+)$/.test(domain) || domain === "localhost" || domain.endsWith(".local");
}

async function safeFetch(url, timeout = 8000) {
  const res = await fetchWithTimeout(url, { timeout });
  if (res.error) return { found: false, error: res.error };
  if (res.status === null) return { found: false, error: "no response" };
  if (res.status === 404) return { found: false };
  if (res.status !== 200) {
    return { found: false, error: `HTTP ${res.status}` };
  }
  return { found: true, body: res.body ?? "", contentType: res.headers["content-type"] ?? "" };
}

async function checkExposedFilesInner(domain) {
  const findings = [];
  const errors = [];
  await Promise.all(
    EXPOSED_FILES.map(async (file) => {
      const res = await fetchWithTimeout(`https://${domain}${file.path}`, { timeout: 8000 });
      if (res.error) {
        errors.push(`${file.path}: ${res.error}`);
        return;
      }
      if (res.status === null || res.status !== 200) return;
      const body = res.body ?? "";
      if (!file.matches(body)) return;
      findings.push(
        finding(file.check, file.title, file.severity, file.detail, {
          url: `https://${domain}${file.path}`,
          evidence: `${res.status} ${res.headers["content-type"] ?? "unknown"} · ${body.length} bytes`,
        }),
      );
    }),
  );
  return { findings, error: errors.length ? errors.join("; ") : null };
}

function checkHeaders(headers) {
  const out = [];
  for (const h of SECURITY_HEADERS) {
    if (!headers[h.key]) {
      out.push(finding(h.check, h.title, h.severity, h.detail));
    }
  }
  const server = headers["server"] ?? "";
  if (/\d/.test(server)) {
    out.push(
      finding(
        "server_banner",
        "Server version disclosed",
        "low",
        "The Server header reveals software and version, which helps attackers target known CVEs.",
        { evidence: server },
      ),
    );
  }
  return out;
}

function checkCspQuality(headers) {
  const csp = headers["content-security-policy"];
  if (!csp) return [];
  const out = [];
  const lower = csp.toLowerCase();
  if (lower.includes("'unsafe-inline'")) {
    out.push(
      finding(
        "csp_unsafe_inline",
        "CSP allows unsafe-inline",
        "medium",
        "Your Content-Security-Policy permits inline scripts, so an injected <script> still runs and the policy gives little XSS protection.",
        { evidence: csp.slice(0, 220) },
      ),
    );
  }
  if (lower.includes("'unsafe-eval'")) {
    out.push(
      finding(
        "csp_unsafe_eval",
        "CSP allows unsafe-eval",
        "medium",
        "eval() and Function() stay available to any injected code, which is a common malware execution path.",
        { evidence: csp.slice(0, 220) },
      ),
    );
  }
  if (/(script-src|default-src)[^;]*\s\*\s*(;|$)/.test(lower)) {
    out.push(
      finding(
        "csp_wildcard",
        "CSP allows scripts from any origin",
        "high",
        "A wildcard source in script-src or default-src lets an attacker load scripts from a domain they control.",
        { evidence: csp.slice(0, 220) },
      ),
    );
  }
  return out;
}

async function checkCorsInner(domain) {
  const findings = [];
  const probeOrigin = "https://bulwark-cors-probe.example";
  const res = await fetchWithTimeout(`https://${domain}/`, {
    timeout: 10000,
    headers: { origin: probeOrigin },
  });
  if (res.error) return { findings, error: res.error };
  if (res.status === null) return { findings, error: "no response from CORS probe" };
  const allow = res.headers["access-control-allow-origin"];
  const credentials = (res.headers["access-control-allow-credentials"] ?? "").toLowerCase();
  if (!allow) return { findings, error: null };
  if (allow === "*" && credentials === "true") {
    findings.push(
      finding(
        "cors_wildcard_credentials",
        "CORS allows any origin with credentials",
        "high",
        "Any website can read authenticated responses from your API, which exposes user data cross-site.",
        { evidence: "access-control-allow-origin: * · allow-credentials: true" },
      ),
    );
  } else if (allow === probeOrigin) {
    findings.push(
      finding(
        "cors_reflects_origin",
        "CORS reflects any origin",
        "medium",
        "The server echoes back whatever Origin it receives. Combined with cookies, any site can read your users' data.",
        { evidence: `access-control-allow-origin: ${allow}` },
      ),
    );
  } else if (allow === "*") {
    findings.push(
      finding(
        "cors_wildcard",
        "CORS is open to every origin",
        "low",
        "Public cross-origin reads are allowed. Fine for a public API, risky if any response contains private data.",
        { evidence: "access-control-allow-origin: *" },
      ),
    );
  }
  return { findings, error: null };
}

function checkCookies(headers) {
  const raw = Array.isArray(headers["set-cookie"])
    ? headers["set-cookie"]
    : headers["set-cookie"]
    ? [headers["set-cookie"]]
    : [];
  if (!raw.length) return [];
  const problems = [];
  for (const cookie of raw) {
    const name = cookie.split("=")[0]?.trim() ?? "cookie";
    const lower = cookie.toLowerCase();
    const sensitive = /session|token|auth|sid|jwt|refresh/i.test(name);
    if (!lower.includes("secure")) problems.push(`${name} missing Secure`);
    if (sensitive && !lower.includes("httponly")) problems.push(`${name} missing HttpOnly`);
    if (!lower.includes("samesite")) problems.push(`${name} missing SameSite`);
  }
  if (!problems.length) return [];
  const severe = problems.some((p) => p.includes("HttpOnly"));
  return [
    finding(
      "cookie_flags",
      "Cookie security flags are incomplete",
      severe ? "high" : "medium",
      severe
        ? "A session-style cookie can be read by JavaScript, so a single XSS becomes full account takeover."
        : "Cookies without Secure or SameSite can leak over plain HTTP or be sent on cross-site requests.",
      { evidence: problems.slice(0, 6).join(" · ") },
    ),
  ];
}

function checkMixedContent(html, finalUrl) {
  if (!html) return [];
  const insecure = [...html.matchAll(/(?:src|href)=["']http:\/\/([^"']+)/gi)]
    .map((m) => m[1])
    .filter((u) => !/^localhost|^127\.0\.0\.1/.test(u));
  if (!insecure.length) return [];
  return [
    finding(
      "mixed_content",
      "Mixed content on an HTTPS page",
      "low",
      `${insecure.length} resource(s) load over plain HTTP and can be tampered with in transit.`,
      { url: finalUrl, evidence: insecure.slice(0, 5).join(", ") },
    ),
  ];
}

function checkDirectoryListing(html) {
  if (!html) return [];
  if (/<title>\s*index of \//i.test(html)) {
    return [
      finding(
        "directory_listing",
        "Directory listing enabled",
        "medium",
        "The web server lists directory contents, exposing files that were not meant to be browsable.",
      ),
    ];
  }
  return [];
}

async function checkDiscoveryInner(domain) {
  const findings = [];
  const errors = [];
  const [robots, sitemap, securityTxt, securityTxtAlt] = await Promise.all([
    safeFetch(`https://${domain}/robots.txt`),
    safeFetch(`https://${domain}/sitemap.xml`),
    safeFetch(`https://${domain}/.well-known/security.txt`),
    safeFetch(`https://${domain}/security.txt`),
  ]);

  const record = (res, label) => {
    if (res.error) errors.push(`${label}: ${res.error}`);
    return res;
  };
  record(robots, "robots.txt");
  record(sitemap, "sitemap.xml");
  record(securityTxt, "security.txt");

  if (!robots.error && !robots.found) {
    findings.push(
      finding(
        "robots_missing",
        "No robots.txt",
        "info",
        "Search engines and bots have no guidance. Not a vulnerability on its own.",
        { url: `https://${domain}/robots.txt` },
      ),
    );
  } else if (robots.found) {
    const paths = [...robots.body.matchAll(/^\s*(?:disallow|allow):\s*(\/\S*)/gim)]
      .map((m) => m[1])
      .filter((p) => /\/(admin|config|backup|private|db|sql|env|secret|internal|staging)/i.test(p));
    if (paths.length) {
      findings.push(
        finding(
          "robots_sensitive_paths",
          "robots.txt points at sensitive paths",
          "low",
          "robots.txt publicly lists internal-looking paths, which acts as a map for attackers. Do not rely on it to hide anything.",
          { url: `https://${domain}/robots.txt`, evidence: paths.slice(0, 6).join(", ") },
        ),
      );
    }
  }

  if (!sitemap.error && !sitemap.found) {
    findings.push(
      finding(
        "sitemap_missing",
        "No sitemap.xml",
        "info",
        "A sitemap helps search engines find your pages. Missing is normal for apps.",
        { url: `https://${domain}/sitemap.xml` },
      ),
    );
  } else if (sitemap.found && !/<(urlset|sitemapindex)[\s>]/i.test(sitemap.body)) {
    findings.push(
      finding(
        "sitemap_invalid",
        "sitemap.xml is not a sitemap",
        "low",
        "The sitemap URL returns something that is not a sitemap document, which confuses crawlers and may expose a fallback page.",
        { url: `https://${domain}/sitemap.xml` },
      ),
    );
  }

  const security = securityTxt.found ? securityTxt : securityTxtAlt.found ? securityTxtAlt : null;
  const securityUrl = security === securityTxt
    ? `https://${domain}/.well-known/security.txt`
    : `https://${domain}/security.txt`;
  if (!security) {
    findings.push(
      finding(
        "security_txt_missing",
        "No security.txt",
        "low",
        "Researchers have no published way to report a vulnerability, so reports may go nowhere.",
        { url: `https://${domain}/.well-known/security.txt` },
      ),
    );
  } else if (!/^\s*contact\s*:/im.test(security.body)) {
    findings.push(
      finding(
        "security_txt_invalid",
        "security.txt has no Contact field",
        "medium",
        "A security.txt without a Contact line cannot be used to report issues.",
        { url: securityUrl },
      ),
    );
  }

  return { findings, error: errors.length ? errors.join("; ") : null };
}

function redactSecret(value) {
  const s = String(value);
  if (s.length <= 10) return "••••";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function decodeJwtRole(token) {
  try {
    const payload = token.split(".")[1];
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return typeof json.role === "string" ? json.role : null;
  } catch {
    return null;
  }
}

function scanTextForSecrets(text, sourceUrl) {
  const out = [];
  if (!text) return out;
  for (const pattern of SECRET_PATTERNS) {
    pattern.re.lastIndex = 0;
    const match = pattern.re.exec(text);
    if (!match) continue;
    out.push(
      finding(
        pattern.key,
        `${pattern.name} exposed in client code`,
        pattern.severity,
        "A secret is shipped to the browser, so anyone can copy it and use it against your account or infrastructure. Revoke it, then move the call behind your server.",
        {
          url: sourceUrl,
          evidence: `${redactSecret(match[0])} · found in ${sourceUrl.split("/").pop() || sourceUrl}`,
        },
      ),
    );
  }
  const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
  for (const match of text.matchAll(jwtRe)) {
    if (decodeJwtRole(match[0]) === "service_role") {
      out.push(
        finding(
          "secret_supabase_service_role",
          "Supabase service_role key exposed",
          "critical",
          "The service_role key bypasses Row Level Security for your entire database. Treat every table as public until it is rotated.",
          {
            url: sourceUrl,
            evidence: `${redactSecret(match[0])} · role: service_role`,
          },
        ),
      );
      break;
    }
  }
  return out;
}

function collectScriptUrls(html, pageUrl) {
  if (!html) return [];
  const urls = new Set();
  const push = (raw) => {
    if (!raw) return;
    try {
      const resolved = new URL(raw, pageUrl);
      if (!/^https?:$/.test(resolved.protocol)) return;
      urls.add(resolved.toString());
    } catch {
      // Ignore malformed references.
    }
  };
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) push(m[1]);
  for (const m of html.matchAll(/<link[^>]+href=["']([^"']+\.js(?:\?[^"']*)?)["']/gi)) push(m[1]);
  return [...urls];
}

async function checkLeakedSecretsInner(domain, page) {
  const findings = [];
  const errors = [];
  const seen = new Set();
  const add = (items) => {
    for (const item of items) {
      if (seen.has(item.check_key)) continue;
      seen.add(item.check_key);
      findings.push(item);
    }
  };
  add(scanTextForSecrets(page.body, page.finalUrl));

  const pageHost = new URL(page.finalUrl).host;
  const candidates = collectScriptUrls(page.body, page.finalUrl)
    .filter((url) => {
      try {
        return new URL(url).host === pageHost;
      } catch {
        return false;
      }
    })
    .slice(0, 6);

  const bundleResults = await Promise.all(
    candidates.map(async (url) => {
      const res = await safeFetch(url, 12000);
      if (res.error) {
        errors.push(`${url}: ${res.error}`);
        return null;
      }
      if (!res.found) return null;
      if (!res.body || res.body.length > 4_000_000) return null;
      return { url, body: res.body };
    }),
  );

  for (const bundle of bundleResults) {
    if (!bundle) continue;
    add(scanTextForSecrets(bundle.body, bundle.url));
  }

  return { findings, error: errors.length ? errors.join("; ") : null };
}

let rdapBootstrapCache = { cached: false, error: null, services: [] };

async function rdapBaseUrl(tld) {
  if (!rdapBootstrapCache.cached) {
    try {
      const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", { timeout: 12000 });
      if (res.error) {
        rdapBootstrapCache = { cached: true, error: res.error, services: [] };
      } else if (res.status === null || res.status !== 200) {
        rdapBootstrapCache = {
          cached: true,
          error: res.status === null ? "no response" : `HTTP ${res.status}`,
          services: [],
        };
      } else {
        rdapBootstrapCache = JSON.parse(res.body ?? "{}");
        rdapBootstrapCache.cached = true;
      }
    } catch (err) {
      rdapBootstrapCache = {
        cached: true,
        error: err?.message ?? String(err),
        services: [],
      };
    }
  }
  if (rdapBootstrapCache.error) return null;
  const services = rdapBootstrapCache.services ?? [];
  for (const entry of services) {
    const [tlds, urls] = entry;
    if (Array.isArray(tlds) && tlds.includes(tld) && urls?.length) return urls[0];
  }
  return null;
}

async function checkDomainExpiryInner(domain) {
  const findings = [];
  const errors = [];
  if (isIpOrLocal(domain)) return { findings, error: null };
  const registrable = registrableDomain(domain);
  const tld = registrable.split(".").pop();

  let expiration = null;
  const bases = [];
  const iana = await rdapBaseUrl(tld);
  if (iana) bases.push(iana);
  if (tld === "com" || tld === "net") bases.push(`https://rdap.verisign.com/${tld}/v1/`);

  let rdapError = null;
  for (const base of bases) {
    try {
      const res = await fetchWithTimeout(
        `${base.replace(/\/$/, "")}/domain/${registrable}`,
        { timeout: 12000, headers: { accept: "application/rdap+json" } },
      );
      if (res.error) {
        rdapError = res.error;
        continue;
      }
      if (res.status === null || !res.ok) {
        rdapError = res.status === null ? "no response" : `HTTP ${res.status}`;
        continue;
      }
      const json = JSON.parse(res.body ?? "{}");
      expiration = (json.events ?? []).find((e) => e.eventAction === "expiration")?.eventDate;
      if (expiration) break;
    } catch (err) {
      rdapError = err?.message ?? String(err);
      continue;
    }
  }

  if (!expiration) {
    if (rdapError || rdapBootstrapCache.error) {
      errors.push(rdapError ?? rdapBootstrapCache.error);
    }
    return { findings, error: errors.length ? errors.join("; ") : null };
  }
  const days = Math.round((new Date(expiration).getTime() - Date.now()) / 86_400_000);

  if (days < 0) {
    findings.push(
      finding(
        "domain_expired",
        "Domain registration expired",
        "critical",
        "The domain has lapsed. Anyone can register it and take over your traffic and email.",
        { evidence: `Expired ${Math.abs(days)} day(s) ago · ${expiration}` },
      ),
    );
  } else if (days <= 14) {
    findings.push(
      finding(
        "domain_expiring",
        "Domain expires within 14 days",
        "high",
        "If renewal fails the site and its email stop working, and the domain can be snapped up by someone else.",
        { evidence: `Expires in ${days} day(s) · ${expiration}` },
      ),
    );
  } else if (days <= 45) {
    findings.push(
      finding(
        "domain_expiring_soon",
        "Domain expires within 45 days",
        "medium",
        "Renew now so an expired card cannot take the site offline.",
        { evidence: `Expires in ${days} day(s) · ${expiration}` },
      ),
    );
  }
  return { findings, error: null };
}

async function dohQuery(name, type) {
  const res = await fetchWithTimeout(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { timeout: 9000, headers: { accept: "application/dns-json" } },
  );
  if (res.error) return { records: null, error: res.error };
  if (res.status === null || !res.ok) {
    return { records: null, error: res.status === null ? "no response" : `HTTP ${res.status}` };
  }
  const json = JSON.parse(res.body ?? "{}");
  if (json.Status !== 0) return { records: [], error: null };
  return { records: json.Answer ?? [], error: null };
}

async function checkDnsInner(domain) {
  const findings = [];
  const errors = [];
  if (isIpOrLocal(domain)) return { findings, error: null };
  const registrable = registrableDomain(domain);

  const [nsResult, mxResult] = await Promise.all([
    dohQuery(registrable, "NS"),
    dohQuery(registrable, "MX"),
  ]);

  if (nsResult.error) errors.push(`DNS NS lookup: ${nsResult.error}`);
  else if (nsResult.records && nsResult.records.length === 0) {
    findings.push(
      finding(
        "dns_no_ns",
        "No nameservers returned",
        "high",
        "The domain has no NS records, which usually means DNS is misconfigured or the domain is suspended.",
        { evidence: registrable },
      ),
    );
  }
  if (mxResult.error) errors.push(`DNS MX lookup: ${mxResult.error}`);
  else if (mxResult.records && mxResult.records.length === 0) {
    findings.push(
      finding(
        "dns_no_mx",
        "No mail records (MX)",
        "info",
        "The domain cannot receive email. Fine if you never plan to, a problem for password resets and reports.",
        { evidence: registrable },
      ),
    );
  }
  return { findings, error: errors.length ? errors.join("; ") : null };
}

function visibleText(html) {
  return String(html ?? "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&[a-z]+;/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function tokenSet(text) {
  return new Set((text.match(/[a-z0-9]{3,}/g) ?? []).slice(0, 5000));
}

function jaccard(a, b) {
  if (!a.size || !b.size) return 1;
  let overlap = 0;
  for (const token of a) if (b.has(token)) overlap += 1;
  return overlap / (a.size + b.size - overlap);
}

export function pageSampleFromHtml(html) {
  const title = (String(html ?? "").match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200);
  const text = visibleText(html).slice(0, 6000);
  return JSON.stringify({ title, text, at: new Date().toISOString() });
}

function checkDefacement(html, baselineJson) {
  const out = [];
  const lower = String(html ?? "").toLowerCase();
  const marker = lower.match(/(hacked by|defaced by|pwned by|you have been hacked|_hacked|owned by [a-z0-9_]+)/);
  if (marker) {
    out.push(
      finding(
        "defacement_marker",
        "Defacement text on the homepage",
        "critical",
        "The homepage contains language typical of a defacement. Treat this as an active compromise.",
        { evidence: marker[0].slice(0, 80) },
      ),
    );
  }

  const sample = JSON.parse(pageSampleFromHtml(html));
  if (sample.text.length < 60) return { findings: out, sample, similarity: 1 };

  let similarity = 1;
  if (baselineJson) {
    try {
      const baseline = JSON.parse(baselineJson);
      if (baseline?.text && baseline.text.length >= 60) {
        similarity = jaccard(tokenSet(baseline.text), tokenSet(sample.text));
        if (similarity < 0.55) {
          out.push(
            finding(
              "content_replaced",
              "Homepage content changed dramatically",
              "high",
              "Most of the homepage text was replaced since the last scan. That is how defacement, a hijacked deployment, or a malicious redirect starts.",
              {
                evidence: `Only ${Math.round(similarity * 100)}% of the previous page text is still present${
                  baseline.title ? ` · was "${baseline.title}"` : ""
                }`,
              },
            ),
          );
        }
      }
    } catch {
      // Unreadable baseline: treat as first scan.
    }
  }

  return { findings: out, sample, similarity };
}

export async function fetchPageSample(domain) {
  const page = await checkUptime(normalizeDomain(domain));
  if (!page.ok) throw new Error("The site did not respond, so it could not be baselined.");
  return pageSampleFromHtml(page.body);
}

// ============================================================================
// Individual checks (single-request, gating, etc.)
// ============================================================================

export async function checkUptime(domain) {
  const start = Date.now();
  const res = await fetchWithTimeout(`https://${domain}/`);
  const responseMs = Date.now() - start;
  if (res.error) {
    return { ok: false, error: res.error, responseMs };
  }
  if (res.status === null) {
    return { ok: false, error: "no response", responseMs };
  }
  return {
    ok: true,
    status: res.status,
    responseMs,
    body: res.body ?? "",
    headers: res.headers,
    finalUrl: res.url ?? `https://${domain}/`,
  };
}

export function checkTls(domain) {
  return new Promise((resolve) => {
    const normalized = String(domain ?? "").trim().toLowerCase().replace(/\.$/, "");
    if (isBlockedOutboundHost(normalized)) {
      return resolve({ error: `Blocked TLS target: ${normalized}` });
    }
    // Pre-resolve and validate addresses before opening the socket so the
    // connection cannot be redirected to a blocked address via DNS changes.
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    lookup(normalized, { all: true })
      .then((results) => {
        const blocked = results.some((entry) => isBlockedIpAddress(entry.address));
        if (blocked) {
          return finish({ error: `Blocked TLS target: ${normalized}` });
        }
        const socket = connect(
          { host: normalized, port: 443, servername: normalized, timeout: 10000 },
          () => {
            const cert = socket.getPeerCertificate();
            socket.end();
            if (!cert?.valid_to) return finish(null);
            const expires = new Date(cert.valid_to);
            const days = Math.round((expires.getTime() - Date.now()) / 86_400_000);
            finish({
              days,
              validTo: cert.valid_to,
              issuer: cert.issuer?.O ?? cert.issuer?.CN ?? "unknown",
              subject: cert.subject?.CN ?? domain,
            });
          },
        );
        socket.on("error", () => finish(null));
        socket.on("timeout", () => {
          socket.destroy();
          finish(null);
        });
      })
      .catch(() => finish({ error: `DNS resolution failed for: ${normalized}` }));
  });
}

// ============================================================================
// Orchestrator
// ============================================================================

export async function runChecks(rawDomain, { baseline = null } = {}) {
  const domain = normalizeDomain(rawDomain);
  const findings = [];
  const start = Date.now();
  const checkResults = {};

  const register = (key, outcome, error = null) => {
    checkResults[key] = outcome;
  };

  // --- Gating check: site uptime ---
  const page = await checkUptime(domain);
  if (!page.ok) {
    register("site_uptime", "error", page.error);
    findings.push(
      finding(
        "site_unreachable",
        "Site unreachable",
        "critical",
        "The site did not respond over HTTPS within 15 seconds.",
        { evidence: page.error },
      ),
    );
    return {
      domain,
      status: "failed",
      httpStatus: null,
      responseMs: page.responseMs,
      checksTotal: 1,
      checksPassed: 0,
      checksErrored: 1,
      checksSkipped: 0,
      checkResults,
      findings,
      error: page.error,
    };
  }
  register("site_uptime", "pass");

  // --- HTTP status ---
  if (page.status >= 500) {
    register("http_status", "finding");
    findings.push(
      finding("http_5xx", "Server error on the homepage", "critical", "The homepage returned a 5xx error.", {
        evidence: `HTTP ${page.status}`,
      }),
    );
  } else if (page.status >= 400) {
    register("http_status", "finding");
    findings.push(
      finding("http_4xx", "Homepage returned an error status", "high", "The homepage is not serving successfully.", {
        evidence: `HTTP ${page.status}`,
      }),
    );
  } else {
    register("http_status", "pass");
  }

  // --- Response time ---
  if (page.responseMs > 3000) {
    register("response_time", "finding");
    findings.push(
      finding("slow_response", "Slow homepage response", "low", "The homepage took over 3 seconds to respond.", {
        evidence: `${page.responseMs} ms`,
      }),
    );
  } else {
    register("response_time", "pass");
  }

  // --- TLS ---
  const tls = await checkTls(domain);
  if (tls.error) {
    register("tls", "error", tls.error);
    findings.push(
      finding("tls_unavailable", "TLS certificate could not be read", "high", "Could not establish a TLS session to read the certificate."),
    );
  } else if (!tls) {
    register("tls", "error", "TLS connection returned no certificate data");
    findings.push(
      finding("tls_unavailable", "TLS certificate could not be read", "high", "Could not establish a TLS session to read the certificate."),
    );
  } else if (tls.days < 0) {
    register("tls", "finding");
    findings.push(
      finding("tls_expired", "TLS certificate expired", "critical", "Browsers will show a full-page warning to every visitor.", {
        evidence: `Expired ${Math.abs(tls.days)} day(s) ago · ${tls.validTo}`,
      }),
    );
  } else if (tls.days <= 14) {
    register("tls", "finding");
    findings.push(
      finding("tls_expiring", "TLS certificate expires soon", "high", `Certificate expires in ${tls.days} day(s).`, {
        evidence: `${tls.validTo} · issued by ${tls.issuer}`,
      }),
    );
  } else if (tls.days <= 30) {
    register("tls", "finding");
    findings.push(
      finding("tls_expiring_soon", "TLS certificate expires within 30 days", "medium", `Certificate expires in ${tls.days} day(s).`, {
        evidence: `${tls.validTo} · issued by ${tls.issuer}`,
      }),
    );
  } else {
    register("tls", "pass");
  }

  // --- Header-based checks (no network beyond the page already fetched) ---
  const headersFindings = checkHeaders(page.headers);
  findings.push(...headersFindings);
  register("security_headers", headersFindings.length ? "finding" : "pass");

  const cspFindings = checkCspQuality(page.headers);
  findings.push(...cspFindings);
  register("csp_policy", cspFindings.length ? "finding" : "pass");

  const cookieFindings = checkCookies(page.headers);
  findings.push(...cookieFindings);
  register("cookies", cookieFindings.length ? "finding" : "pass");

  const mixedContentFindings = checkMixedContent(page.body, page.finalUrl);
  findings.push(...mixedContentFindings);
  register("mixed_content", mixedContentFindings.length ? "finding" : "pass");

  const directoryFindings = checkDirectoryListing(page.body);
  findings.push(...directoryFindings);
  register("directory_listing", directoryFindings.length ? "finding" : "pass");

  const defacement = checkDefacement(page.body, baseline);
  findings.push(...defacement.findings);
  register("defacement", defacement.findings.length ? "finding" : "pass");

  // --- Parallel network checks ---
  const [
    exposedResult,
    corsResult,
    discoveryResult,
    secretsResult,
    domainExpiryResult,
    dnsResult,
  ] = await Promise.all([
    runCheck("exposed_files", () => checkExposedFilesInner(domain)),
    runCheck("cors", () => checkCorsInner(domain)),
    runCheck("public_discovery", () => checkDiscoveryInner(domain)),
    runCheck("secrets", () => checkLeakedSecretsInner(domain, page)),
    runCheck("domain_registration", () => checkDomainExpiryInner(domain)),
    runCheck("dns", () => checkDnsInner(domain)),
  ]);

  for (const r of [exposedResult, corsResult, discoveryResult, secretsResult, domainExpiryResult, dnsResult]) {
    findings.push(...r.findings);
    register(r.key, r.outcome, r.error ?? null);
  }

  // Deduplicate by check_key (keep first occurrence).
  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    if (seen.has(f.check_key)) continue;
    seen.add(f.check_key);
    unique.push(f);
  }

  const checksPassed = Object.values(checkResults).filter((v) => v === "pass").length;
  const checksErrored = Object.values(checkResults).filter((v) => v === "error").length;
  const checksSkipped = Object.values(checkResults).filter((v) => v === "not_checked").length;
  const checksTotal = Object.keys(checkResults).length;

  const status = checksErrored || checksSkipped ? "partial" : "completed";

  return {
    domain,
    status,
    httpStatus: page.status,
    responseMs: page.responseMs,
    checksTotal,
    checksPassed,
    checksErrored,
    checksSkipped,
    checkResults,
    findings: unique,
    tls,
    pageSample: defacement.sample,
    defacementSimilarity: defacement.similarity,
    durationMs: Date.now() - start,
  };
}

export { normalizeDomain, ensureSafeFetchUrl, fetchWithTimeout };
