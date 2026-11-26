import { connect } from "node:tls";
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { WEBSITE_CHECK_LABELS } from "./check-groups.mjs";

const UA = "BulwarkBot/0.3 (+https://bulwark.app/bot)";

/** Captured once so a test stub can be told apart from undici's real fetch. */
const nativeFetch = globalThis.fetch;

// ============================================================================
// SSRF / outbound network safety
// ============================================================================

/**
 * Every non-public address family we refuse to connect to. Prefix lengths are
 * exact, so 100.64.0.0/10 (CGNAT) is not accidentally read as 100.0.0.0/8 and
 * 172.16.0.0/12 does not spill into 172.32.0.0.
 */
const BLOCKED_V4_RANGES = [
  ["0.0.0.0", 8], // "this network", includes 0.0.0.0 and 0.x.y.z
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, cloud metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, includes 255.255.255.255
];

const ALLOWED_PORTS = new Set([80, 443]);

function ipv4ToInt(value) {
  const parts = String(value ?? "").split(".");
  if (parts.length !== 4) return null;
  let total = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    total = total * 256 + octet;
  }
  return total >>> 0;
}

function isBlockedV4(value) {
  const ip = ipv4ToInt(value);
  if (ip === null) return true;
  return BLOCKED_V4_RANGES.some(([base, bits]) => {
    const baseInt = ipv4ToInt(base);
    if (baseInt === null) return true;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ip & mask) === (baseInt & mask);
  });
}

function isBlockedV6(value) {
  const ip = String(value ?? "").toLowerCase();
  if (!ip) return true;
  if (ip === "::" || ip === "::1" || ip === "0:0:0:0:0:0:0:0" || ip === "0:0:0:0:0:0:0:1") {
    return true;
  }
  if (ip.startsWith("::ffff:")) return true; // IPv4-mapped
  if (ip.startsWith("64:ff9b:") || ip.startsWith("64:ff9b::")) return true; // NAT64
  if (/^f[cd]/.test(ip)) return true; // unique local fc00::/7
  if (/^fe[89ab]/.test(ip)) return true; // link-local fe80::/10
  if (/^ff/.test(ip)) return true; // multicast
  return false;
}

/** True for any address that must never be dialled by this service. */
function isBlockedIpAddress(ip) {
  let value = String(ip ?? "").trim().toLowerCase();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const zone = value.indexOf("%");
  if (zone >= 0) value = value.slice(0, zone);
  if (!value) return true;
  if (value === "localhost") return true;
  const family = isIP(value);
  if (family === 4) return isBlockedV4(value);
  if (family === 6) return isBlockedV6(value);
  // Not an IP literal. Hostnames are checked by isBlockedOutboundHost and by
  // the resolver; an unparsable value must not be treated as safe to dial.
  return true;
}

export function isBlockedOutboundHost(hostname) {
  const value = String(hostname ?? "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[|\]$/g, "");
  if (!value) return true;
  if (value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local")) {
    return true;
  }
  if (isIP(value)) return isBlockedIpAddress(value);
  // Public DNS names always contain a dot. "0", "metadata" and "intranet"
  // resolve through search domains or /etc/hosts, never through public DNS.
  if (!value.includes(".")) return true;
  if (value.endsWith(".internal") || value.endsWith(".home.arpa")) return true;
  return false;
}

export function isUnsafeIp(ip) {
  // Used on hostnames as well as literals (redirect targets), so this covers
  // blocked literals, local names and single-label hosts.
  return isBlockedOutboundHost(ip);
}

async function resolvePublicAddresses(hostname, lookupFn = lookup) {
  const value = String(hostname ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!value || isBlockedOutboundHost(value)) return [];
  const results = await lookupFn(value, { all: true });
  return results.map((entry) => entry.address);
}

/** True when the hostname resolves to a blocked/private address, or DNS fails. */
export async function hasUnsafeDns(hostname, lookupFn = lookup) {
  try {
    const addrs = await resolvePublicAddresses(hostname, lookupFn);
    // No addresses is not "safe": it means the host is blocked or DNS failed.
    if (addrs.length === 0) return true;
    return addrs.some((addr) => isBlockedIpAddress(addr));
  } catch {
    return true;
  }
}

async function ensureSafeFetchUrl(urlString, { lookup: lookupFn = lookup } = {}) {
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

  const resolved = await resolvePublicAddresses(host, lookupFn);
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
/**
 * A DNS lookup for sockets that refuses to hand back a blocked address. The
 * socket is therefore pinned to the address that was validated here, which
 * closes the resolve-check-then-connect gap a TTL-0 rebind would exploit.
 */
function validatingLookup(hostname, options, callback) {
  lookup(hostname, { ...options, all: true })
    .then((addresses) => {
      if (!Array.isArray(addresses) || addresses.length === 0) {
        return callback(new Error(`DNS resolution failed for ${hostname}`));
      }
      if (addresses.some((entry) => isBlockedIpAddress(entry.address))) {
        return callback(new Error(`Blocked outbound target: ${hostname}`));
      }
      if (options?.all) return callback(null, addresses);
      return callback(null, addresses[0].address, addresses[0].family);
    })
    .catch((err) => callback(err));
}

/** One HTTP(S) request whose socket lookup is validated. No redirect following. */
function pinnedRequest(urlString, { method, headers, body, timeout, maxBytes }) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const secure = url.protocol === "https:";
    const bareHost = url.hostname.replace(/^\[|\]$/g, "");
    const requestFn = secure ? httpsRequest : httpRequest;

    const req = requestFn(
      {
        protocol: url.protocol,
        hostname: bareHost,
        port: url.port || (secure ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method,
        headers: { host: url.host, "user-agent": UA, accept: "*/*", ...headers },
        lookup: validatingLookup,
        ...(secure && !isIP(bareHost) ? { servername: bareHost } : {}),
        timeout,
      },
      (res) => {
        const headerList = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          headerList[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
        }

        const chunks = [];
        let total = 0;
        let settled = false;
        const fail = (err) => {
          if (settled) return;
          settled = true;
          res.destroy();
          reject(err);
        };

        res.on("data", (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            fail(new Error(`Response body exceeds ${maxBytes} byte limit`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          if (settled) return;
          settled = true;
          resolve({
            status: res.statusCode ?? null,
            headers: headerList,
            body: Buffer.concat(chunks).toString("utf8"),
            url: urlString,
          });
        });
        res.on("error", fail);
      },
    );

    req.on("timeout", () => req.destroy(new Error("Request timed out")));
    req.on("error", reject);
    if (body !== null && body !== undefined) req.write(body);
    req.end();
  });
}

/**
 * One request, either through an injected fetch (tests, fixtures) or through a
 * DNS-pinned socket (production). Redirects are always handled by the caller.
 */
async function sendOnce(urlString, { method, headers, body, timeout, maxBytes, controller, fetchFn }) {
  if (fetchFn !== nativeFetch) {
    const res = await fetchFn(urlString, {
      method,
      redirect: "manual",
      signal: controller?.signal,
      headers: { "user-agent": UA, accept: "*/*", ...headers },
      ...(body !== null && method !== "GET" && method !== "HEAD" ? { body } : {}),
    });

    const headerList = {};
    res.headers.forEach((value, key) => {
      headerList[key.toLowerCase()] = value;
    });
    const isRedirect = res.status >= 300 && res.status < 400;
    let text = null;
    try {
      text = await readBodyBounded(res, maxBytes);
    } catch (err) {
      if (!isRedirect) throw err;
    }
    return {
      status: res.status,
      headers: headerList,
      body: isRedirect ? null : text,
      url: res.url || urlString,
    };
  }

  return pinnedRequest(urlString, { method, headers, body, timeout, maxBytes });
}

async function fetchWithTimeout(urlString, opts = {}) {
  let {
    timeout = 15000,
    method = "GET",
    headers = {},
    maxRedirects = 3,
    maxBytes = MAX_BODY_BYTES,
    body = null,
    lookup: lookupFn = lookup,
    fetch: fetchFn = fetch,
  } = opts;

  let current = await ensureSafeFetchUrl(urlString, { lookup: lookupFn });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let redirected = false;

  try {
    let redirectCount = 0;
    while (true) {
      const res = await sendOnce(current, {
        method,
        headers,
        body,
        timeout,
        maxBytes,
        controller,
        fetchFn,
      });

      if (res.status !== null && res.status >= 300 && res.status < 400) {
        const location = res.headers.location;
        if (location && redirectCount < maxRedirects) {
          redirectCount += 1;
          redirected = true;
          current = await ensureSafeFetchUrl(new URL(location, current).toString(), {
            lookup: lookupFn,
          });
          // 303 always becomes GET; 301/302 commonly do for POST. 307/308
          // preserve the method and body.
          if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
            method = "GET";
            body = null;
          }
          continue;
        }
        return {
          ok: false,
          status: res.status,
          headers: res.headers,
          body: null,
          url: res.url,
          error: null,
          redirected,
        };
      }

      return {
        ok: res.status !== null && res.status >= 200 && res.status < 300,
        status: res.status,
        headers: res.headers,
        body: res.body,
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
  const raw = String(input ?? "").trim();
  if (!raw) return "";

  // Accept a bare host, host:port or full URL. WHATWG URL canonicalises
  // numeric IPv4 forms and keeps IPv6 literals bracketed, so a trailing
  // ":digits" strip cannot corrupt an IPv6 host.
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return "";
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return "";
  return parsed.hostname.toLowerCase().replace(/\.$/, "");
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
  const hsts = headers["strict-transport-security"];
  if (hsts) {
    const maxAgeMatch = String(hsts).match(/max-age\s*=\s*(\d+)/i);
    if (maxAgeMatch && Number(maxAgeMatch[1]) < 86_400) {
      const seconds = Number(maxAgeMatch[1]);
      out.push(
        finding(
          "hsts_short_max_age",
          seconds === 0 ? "HSTS is disabled (max-age=0)" : "HSTS max-age is shorter than 24 hours",
          seconds === 0 ? "medium" : "low",
          seconds === 0
            ? "`Strict-Transport-Security` sets `max-age=0`, which instructs browsers to immediately clear HSTS protection and allow plain HTTP connections again."
            : "`Strict-Transport-Security` sets a `max-age` below 24 hours, so returning visitors lose HTTPS downgrade protection quickly.",
          {
            evidence: String(hsts).slice(0, 180),
            remediation:
              "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` (1 year) once HTTPS works across the domain.",
          },
        ),
      );
    }
  }
  const xfo = headers["x-frame-options"] ?? "";
  if (/\b(?:allowall|allow-from)\b/i.test(xfo)) {
    out.push(
      finding(
        "xfo_allowall",
        "X-Frame-Options permits framing via deprecated or open directive",
        "medium",
        "The `X-Frame-Options` header uses `ALLOWALL` or the obsolete `ALLOW-FROM` directive, which modern browsers ignore — leaving authenticated pages open to clickjacking.",
        {
          evidence: String(xfo).slice(0, 180),
          remediation:
            "Use `X-Frame-Options: DENY` (or `SAMEORIGIN`), or restrict framing with CSP `frame-ancestors 'none'`.",
        },
      ),
    );
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
  if (/\bframe-ancestors[^;]*(?:\s\*|\shttp:)\s*(?:;|$)/.test(lower)) {
    out.push(
      finding(
        "csp_frame_ancestors_wildcard",
        "CSP frame-ancestors allows framing from any origin",
        "medium",
        "Your Content-Security-Policy sets `frame-ancestors *` or `http:`, allowing any third-party site to embed your app in an invisible iframe for clickjacking.",
        {
          evidence: csp.slice(0, 220),
          remediation:
            "Set `frame-ancestors 'none'` or list only explicit trusted HTTPS origins.",
        },
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

function isStagingDomain(domain) {
  return /^(?:dev|staging|stage|test|testing|preview|sandbox|qa|demo)\./i.test(String(domain ?? ""));
}

function scanTextForSecrets(text, sourceUrl, domain = "") {
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
  if (!isStagingDomain(domain)) {
    const stripeTestMatch = text.match(/\bpk_test_[0-9A-Za-z]{20,}\b/);
    if (stripeTestMatch) {
      out.push(
        finding(
          "stripe_test_key_in_production",
          "Stripe test publishable key served on live domain",
          "medium",
          "Your live site bundles a `pk_test_…` Stripe key instead of `pk_live_…`. Real customers either cannot pay or can complete checkout with Stripe test cards without being charged.",
          {
            url: sourceUrl,
            evidence: `${redactSecret(stripeTestMatch[0])} · found in ${sourceUrl.split("/").pop() || sourceUrl}`,
            affected_resource: sourceUrl,
            confidence: "high",
            what_it_does_not_prove:
              "If this domain is intentionally a sandbox or demo environment, test mode may be expected.",
            remediation:
              "Set your production frontend environment variable to `pk_live_…` (and keep `sk_live_…` strictly server-side).",
          },
        ),
      );
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

function extractPublicSupabaseTarget(texts) {
  const urlRe = /https:\/\/([a-z0-9]{10,32})\.supabase\.co\b/gi;
  const pubKeyRe = /\bsb_publishable_[A-Za-z0-9_-]{16,}\b/g;
  const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

  let projectRef = null;
  let anonKey = null;

  for (const text of texts) {
    if (!text) continue;
    if (!projectRef) {
      const m = urlRe.exec(text);
      if (m) projectRef = m[1].toLowerCase();
      urlRe.lastIndex = 0;
    }
    if (!anonKey) {
      const pub = pubKeyRe.exec(text);
      pubKeyRe.lastIndex = 0;
      if (pub) {
        anonKey = pub[0];
      } else {
        for (const jm of text.matchAll(jwtRe)) {
          if (decodeJwtRole(jm[0]) === "anon") {
            anonKey = jm[0];
            break;
          }
        }
      }
    }
    if (projectRef && anonKey) break;
  }

  if (!projectRef || !anonKey) return null;
  return { projectRef, baseUrl: `https://${projectRef}.supabase.co`, anonKey };
}

const SITE_SENSITIVE_SUPABASE_TABLE_RE =
  /^(?:users?|profiles?|accounts?|customers?|members?|admins?|api[_-]?keys?|keys?|secrets?|tokens?|sessions?|orders?|payments?|invoices?|subscriptions?|billing|messages?|chats?|emails?|leads?|waitlist|webhooks?|documents?|uploads?)$/i;

async function probeDiscoveredSupabaseAnonSurface({ projectRef, baseUrl, anonKey }, { lookup: customLookup } = {}) {
  const out = [];
  const authHeaders = {
    apikey: anonKey,
    authorization: `Bearer ${anonKey}`,
    accept: "application/openapi+json, application/json",
  };
  const rootRes = await fetchWithTimeout(`${baseUrl}/rest/v1/`, {
    timeout: 7000,
    maxBytes: 1_500_000,
    headers: authHeaders,
    ...(customLookup ? { lookup: customLookup } : {}),
  });
  if (rootRes.error || !rootRes.ok || !rootRes.body) return out;

  let spec;
  try {
    spec = JSON.parse(rootRes.body);
  } catch {
    return out;
  }
  if (!spec || (!spec.swagger && !spec.openapi) || !spec.paths || typeof spec.paths !== "object") {
    return out;
  }

  const tables = [];
  for (const routePath of Object.keys(spec.paths)) {
    const m = routePath.match(/^\/([A-Za-z_][A-Za-z0-9_]*)$/);
    if (m) {
      tables.push({
        name: m[1],
        sensitive: SITE_SENSITIVE_SUPABASE_TABLE_RE.test(m[1]),
      });
    }
  }
  tables.sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || a.name.localeCompare(b.name));

  const probes = await Promise.all(
    tables.slice(0, 6).map(async (table) => {
      const res = await fetchWithTimeout(
        `${baseUrl}/rest/v1/${encodeURIComponent(table.name)}?limit=1`,
        {
          method: "HEAD",
          timeout: 6000,
          ...(customLookup ? { lookup: customLookup } : {}),
          headers: {
            apikey: anonKey,
            authorization: `Bearer ${anonKey}`,
            prefer: "count=exact",
          },
        },
      );
      return { table, res };
    }),
  );

  for (const { table, res } of probes) {
    if (res.error || !res.ok) continue;
    const rangeMatch = String(res.headers?.["content-range"] ?? "").match(/\/(\d+)\s*$/);
    const visibleRows = rangeMatch ? Number(rangeMatch[1]) : 0;
    if (visibleRows > 0) {
      out.push(
        finding(
          "site_supabase_anon_exposure",
          `Live Supabase table \`${table.name}\` exposes ${visibleRows} row${visibleRows === 1 ? "" : "s"} to visitors`,
          table.sensitive ? "critical" : "high",
          `Your website's public JavaScript bundle connects to Supabase project \`${projectRef}\` with an \`anon\` key that can read ${visibleRows} row${visibleRows === 1 ? "" : "s"} from \`public.${table.name}\` without signing in.`,
          {
            url: `https://supabase.com/dashboard/project/${projectRef}/auth/policies`,
            evidence: `${projectRef}.supabase.co · HEAD /rest/v1/${table.name} · ${visibleRows} row(s) visible to anon`,
            affected_resource: `supabase:${projectRef}:${table.name}`,
            confidence: "high",
            what_it_does_not_prove:
              "Bulwark used a zero-row HEAD count probe and never downloaded table contents. If this table is intentionally public, you can acknowledge or snooze this finding.",
            remediation: `Enable Row Level Security on \`public.${table.name}\` in Supabase project \`${projectRef}\` and scope SELECT policies to authenticated owners.`,
          },
        ),
      );
    }
  }

  return out;
}

function extractSourceMapUrl(scriptBody, scriptUrl) {
  if (!scriptBody) return null;
  // Look near the end of the bundle for sourceMappingURL comments.
  const tail = scriptBody.slice(-1024);
  const match = tail.match(/\/\/[#@]\s*sourceMappingURL=([^\s*]+)\s*$/m);
  if (!match) return null;
  const raw = match[1].trim();
  if (!raw || raw.startsWith("data:")) return null;
  try {
    const resolved = new URL(raw, scriptUrl);
    if (!/^https?:$/.test(resolved.protocol)) return null;
    if (resolved.host !== new URL(scriptUrl).host) return null;
    return resolved.toString();
  } catch {
    return null;
  }
}

async function checkLeakedSecretsInner(domain, page, { lookup: customLookup } = {}) {
  const findings = [];
  const errors = [];
  const seen = new Set();
  const add = (items) => {
    for (const item of items) {
      const dedupKey = `${item.check_key}:${item.affected_resource ?? ""}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);
      findings.push(item);
    }
  };
  add(scanTextForSecrets(page.body, page.finalUrl, domain));

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

  const mapUrls = new Set();
  const inspectableTexts = [page.body];
  for (const bundle of bundleResults) {
    if (!bundle) continue;
    inspectableTexts.push(bundle.body);
    add(scanTextForSecrets(bundle.body, bundle.url, domain));
    const mapUrl = extractSourceMapUrl(bundle.body, bundle.url);
    if (mapUrl) mapUrls.add(mapUrl);
  }

  const discoveredSupabase = extractPublicSupabaseTarget(inspectableTexts);
  if (discoveredSupabase) {
    const sbFindings = await probeDiscoveredSupabaseAnonSurface(discoveredSupabase, {
      lookup: customLookup,
    });
    add(sbFindings);
  }

  // Probe referenced same-host JS source maps (.js.map) without extra fetches
  // when bundles do not declare sourceMappingURL.
  const mapTargets = [...mapUrls].slice(0, 4);
  if (mapTargets.length) {
    await Promise.all(
      mapTargets.map(async (mapUrl) => {
        const res = await safeFetch(mapUrl, 10000);
        if (res.error || !res.found || !res.body) return;
        try {
          const parsed = JSON.parse(res.body);
          if (parsed && parsed.version === 3 && (Array.isArray(parsed.sources) || typeof parsed.mappings === "string")) {
            add([
              finding(
                "exposed_source_map",
                "Public JavaScript source map exposed",
                "high",
                "A production JavaScript bundle links to a publicly downloadable `.map` file. Anyone can reconstruct your original frontend source code, comments, and internal file paths.",
                {
                  url: mapUrl,
                  evidence: `${new URL(mapUrl).pathname} · ${res.body.length} bytes (${Array.isArray(parsed.sources) ? parsed.sources.length : "?"} source files)`,
                  affected_resource: new URL(mapUrl).pathname,
                  remediation:
                    "Disable public source maps in production builds (e.g. `sourcemap: false` or hidden source maps uploaded only to error tracking).",
                },
              ),
            ]);
          }
        } catch {
          // Not valid source map JSON.
        }
      }),
    );
  }

  return { findings, error: errors.length ? errors.join("; ") : null };
}

async function checkApiExposureInner(domain) {
  const findings = [];
  const errors = [];
  const base = `https://${domain}`;

  const docPaths = ["/openapi.json", "/swagger.json"];
  await Promise.all([
    ...docPaths.map(async (docPath) => {
      const url = `${base}${docPath}`;
      const res = await safeFetch(url, 8000);
      if (res.error) {
        errors.push(`${docPath}: ${res.error}`);
        return;
      }
      if (!res.found || !res.body) return;
      try {
        const json = JSON.parse(res.body);
        if (json && (json.openapi || json.swagger) && json.paths && typeof json.paths === "object") {
          const pathCount = Object.keys(json.paths).length;
          findings.push(
            finding(
              "exposed_api_docs",
              `Public API specification exposed (${docPath})`,
              "medium",
              "Your OpenAPI / Swagger schema is publicly accessible without authentication, giving attackers a complete map of internal API endpoints and parameters.",
              {
                url,
                evidence: `${docPath} · ${json.openapi ? `OpenAPI ${json.openapi}` : `Swagger ${json.swagger}`} · ${pathCount} route(s)`,
                affected_resource: docPath,
                remediation:
                  "Disable or gate OpenAPI/Swagger documentation behind authentication in production unless the API is intentionally public.",
              },
            ),
          );
        }
      } catch {
        // Not valid OpenAPI/Swagger JSON.
      }
    }),
    (async () => {
      const url = `${base}/graphql`;
      const res = await fetchWithTimeout(url, {
        method: "POST",
        timeout: 8000,
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      });
      if (res.error) {
        errors.push(`/graphql: ${res.error}`);
        return;
      }
      if (!res.ok || !res.body) return;
      try {
        const json = JSON.parse(res.body);
        const queryType = json?.data?.__schema?.queryType?.name;
        if (queryType) {
          findings.push(
            finding(
              "graphql_introspection_enabled",
              "GraphQL introspection enabled in production",
              "medium",
              "The `/graphql` endpoint answers unauthenticated schema introspection queries, exposing every query, mutation, and type in your API.",
              {
                url,
                evidence: `queryType=${queryType}`,
                affected_resource: "/graphql",
                remediation:
                  "Disable GraphQL introspection in production environments unless the API schema is intentionally public.",
              },
            ),
          );
        }
      } catch {
        // Not a GraphQL JSON response.
      }
    })(),
  ]);

  return { findings, error: errors.length ? errors.join("; ") : null };
}

const RDAP_CACHE_OK_TTL_MS = 24 * 60 * 60 * 1000;
const RDAP_CACHE_ERR_TTL_MS = 60 * 1000;

let rdapBootstrapCache = { expiresAt: 0, error: null, services: [] };

export function resetRdapBootstrapCache() {
  rdapBootstrapCache = { expiresAt: 0, error: null, services: [] };
}

async function rdapBaseUrl(tld, now = Date.now()) {
  if (now >= rdapBootstrapCache.expiresAt) {
    try {
      const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", { timeout: 12000 });
      if (res.error) {
        rdapBootstrapCache = {
          expiresAt: now + RDAP_CACHE_ERR_TTL_MS,
          error: res.error,
          services: [],
        };
      } else if (res.status === null || res.status !== 200) {
        rdapBootstrapCache = {
          expiresAt: now + RDAP_CACHE_ERR_TTL_MS,
          error: res.status === null ? "no response" : `HTTP ${res.status}`,
          services: [],
        };
      } else {
        const parsed = JSON.parse(res.body ?? "{}");
        rdapBootstrapCache = {
          expiresAt: now + RDAP_CACHE_OK_TTL_MS,
          error: null,
          services: Array.isArray(parsed?.services) ? parsed.services : [],
        };
      }
    } catch (err) {
      rdapBootstrapCache = {
        expiresAt: now + RDAP_CACHE_ERR_TTL_MS,
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

const DANGLING_CNAME_SIGNATURES = [
  {
    provider: "GitHub Pages",
    targetRe: /\.github\.io$/i,
    bodyRe: /There isn't a GitHub Pages site here/i,
  },
  {
    provider: "Amazon S3",
    targetRe: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i,
    bodyRe: /NoSuchBucket|The specified bucket does not exist/i,
  },
  {
    provider: "Heroku",
    targetRe: /\.(?:herokudns\.com|herokuapp\.com)$/i,
    bodyRe: /No such app|herokucdn\.com\/error-pages\/no-such-app/i,
  },
  {
    provider: "Vercel",
    targetRe: /\.(?:vercel-dns\.com|vercel\.app|now\.sh)$/i,
    bodyRe: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i,
  },
  {
    provider: "Netlify",
    targetRe: /\.netlify\.app$/i,
    bodyRe: /Not Found - Request ID:/i,
  },
  {
    provider: "Azure",
    targetRe: /\.(?:azurewebsites\.net|azurefd\.net|blob\.core\.windows\.net)$/i,
    bodyRe: /Error 404 - Web app not found|The specified container does not exist/i,
  },
  {
    provider: "Render",
    targetRe: /\.onrender\.com$/i,
    bodyRe: /This Render service is either suspended or does not exist/i,
  },
  {
    provider: "Surge.sh",
    targetRe: /\.surge\.sh$/i,
    bodyRe: /project not found/i,
  },
  {
    provider: "Ghost",
    targetRe: /\.ghost\.io$/i,
    bodyRe: /The thing you were looking for is no longer here/i,
  },
  {
    provider: "Shopify",
    targetRe: /\.myshopify\.com$/i,
    bodyRe: /Sorry, this shop is currently unavailable/i,
  },
];

async function checkDnsInner(domain, page = null) {
  const findings = [];
  const errors = [];
  if (isIpOrLocal(domain)) return { findings, error: null };
  const registrable = registrableDomain(domain);
  const isSubdomain = domain !== registrable;

  const [nsResult, mxResult, txtResult, dmarcResult, cnameResult] = await Promise.all([
    dohQuery(registrable, "NS"),
    dohQuery(registrable, "MX"),
    dohQuery(registrable, "TXT"),
    dohQuery(`_dmarc.${registrable}`, "TXT"),
    isSubdomain ? dohQuery(domain, "CNAME") : Promise.resolve({ records: [], error: null }),
  ]);

  if (isSubdomain && !cnameResult.error && (cnameResult.records?.length ?? 0) > 0) {
    const cnameTargets = cnameResult.records
      .filter((r) => r.type === 5 || typeof r.data === "string")
      .map((r) => String(r.data ?? "").trim().toLowerCase().replace(/\.$/, ""))
      .filter(Boolean);

    const status = page?.status ?? null;
    const body = String(page?.body ?? "");
    if (status === 404 || status === 410) {
      for (const target of cnameTargets) {
        const sig = DANGLING_CNAME_SIGNATURES.find(
          (entry) => entry.targetRe.test(target) && entry.bodyRe.test(body),
        );
        if (sig) {
          findings.push(
            finding(
              "dns_dangling_cname",
              `Subdomain takeover risk on ${domain} (${sig.provider})`,
              "critical",
              `\`${domain}\` has a DNS \`CNAME\` pointing to \`${target}\`, and ${sig.provider} returned an unclaimed-project 404 page. Anyone can register that ${sig.provider} project/bucket name to serve phishing pages, steal domain-scoped cookies, or intercept OAuth redirects on \`${domain}\`.`,
              {
                url: `https://${domain}/`,
                evidence: `${domain} CNAME → ${target} · HTTP ${status} (${sig.provider} unclaimed page)`,
                affected_resource: `${domain}->${target}`,
                confidence: "high",
                what_it_does_not_prove:
                  "Some providers temporarily reserve recently deleted project names before allowing another account to claim them.",
                remediation: `Delete the stale \`CNAME\` record for \`${domain}\` in your DNS provider immediately, or re-attach \`${domain}\` to your active ${sig.provider} deployment.`,
              },
            ),
          );
          break;
        }
      }
    }
  }

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

  if (txtResult.error) {
    errors.push(`DNS SPF lookup: ${txtResult.error}`);
  } else {
    const txtValues = (txtResult.records ?? []).map((r) => String(r.data ?? "").replace(/^"|"$/g, ""));
    const spfRecord = txtValues.find((v) => /^v=spf1\b/i.test(v));
    if (!spfRecord) {
      findings.push(
        finding(
          "dns_no_spf",
          "Missing SPF record (email spoofing risk)",
          "low",
          "No SPF TXT record was found on the root domain. Without SPF, mail providers have a weaker signal for rejecting spoofed emails sent from your domain.",
          {
            evidence: `${registrable} TXT (no v=spf1 record)`,
            remediation:
              "Add a TXT record at the root domain (e.g. `v=spf1 include:_spf.your-provider.com ~all`, or `v=spf1 -all` if the domain never sends email).",
          },
        ),
      );
    }
  }

  if (dmarcResult.error) {
    errors.push(`DNS DMARC lookup: ${dmarcResult.error}`);
  } else {
    const dmarcValues = (dmarcResult.records ?? []).map((r) =>
      String(r.data ?? "").replace(/^"|"$/g, ""),
    );
    const dmarcRecord = dmarcValues.find((v) => /^v=DMARC1\b/i.test(v));
    if (!dmarcRecord) {
      findings.push(
        finding(
          "dns_no_dmarc",
          "Missing DMARC record (email spoofing risk)",
          "low",
          "No `_dmarc` TXT record was found. DMARC tells receiving mail servers how to handle spoofed emails claiming to come from your domain.",
          {
            evidence: `_dmarc.${registrable} TXT (missing)`,
            remediation:
              "Add a `_dmarc` TXT record such as `v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@yourdomain.com` (or `p=reject` if you do not send email).",
          },
        ),
      );
    } else if (/;\s*p=none\b|\bp=none\b/i.test(dmarcRecord)) {
      findings.push(
        finding(
          "dns_dmarc_monitor_only",
          "DMARC policy is monitor-only (p=none)",
          "info",
          "DMARC is present with `p=none`, which only collects reports without quarantining or rejecting spoofed emails.",
          {
            evidence: dmarcRecord.slice(0, 180),
            remediation:
              "Once legitimate mail senders pass SPF/DKIM cleanly, tighten DMARC to `p=quarantine` or `p=reject`.",
          },
        ),
      );
    }
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

const MAX_SAMPLE_TOKENS = 1200;

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

/**
 * Defacement detection only needs token overlap, never readable page text.
 * Storing hashed tokens means a secret that appears in visible copy is not
 * persisted (or shipped to the browser) in a usable form.
 */
function hashedTokens(text) {
  const tokens = String(text ?? "").match(/[a-z0-9]{3,}/g) ?? [];
  const unique = new Set();
  for (const token of tokens) {
    unique.add(hashToken(token));
    if (unique.size >= MAX_SAMPLE_TOKENS) break;
  }
  return [...unique];
}

/** Supports v2 hashed samples and legacy `{text}` baselines. */
function tokenSet(value) {
  if (Array.isArray(value?.tokens)) return new Set(value.tokens);
  if (typeof value?.text === "string") return new Set(hashedTokens(value.text));
  return new Set();
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
  return JSON.stringify({
    v: 2,
    title,
    tokens: hashedTokens(visibleText(html)),
    at: new Date().toISOString(),
  });
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
  if ((sample.tokens?.length ?? 0) < 30) return { findings: out, sample, similarity: 1 };

  let similarity = 1;
  if (baselineJson) {
    try {
      const baseline = JSON.parse(baselineJson);
      const baselineTokens = tokenSet(baseline);
      if (baselineTokens.size >= 30) {
        similarity = jaccard(baselineTokens, new Set(sample.tokens));
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
    const normalized = String(domain ?? "")
      .trim()
      .toLowerCase()
      .replace(/\.$/, "")
      .replace(/^\[|\]$/g, "");
    if (isBlockedOutboundHost(normalized)) {
      return resolve({ error: `Blocked TLS target: ${normalized}` });
    }

    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };

    let socket;
    try {
      socket = connect(
        {
          host: normalized,
          port: 443,
          timeout: 10000,
          lookup: validatingLookup,
          ...(isIP(normalized) ? {} : { servername: normalized }),
        },
        () => {
          // The lookup above is the one the socket used, but check the peer
          // address too so any future transport change cannot regress this.
          if (isBlockedIpAddress(socket.remoteAddress ?? "")) {
            socket.destroy();
            return finish({ error: `Blocked TLS target: ${normalized}` });
          }
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
    } catch (err) {
      return finish({ error: err?.message ?? `TLS connection failed for: ${normalized}` });
    }

    socket.on("error", () => finish(null));
    socket.on("timeout", () => {
      socket.destroy();
      finish(null);
    });
  });
}

// ============================================================================
// Orchestrator
// ============================================================================

export async function runChecks(rawDomain, { baseline = null, lookup: customLookup } = {}) {
  const domain = normalizeDomain(rawDomain);
  const findings = [];
  const start = Date.now();
  const checkResults = {};
  const checkResultsList = [];

  const register = (key, outcome, error = null) => {
    checkResults[key] = outcome;
    const entry = {
      key,
      label: WEBSITE_CHECK_LABELS[key] ?? key,
      status: outcome,
      complete: outcome === "pass" || outcome === "finding",
    };
    if (error) entry.error = String(error);
    checkResultsList.push(entry);
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
      checkResultsList,
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
    apiExposureResult,
    domainExpiryResult,
    dnsResult,
  ] = await Promise.all([
    runCheck("exposed_files", () => checkExposedFilesInner(domain)),
    runCheck("cors", () => checkCorsInner(domain)),
    runCheck("public_discovery", () => checkDiscoveryInner(domain)),
    runCheck("secrets", () => checkLeakedSecretsInner(domain, page, { lookup: customLookup })),
    runCheck("api_exposure", () => checkApiExposureInner(domain)),
    runCheck("domain_registration", () => checkDomainExpiryInner(domain)),
    runCheck("dns", () => checkDnsInner(domain, page)),
  ]);

  for (const r of [
    exposedResult,
    corsResult,
    discoveryResult,
    secretsResult,
    apiExposureResult,
    domainExpiryResult,
    dnsResult,
  ]) {
    findings.push(...r.findings);
    register(r.key, r.outcome, r.error ?? null);
  }

  // Deduplicate by (check_key, affected_resource) so multi-resource checks stay distinct.
  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    const dedupKey = f.affected_resource ? `${f.check_key}:${f.affected_resource}` : f.check_key;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
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
    checkResultsList,
    findings: unique,
    tls,
    pageSample: defacement.sample,
    defacementSimilarity: defacement.similarity,
    durationMs: Date.now() - start,
  };
}

export { normalizeDomain, ensureSafeFetchUrl, fetchWithTimeout, rdapBaseUrl };
