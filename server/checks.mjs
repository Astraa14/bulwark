import { connect } from "node:tls";

const UA = "BulwarkBot/0.2 (+https://bulwark.app/bot)";

const SECURITY_HEADERS = [
  {
    key: "strict-transport-security",
    check: "header_hsts",
    title: "Missing HSTS header",
    severity: "medium",
    detail:
      "Strict-Transport-Security is not set, so browsers may fall back to plain HTTP on the first visit.",
    confidence: "medium",
    what_it_does_not_prove: "Does not prove the site serves content over HTTP; may be behind a proxy that handles TLS.",
    remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
  },
  {
    key: "content-security-policy",
    check: "header_csp",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    detail:
      "No CSP means injected scripts run freely. It is the strongest single defence against XSS.",
    confidence: "medium",
    what_it_does_not_prove: "Does not prove XSS vulnerabilities exist; CSP is a defense-in-depth measure.",
    remediation: "Implement a Content-Security-Policy header starting with 'default-src' restrictions.",
  },
  {
    key: "x-content-type-options",
    check: "header_nosniff",
    title: "Missing X-Content-Type-Options",
    severity: "low",
    detail: "Without 'nosniff', browsers may MIME-sniff responses and execute unexpected content.",
    confidence: "low",
    what_it_does_not_prove: "Does not prove content sniffing is being exploited; modern browsers have improved protections.",
    remediation: "Add 'X-Content-Type-Options: nosniff' header.",
  },
  {
    key: "referrer-policy",
    check: "header_referrer",
    title: "Missing Referrer-Policy",
    severity: "low",
    detail: "URLs can leak to third parties through the Referer header.",
    confidence: "low",
    what_it_does_not_prove: "Does not prove sensitive data is being leaked; depends on URL structure.",
    remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
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
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "co.jp",
  "com.br",
  "co.in",
  "com.sg",
  "com.mx",
  "co.za",
  "com.tr",
  "com.hk",
  "co.kr",
]);

function finding(check_key, title, severity, detail, extra = {}) {
  return {
    check_key,
    title,
    severity,
    detail,
    confidence: extra.confidence ?? "medium", // high, medium, low
    what_it_does_not_prove: extra.what_it_does_not_prove ?? null,
    remediation: extra.remediation ?? null,
    ...extra,
  };
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
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || domain === "localhost" || domain.endsWith(".local");
}

/**
 * Checks if an IP address is in a private, loopback, link-local, or reserved range.
 * Returns true if the IP should be blocked.
 */
function isUnsafeIp(ip) {
  // IPv4 private ranges
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (ipv4) {
    const [, a, b, c, d] = ipv4.map(Number);
    // Loopback: 127.0.0.0/8
    if (a === 127) return true;
    // Private: 10.0.0.0/8
    if (a === 10) return true;
    // Private: 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // Private: 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // Link-local: 169.254.0.0/16
    if (a === 169 && b === 254) return true;
    // Reserved for benchmarking: 198.18.0.0/15
    if (a === 198 && (b === 18 || b === 19)) return true;
    // Reserved for documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (a === 192 && b === 0 && c === 2) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    // Broadcast: 255.255.255.255
    if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  }

  // IPv6 private ranges
  if (ip.includes(':')) {
    // Loopback: ::1
    if (ip === '::1' || ip.startsWith('::1')) return true;
    // Link-local: fe80::/10
    if (ip.startsWith('fe80:') || ip.startsWith('fe81:') || ip.startsWith('fe82:') || ip.startsWith('fe83:') ||
        ip.startsWith('fe84:') || ip.startsWith('fe85:') || ip.startsWith('fe86:') || ip.startsWith('fe87:') ||
        ip.startsWith('fe88:') || ip.startsWith('fe89:') || ip.startsWith('fe8a:') || ip.startsWith('fe8b:') ||
        ip.startsWith('fe8c:') || ip.startsWith('fe8d:') || ip.startsWith('fe8e:') || ip.startsWith('fe8f:')) return true;
    // Unique local: fc00::/7
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
    // Documentation: 2001:db8::/32
    if (ip.startsWith('2001:db8:')) return true;
  }

  return false;
}

/**
 * Resolves a hostname to IPs and checks if any are unsafe.
 * Returns true if the hostname resolves to an unsafe IP.
 */
async function hasUnsafeDns(hostname) {
  try {
    const { resolve } = await import('node:dns/promises');
    const ips = await resolve(hostname);
    return ips.some(ip => isUnsafeIp(ip));
  } catch {
    // If DNS resolution fails, assume safe (will fail at fetch time anyway)
    return false;
  }
}

async function fetchWithTimeout(url, { timeout = 15000, method = "GET", headers = {}, maxRedirects = 5, maxSize = 5_000_000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  // Validate initial URL hostname for unsafe IPs
  try {
    const initialUrl = new URL(url);
    if (initialUrl.hostname && await hasUnsafeDns(initialUrl.hostname)) {
      clearTimeout(timer);
      throw new Error(`Blocked request to unsafe IP range: ${initialUrl.hostname}`);
    }
  } catch (err) {
    if (err.message.includes('unsafe IP')) {
      clearTimeout(timer);
      throw err;
    }
    // If URL parsing fails, continue (will fail at fetch time)
  }

  try {
    const response = await fetch(url, {
      method,
      redirect: "manual", // We'll handle redirects manually to validate each one
      signal: controller.signal,
      headers: { "user-agent": UA, accept: "*/*", ...headers },
    });

    // Handle redirects manually with validation
    if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
      let redirectCount = 0;
      let currentUrl = url;
      let currentResponse = response;

      while (currentResponse.status >= 300 && currentResponse.status < 400 && redirectCount < maxRedirects) {
        const location = currentResponse.headers.get('location');
        if (!location) break;

        const nextUrl = new URL(location, currentUrl);

        // Validate redirect target for unsafe IPs
        if (nextUrl.hostname && await hasUnsafeDns(nextUrl.hostname)) {
          clearTimeout(timer);
          throw new Error(`Blocked redirect to unsafe IP range: ${nextUrl.hostname}`);
        }

        redirectCount++;
        currentUrl = nextUrl.toString();

        currentResponse = await fetch(currentUrl, {
          method,
          redirect: "manual",
          signal: controller.signal,
          headers: { "user-agent": UA, accept: "*/*", ...headers },
        });
      }

      if (redirectCount >= maxRedirects) {
        clearTimeout(timer);
        throw new Error(`Too many redirects (${maxRedirects} max)`);
      }

      // Wrap the final response to enforce size limits on body reads
      return wrapResponseWithSizeLimit(currentResponse, timer, maxSize);
    }

    // No redirects, wrap response to enforce size limits
    return wrapResponseWithSizeLimit(response, timer, maxSize);
  } finally {
    // Don't clear timeout here - it's cleared when body reading completes or errors
  }
}

/**
 * Wraps a Response object to enforce size limits on body reads.
 * The timeout is cleared when body reading completes.
 */
function wrapResponseWithSizeLimit(response, timer, maxSize) {
  return new Proxy(response, {
    get(target, prop) {
      if (prop === 'text' || prop === 'json' || prop === 'arrayBuffer' || prop === 'blob') {
        return async () => {
          const reader = target.body.getReader();
          let receivedLength = 0;
          const chunks = [];

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            receivedLength += value.length;
            if (receivedLength > maxSize) {
              reader.cancel();
              clearTimeout(timer);
              throw new Error(`Response body exceeds maximum size of ${maxSize} bytes`);
            }

            chunks.push(value);
          }

          clearTimeout(timer);

          const body = new Uint8Array(receivedLength);
          let position = 0;
          for (const chunk of chunks) {
            body.set(chunk, position);
            position += chunk.length;
          }

          const decoder = new TextDecoder();
          const text = decoder.decode(body);

          if (prop === 'text') return text;
          if (prop === 'json') return JSON.parse(text);
          if (prop === 'arrayBuffer') return body.buffer;
          if (prop === 'blob') return new Blob([body]);

          return text;
        };
      }
      return target[prop];
    }
  });
}

export async function checkUptime(domain) {
  const start = Date.now();
  try {
    const res = await fetchWithTimeout(`https://${domain}/`);
    const responseMs = Date.now() - start;
    const body = await res.text().catch(() => "");
    return { ok: true, status: res.status, responseMs, body, headers: res.headers, finalUrl: res.url };
  } catch (err) {
    return { ok: false, error: err?.message ?? String(err), responseMs: Date.now() - start };
  }
}

export function checkTls(domain) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };

    const socket = connect(
      { host: domain, port: 443, servername: domain, timeout: 10000 },
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
  });
}

async function checkExposedFiles(domain) {
  const probes = EXPOSED_FILES.map(async (file) => {
    try {
      const res = await fetchWithTimeout(`https://${domain}${file.path}`, { timeout: 8000, maxSize: 1_000_000 });
      if (res.status !== 200) return null;
      const body = await res.text().catch(() => "");
      if (!file.matches(body)) return null;
      return finding(file.check, file.title, file.severity, file.detail, {
        url: `https://${domain}${file.path}`,
        evidence: `${res.status} ${res.headers.get("content-type") ?? "unknown"} · ${body.length} bytes`,
      });
    } catch {
      return null;
    }
  });

  const results = await Promise.all(probes);
  return results.filter(Boolean);
}

function checkHeaders(headers) {
  const out = [];
  for (const h of SECURITY_HEADERS) {
    if (!headers.get(h.key)) {
      out.push(finding(h.check, h.title, h.severity, h.detail, {
        confidence: h.confidence,
        what_it_does_not_prove: h.what_it_does_not_prove,
        remediation: h.remediation,
      }));
    }
  }
  const server = headers.get("server") ?? "";
  if (/\d/.test(server)) {
    out.push(
      finding(
        "server_banner",
        "Server version disclosed",
        "low",
        "The Server header reveals software and version, which helps attackers target known CVEs.",
        {
          evidence: server,
          confidence: "low",
          what_it_does_not_prove: "Does not prove the server has unpatched vulnerabilities; version may be outdated but patched.",
          remediation: "Configure server to omit version number or use a generic Server header.",
        },
      ),
    );
  }
  return out;
}

function checkCspQuality(headers) {
  const csp = headers.get("content-security-policy");
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

async function checkCors(domain) {
  try {
    const probeOrigin = "https://bulwark-cors-probe.example";
    const res = await fetchWithTimeout(`https://${domain}/`, {
      timeout: 10000,
      headers: { origin: probeOrigin },
    });
    const allow = res.headers.get("access-control-allow-origin");
    const credentials = (res.headers.get("access-control-allow-credentials") ?? "").toLowerCase();
    if (!allow) return [];

    // High severity: wildcard with credentials is always dangerous
    if (allow === "*" && credentials === "true") {
      return [
        finding(
          "cors_wildcard_credentials",
          "CORS allows any origin with credentials",
          "high",
          "Any website can read authenticated responses from your API, which exposes user data cross-site.",
          { evidence: "access-control-allow-origin: * · allow-credentials: true" },
        ),
      ];
    }

    // Reflecting origin is only high risk if credentials are supported
    if (allow === probeOrigin) {
      if (credentials === "true") {
        return [
          finding(
            "cors_reflects_origin_credentials",
            "CORS reflects any origin with credentials",
            "high",
            "The server echoes back whatever Origin it receives with credentials. Any site can read your users' data.",
            { evidence: `access-control-allow-origin: ${allow} · allow-credentials: true` },
          ),
        ];
      }
      // Without credentials, medium severity - still reflective but less dangerous
      return [
        finding(
          "cors_reflects_origin",
          "CORS reflects any origin without credentials",
          "medium",
          "The server echoes back whatever Origin it receives. Risk depends on whether the response contains sensitive data.",
          { evidence: `access-control-allow-origin: ${allow}` },
        ),
      ];
    }

    // Wildcard without credentials is generally low risk unless serving private data
    if (allow === "*") {
      return [
        finding(
          "cors_wildcard",
          "CORS is open to every origin",
          "low",
          "Public cross-origin reads are allowed. Only a concern if responses contain private data.",
          { evidence: "access-control-allow-origin: *" },
        ),
      ];
    }

    // Specific origin without credentials is informational
    return [
      finding(
        "cors_specific_origin",
        "CORS allows specific origin",
        "info",
        `CORS is restricted to ${allow}. This is a safe configuration for cross-origin requests.`,
        { evidence: `access-control-allow-origin: ${allow}` },
      ),
    ];
  } catch {
    return [];
  }
}

function checkCookies(headers) {
  const raw = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  if (!raw.length) return [];

  const problems = [];
  for (const cookieStr of raw) {
    // Parse cookie attributes structurally
    const parts = cookieStr.split(';').map(p => p.trim());
    const nameValue = parts[0].split('=');
    const name = nameValue[0]?.trim() ?? "cookie";

    // Check if this is a sensitive cookie
    const sensitive = /session|token|auth|sid|jwt|refresh/i.test(name);

    // Parse attributes properly (after the first =)
    const attributes = new Map();
    for (let i = 1; i < parts.length; i++) {
      const attr = parts[i].toLowerCase();
      if (attr.includes('=')) {
        const [key, value] = attr.split('=');
        attributes.set(key.trim(), value.trim());
      } else {
        attributes.set(attr, true);
      }
    }

    // Check Secure attribute
    if (!attributes.has('secure')) {
      problems.push(`${name} missing Secure`);
    }

    // Check HttpOnly for sensitive cookies
    if (sensitive && !attributes.has('httponly')) {
      problems.push(`${name} missing HttpOnly`);
    }

    // Check SameSite attribute
    if (!attributes.has('samesite')) {
      problems.push(`${name} missing SameSite`);
    } else {
      const sameSite = attributes.get('samesite');
      // SameSite=None without Secure is problematic
      if (sameSite === 'none' && !attributes.has('secure')) {
        problems.push(`${name} SameSite=None without Secure`);
      }
    }
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

async function fetchOptional(url, timeout = 8000) {
  try {
    const res = await fetchWithTimeout(url, { timeout });
    if (res.status !== 200) return null;
    const body = await res.text().catch(() => "");
    return { body, contentType: res.headers.get("content-type") ?? "" };
  } catch {
    return null;
  }
}

async function checkDiscovery(domain) {
  const out = [];
  const [robots, sitemap, securityTxt, securityTxtAlt] = await Promise.all([
    fetchOptional(`https://${domain}/robots.txt`),
    fetchOptional(`https://${domain}/sitemap.xml`),
    fetchOptional(`https://${domain}/.well-known/security.txt`),
    fetchOptional(`https://${domain}/security.txt`),
  ]);

  if (!robots) {
    out.push(
      finding(
        "robots_missing",
        "No robots.txt",
        "info",
        "Search engines and bots have no guidance. Not a vulnerability on its own.",
        {
          url: `https://${domain}/robots.txt`,
          confidence: "low",
          what_it_does_not_prove: "Does not indicate a security issue; many sites intentionally omit robots.txt.",
          remediation: "Create robots.txt if you want to guide search engine crawling behavior.",
        },
      ),
    );
  } else {
    const paths = [...robots.body.matchAll(/^\s*(?:disallow|allow):\s*(\/\S*)/gim)]
      .map((m) => m[1])
      .filter((p) => /\/(admin|config|backup|private|db|sql|env|secret|internal|staging)/i.test(p));
    if (paths.length) {
      out.push(
        finding(
          "robots_sensitive_paths",
          "robots.txt points at sensitive paths",
          "low",
          "robots.txt publicly lists internal-looking paths, which acts as a map for attackers. Do not rely on it to hide anything.",
          {
            url: `https://${domain}/robots.txt`,
            evidence: paths.slice(0, 6).join(", "),
            confidence: "medium",
            what_it_does_not_prove: "Does not prove the paths are accessible or contain sensitive data.",
            remediation: "Remove sensitive paths from robots.txt; rely on authentication and authorization instead.",
          },
        ),
      );
    }
  }

  if (!sitemap) {
    out.push(
      finding(
        "sitemap_missing",
        "No sitemap.xml",
        "info",
        "A sitemap helps search engines find your pages. Missing is normal for apps.",
        {
          url: `https://${domain}/sitemap.xml`,
          confidence: "low",
          what_it_does_not_prove: "Does not indicate a security issue; many single-page apps intentionally omit sitemaps.",
          remediation: "Create sitemap.xml if you want to improve SEO for content pages.",
        },
      ),
    );
  } else if (!/<(urlset|sitemapindex)[\s>]/i.test(sitemap.body)) {
    out.push(
      finding(
        "sitemap_invalid",
        "sitemap.xml is not a sitemap",
        "low",
        "The sitemap URL returns something that is not a sitemap document, which confuses crawlers and may expose a fallback page.",
        {
          url: `https://${domain}/sitemap.xml`,
          confidence: "medium",
          what_it_does_not_prove: "Does not prove a security issue; may be a misconfiguration.",
          remediation: "Ensure sitemap.xml returns valid XML or remove the endpoint.",
        },
      ),
    );
  }

  const security = securityTxt ?? securityTxtAlt;
  const securityUrl = securityTxt
    ? `https://${domain}/.well-known/security.txt`
    : `https://${domain}/security.txt`;
  if (!security) {
    out.push(
      finding(
        "security_txt_missing",
        "No security.txt",
        "low",
        "Researchers have no published way to report a vulnerability, so reports may go nowhere.",
        {
          url: `https://${domain}/.well-known/security.txt`,
          confidence: "low",
          what_it_does_not_prove: "Does not indicate a security issue; you may handle reports through other channels.",
          remediation: "Create security.txt at /.well-known/security.txt with a Contact field.",
        },
      ),
    );
  } else if (!/^\s*contact\s*:/im.test(security.body)) {
    out.push(
      finding(
        "security_txt_invalid",
        "security.txt has no Contact field",
        "medium",
        "A security.txt without a Contact line cannot be used to report issues.",
        {
          url: securityUrl,
          confidence: "high",
          what_it_does_not_prove: "Does not prove researchers can't contact you through other means.",
          remediation: "Add a 'Contact:' field to security.txt with an email or URL.",
        },
      ),
    );
  }

  return out;
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

async function checkLeakedSecrets(domain, page) {
  const out = [];
  const seen = new Set();

  const add = (items) => {
    for (const item of items) {
      if (seen.has(item.check_key)) continue;
      seen.add(item.check_key);
      out.push(item);
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

  const bundles = await Promise.all(
    candidates.map(async (url) => {
      try {
        const res = await fetchWithTimeout(url, { timeout: 12000, maxSize: 4_000_000 });
        if (res.status !== 200) return null;
        const body = await res.text().catch(() => "");
        if (!body) return null;
        return { url, body };
      } catch {
        return null;
      }
    }),
  );

  for (const bundle of bundles) {
    if (!bundle) continue;
    add(scanTextForSecrets(bundle.body, bundle.url));
  }

  return out;
}

let rdapBootstrapCache = null;

async function rdapBaseUrl(tld) {
  if (!rdapBootstrapCache) {
    try {
      const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", { timeout: 12000 });
      if (res.ok) rdapBootstrapCache = await res.json();
    } catch {
      rdapBootstrapCache = { services: [] };
    }
  }
  const services = rdapBootstrapCache?.services ?? [];
  for (const entry of services) {
    const [tlds, urls] = entry;
    if (Array.isArray(tlds) && tlds.includes(tld) && urls?.length) return urls[0];
  }
  return null;
}

async function checkDomainExpiry(domain) {
  if (isIpOrLocal(domain)) return [];
  const registrable = registrableDomain(domain);
  const tld = registrable.split(".").pop();

  let expiration = null;
  const bases = [];
  const iana = await rdapBaseUrl(tld);
  if (iana) bases.push(iana);
  if (tld === "com" || tld === "net") bases.push(`https://rdap.verisign.com/${tld}/v1/`);

  for (const base of bases) {
    try {
      const res = await fetchWithTimeout(
        `${base.replace(/\/$/, "")}/domain/${registrable}`,
        { timeout: 12000, headers: { accept: "application/rdap+json" } },
      );
      if (!res.ok) continue;
      const json = await res.json();
      expiration = (json.events ?? []).find((e) => e.eventAction === "expiration")?.eventDate;
      if (expiration) break;
    } catch {
      // Try the next registry endpoint.
    }
  }

  if (!expiration) return [];
  const days = Math.round((new Date(expiration).getTime() - Date.now()) / 86_400_000);

  if (days < 0) {
    return [
      finding(
        "domain_expired",
        "Domain registration expired",
        "critical",
        "The domain has lapsed. Anyone can register it and take over your traffic and email.",
        { evidence: `Expired ${Math.abs(days)} day(s) ago · ${expiration}` },
      ),
    ];
  }
  if (days <= 14) {
    return [
      finding(
        "domain_expiring",
        "Domain expires within 14 days",
        "high",
        "If renewal fails the site and its email stop working, and the domain can be snapped up by someone else.",
        { evidence: `Expires in ${days} day(s) · ${expiration}` },
      ),
    ];
  }
  if (days <= 45) {
    return [
      finding(
        "domain_expiring_soon",
        "Domain expires within 45 days",
        "medium",
        "Renew now so an expired card cannot take the site offline.",
        { evidence: `Expires in ${days} day(s) · ${expiration}` },
      ),
    ];
  }
  return [];
}

async function dohQuery(name, type) {
  try {
    const res = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { timeout: 9000, headers: { accept: "application/dns-json" } },
    );
    if (!res.ok) return null;
    const json = await res.json();
    if (json.Status !== 0) return null;
    return json.Answer ?? [];
  } catch {
    return null;
  }
}

async function checkDns(domain) {
  if (isIpOrLocal(domain)) return [];
  const registrable = registrableDomain(domain);
  const out = [];

  const [ns, mx] = await Promise.all([dohQuery(registrable, "NS"), dohQuery(registrable, "MX")]);

  if (ns && ns.length === 0) {
    out.push(
      finding(
        "dns_no_ns",
        "No nameservers returned",
        "high",
        "The domain has no NS records, which usually means DNS is misconfigured or the domain is suspended.",
        { evidence: registrable },
      ),
    );
  }
  if (mx && mx.length === 0) {
    out.push(
      finding(
        "dns_no_mx",
        "No mail records (MX)",
        "info",
        "The domain cannot receive email. Fine if you never plan to, a problem for password resets and reports.",
        { evidence: registrable },
      ),
    );
  }
  return out;
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

/**
 * Runs every check for one domain and returns a scan record.
 * Read-only against the target; the caller persists the result.
 */
export async function runChecks(rawDomain, { baseline = null } = {}) {
  const domain = normalizeDomain(rawDomain);
  const findings = [];
  const checkOutcomes = new Map(); // check_key -> { status: 'pass'|'finding'|'error', checkKey: string }
  const start = Date.now();

  const checksTotal =
    1 + // uptime
    1 + // http status
    1 + // tls
    SECURITY_HEADERS.length +
    1 + // server banner
    1 + // csp quality
    1 + // cors
    1 + // cookies
    1 + // mixed content
    1 + // directory listing
    EXPOSED_FILES.length +
    3 + // discovery
    1 + // leaked secrets
    1 + // domain expiry
    2 + // dns
    1; // defacement

  const page = await checkUptime(domain);

  if (!page.ok) {
    findings.push(
      finding("site_unreachable", "Site unreachable", "critical", "The site did not respond over HTTPS within 15 seconds.", {
        evidence: page.error,
      }),
    );
    checkOutcomes.set("site_unreachable", { status: "error", checkKey: "site_unreachable" });
    return {
      domain,
      status: "failed",
      httpStatus: null,
      responseMs: page.responseMs,
      checksTotal: 1,
      checksPassed: 0,
      findings,
      checkOutcomes: Object.fromEntries(checkOutcomes),
      error: page.error,
    };
  }

  if (page.status >= 500) {
    findings.push(
      finding("http_5xx", "Server error on the homepage", "critical", "The homepage returned a 5xx error.", {
        evidence: `HTTP ${page.status}`,
      }),
    );
    checkOutcomes.set("http_5xx", { status: "finding", checkKey: "http_5xx" });
  } else if (page.status >= 400) {
    findings.push(
      finding("http_4xx", "Homepage returned an error status", "high", "The homepage is not serving successfully.", {
        evidence: `HTTP ${page.status}`,
      }),
    );
    checkOutcomes.set("http_4xx", { status: "finding", checkKey: "http_4xx" });
  } else {
    checkOutcomes.set("http_status", { status: "pass", checkKey: "http_status" });
  }

  if (page.responseMs > 3000) {
    findings.push(
      finding("slow_response", "Slow homepage response", "low", "The homepage took over 3 seconds to respond.", {
        evidence: `${page.responseMs} ms`,
      }),
    );
    checkOutcomes.set("slow_response", { status: "finding", checkKey: "slow_response" });
  } else {
    checkOutcomes.set("response_time", { status: "pass", checkKey: "response_time" });
  }

  const tls = await checkTls(domain);
  if (!tls) {
    findings.push(
      finding("tls_unavailable", "TLS certificate could not be read", "high", "Could not establish a TLS session to read the certificate."),
    );
    checkOutcomes.set("tls_unavailable", { status: "error", checkKey: "tls_unavailable" });
  } else if (tls.days < 0) {
    findings.push(
      finding("tls_expired", "TLS certificate expired", "critical", "Browsers will show a full-page warning to every visitor.", {
        evidence: `Expired ${Math.abs(tls.days)} day(s) ago · ${tls.validTo}`,
      }),
    );
    checkOutcomes.set("tls_expired", { status: "finding", checkKey: "tls_expired" });
  } else if (tls.days <= 14) {
    findings.push(
      finding("tls_expiring", "TLS certificate expires soon", "high", `Certificate expires in ${tls.days} day(s).`, {
        evidence: `${tls.validTo} · issued by ${tls.issuer}`,
      }),
    );
    checkOutcomes.set("tls_expiring", { status: "finding", checkKey: "tls_expiring" });
  } else if (tls.days <= 30) {
    findings.push(
      finding("tls_expiring_soon", "TLS certificate expires within 30 days", "medium", `Certificate expires in ${tls.days} day(s).`, {
        evidence: `${tls.validTo} · issued by ${tls.issuer}`,
      }),
    );
    checkOutcomes.set("tls_expiring_soon", { status: "finding", checkKey: "tls_expiring_soon" });
  } else {
    checkOutcomes.set("tls", { status: "pass", checkKey: "tls" });
  }

  const headerFindings = checkHeaders(page.headers);
  findings.push(...headerFindings);
  headerFindings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  SECURITY_HEADERS.forEach(h => {
    if (!checkOutcomes.has(h.check)) {
      checkOutcomes.set(h.check, { status: "pass", checkKey: h.check });
    }
  });
  if (!checkOutcomes.has("server_banner")) {
    checkOutcomes.set("server_banner", { status: "pass", checkKey: "server_banner" });
  }

  const cspFindings = checkCspQuality(page.headers);
  findings.push(...cspFindings);
  cspFindings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!cspFindings.some(f => f.check_key.startsWith("csp_"))) {
    checkOutcomes.set("csp_quality", { status: "pass", checkKey: "csp_quality" });
  }

  const cookieFindings = checkCookies(page.headers);
  findings.push(...cookieFindings);
  cookieFindings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!cookieFindings.length) {
    checkOutcomes.set("cookie_flags", { status: "pass", checkKey: "cookie_flags" });
  }

  const mixedFindings = checkMixedContent(page.body, page.finalUrl);
  findings.push(...mixedFindings);
  mixedFindings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!mixedFindings.length) {
    checkOutcomes.set("mixed_content", { status: "pass", checkKey: "mixed_content" });
  }

  const dirFindings = checkDirectoryListing(page.body);
  findings.push(...dirFindings);
  dirFindings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!dirFindings.length) {
    checkOutcomes.set("directory_listing", { status: "pass", checkKey: "directory_listing" });
  }

  const defacement = checkDefacement(page.body, baseline);
  findings.push(...defacement.findings);
  defacement.findings.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!defacement.findings.length) {
    checkOutcomes.set("defacement", { status: "pass", checkKey: "defacement" });
  }

  const [exposed, cors, discovery, secrets, domainExpiry, dns] = await Promise.all([
    checkExposedFiles(domain),
    checkCors(domain),
    checkDiscovery(domain),
    checkLeakedSecrets(domain, page),
    checkDomainExpiry(domain),
    checkDns(domain),
  ]);

  findings.push(...exposed, ...cors, ...discovery, ...secrets, ...domainExpiry, ...dns);

  exposed.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  EXPOSED_FILES.forEach(f => {
    if (!checkOutcomes.has(f.check)) {
      checkOutcomes.set(f.check, { status: "pass", checkKey: f.check });
    }
  });

  cors.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!cors.length) {
    checkOutcomes.set("cors", { status: "pass", checkKey: "cors" });
  }

  discovery.forEach(f => {
    // Info findings still count as findings here. Their severity keeps them
    // out of the way in the threat queue without making the scan summary lie.
    checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key });
  });
  [
    ["robots", "robots_missing"],
    ["sitemap", "sitemap_missing"],
    ["security_txt", "security_txt_missing"],
  ].forEach(([prefix, passKey]) => {
    const hasOutcome = Array.from(checkOutcomes.keys()).some((key) => key.startsWith(prefix));
    if (!hasOutcome) checkOutcomes.set(passKey, { status: "pass", checkKey: passKey });
  });

  secrets.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!secrets.length) {
    checkOutcomes.set("leaked_secrets", { status: "pass", checkKey: "leaked_secrets" });
  }

  domainExpiry.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!domainExpiry.length) {
    checkOutcomes.set("domain_expiry", { status: "pass", checkKey: "domain_expiry" });
  }

  dns.forEach(f => checkOutcomes.set(f.check_key, { status: "finding", checkKey: f.check_key }));
  if (!dns.length) {
    checkOutcomes.set("dns_ns", { status: "pass", checkKey: "dns_ns" });
    checkOutcomes.set("dns_mx", { status: "pass", checkKey: "dns_mx" });
  }

  // De-duplicate by check key, keeping the first (most severe) occurrence.
  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    if (seen.has(f.check_key)) continue;
    seen.add(f.check_key);
    unique.push(f);
  }

  const passedCount = Array.from(checkOutcomes.values()).filter(o => o.status === 'pass').length;

  return {
    domain,
    status: "completed",
    httpStatus: page.status,
    responseMs: page.responseMs,
    checksTotal,
    checksPassed: passedCount,
    findings: unique,
    checkOutcomes: Object.fromEntries(checkOutcomes),
    tls,
    pageSample: defacement.sample,
    defacementSimilarity: defacement.similarity,
    durationMs: Date.now() - start,
  };
}

export { normalizeDomain, isUnsafeIp, hasUnsafeDns };
