import { resolveTxt } from "node:dns/promises";
import {
  normalizeDomain,
  isUnsafeIp,
  hasUnsafeDns,
  ensureSafeFetchUrl,
  fetchWithTimeout,
} from "./checks.mjs";

const UA = "BulwarkBot/0.4 (+https://bulwark.app/bot)";

/**
 * Ownership proof. Either:
 *   DNS  _bulwark.<domain>  TXT  "<token>"
 *   HTML <meta name="bulwark-verify" content="<token>">
 * Nothing is scanned until one of these passes.
 */
export async function verifyDomain(rawDomain, token) {
  const domain = normalizeDomain(rawDomain);

  // Validate domain doesn't resolve to unsafe IP. DNS failure is unsafe.
  if (await hasUnsafeDns(domain)) {
    return { ok: false, method: null, error: "Domain resolves to unsafe IP range" };
  }

  try {
    const records = await resolveTxt(`_bulwark.${domain}`);
    const values = records.flat().map((v) => v.trim());
    if (values.includes(token)) return { ok: true, method: "dns" };
  } catch {
    // No TXT record; fall through to the meta tag.
  }

  try {
    let redirectCount = 0;
    const maxRedirects = 5;
    let currentUrl = `https://${domain}/`;

    while (redirectCount <= maxRedirects) {
      // ensureSafeFetchUrl validates scheme, host, port, and DNS before each hop.
      currentUrl = await ensureSafeFetchUrl(currentUrl);

      const res = await fetchWithTimeout(currentUrl, {
        timeout: 15000,
        headers: { "user-agent": UA },
      });

      if (res.error) {
        return { ok: false, method: null, error: res.error };
      }
      if (res.status === null) {
        return { ok: false, method: null, error: "no response" };
      }

      // Validate redirect target before following.
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers["location"];
        if (!location) break;
        const nextUrl = new URL(location, currentUrl);
        if (!["http:", "https:"].includes(nextUrl.protocol)) {
          return { ok: false, method: null, error: "Redirect to unsupported scheme" };
        }
        if (isUnsafeIp(nextUrl.hostname) || await hasUnsafeDns(nextUrl.hostname)) {
          return { ok: false, method: null, error: "Redirect to unsafe IP range" };
        }
        const port = Number(nextUrl.port) || (nextUrl.protocol === "https:" ? 443 : 80);
        if (port !== 80 && port !== 443) {
          return { ok: false, method: null, error: "Redirect to non-web port" };
        }

        redirectCount += 1;
        currentUrl = nextUrl.toString();
        continue;
      }

      // Not a redirect: check for the meta tag.
      const html = res.body ?? "";
      const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(
        `<meta[^>]+name=["']bulwark-verify["'][^>]+content=["']${escaped}["']`,
        "i",
      );
      if (re.test(html)) return { ok: true, method: "meta" };
      break;
    }

    if (redirectCount > maxRedirects) {
      return { ok: false, method: null, error: "Too many redirects" };
    }
  } catch {
    // Site unreachable or blocked; verification simply fails.
  }

  return { ok: false, method: null };
}
