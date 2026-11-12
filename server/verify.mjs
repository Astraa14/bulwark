import { resolveTxt } from "node:dns/promises";
import { normalizeDomain, isUnsafeIp, hasUnsafeDns } from "./checks.mjs";

const UA = "BulwarkBot/0.1 (+https://bulwark.app/bot)";

/**
 * Ownership proof. Either:
 *   DNS  _bulwark.<domain>  TXT  "<token>"
 *   HTML <meta name="bulwark-verify" content="<token>">
 * Nothing is scanned until one of these passes.
 */
export async function verifyDomain(rawDomain, token) {
  const domain = normalizeDomain(rawDomain);

  // Validate domain doesn't resolve to unsafe IP
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
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);

    let redirectCount = 0;
    const maxRedirects = 5;
    let currentUrl = `https://${domain}/`;

    while (redirectCount <= maxRedirects) {
      const res = await fetch(currentUrl, {
        redirect: "manual",
        headers: { "user-agent": UA },
        signal: controller.signal,
      });

      // Validate redirect target
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) break;

        const nextUrl = new URL(location, currentUrl);
        if (await hasUnsafeDns(nextUrl.hostname)) {
          clearTimeout(timer);
          return { ok: false, method: null, error: "Redirect to unsafe IP range" };
        }

        redirectCount++;
        currentUrl = nextUrl.toString();
        continue;
      }

      // Not a redirect, check for meta tag
      const html = await res.text();
      clearTimeout(timer);

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
    // Site unreachable; verification simply fails.
  }

  return { ok: false, method: null };
}
