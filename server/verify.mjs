import { resolveTxt } from "node:dns/promises";
import { normalizeDomain } from "./checks.mjs";

const UA = "BulwarkBot/0.1 (+https://bulwark.app/bot)";

/**
 * Ownership proof. Either:
 *   DNS  _bulwark.<domain>  TXT  "<token>"
 *   HTML <meta name="bulwark-verify" content="<token>">
 * Nothing is scanned until one of these passes.
 */
export async function verifyDomain(rawDomain, token) {
  const domain = normalizeDomain(rawDomain);

  try {
    const records = await resolveTxt(`_bulwark.${domain}`);
    const values = records.flat().map((v) => v.trim());
    if (values.includes(token)) return { ok: true, method: "dns" };
  } catch {
    // No TXT record; fall through to the meta tag.
  }

  try {
    const res = await fetch(`https://${domain}/`, {
      redirect: "follow",
      headers: { "user-agent": UA },
      signal: AbortSignal.timeout(15000),
    });
    const html = await res.text();
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(
      `<meta[^>]+name=["']bulwark-verify["'][^>]+content=["']${escaped}["']`,
      "i",
    );
    if (re.test(html)) return { ok: true, method: "meta" };
  } catch {
    // Site unreachable; verification simply fails.
  }

  return { ok: false, method: null };
}
