// Strict validation for Supabase project connections.
//
// The outbound host is always derived from the project reference
// (https://<ref>.supabase.co). A user-supplied URL is only accepted when its
// origin matches that canonical host exactly. This removes arbitrary-host SSRF
// from the connector instead of trying to filter arbitrary URLs.

const PROJECT_REF_RE = /^[a-z0-9]{10,32}$/;

export function canonicalSupabaseUrl(projectRef) {
  const ref = String(projectRef ?? "").trim().toLowerCase();
  if (!PROJECT_REF_RE.test(ref)) {
    throw new Error(
      "Supabase project reference must be 10-32 lowercase letters or digits (for example abcdefghijklmnopqrst).",
    );
  }
  return `https://${ref}.supabase.co`;
}

export function assertSupabaseProjectUrl(projectUrl, projectRef = null) {
  let parsed;
  try {
    parsed = new URL(String(projectUrl ?? "").trim());
  } catch {
    throw new Error("Supabase project URL is not a valid URL.");
  }

  if (parsed.protocol !== "https:") {
    throw new Error("Supabase project URL must use HTTPS.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Supabase project URL must not contain credentials.");
  }
  if (parsed.port) {
    throw new Error("Supabase project URL must not use a custom port.");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("Supabase project URL must be only the project origin.");
  }

  const host = parsed.hostname.toLowerCase();
  const suffix = ".supabase.co";
  if (!host.endsWith(suffix)) {
    throw new Error("Supabase project URL must be a *.supabase.co host.");
  }

  const refFromHost = host.slice(0, -suffix.length);
  if (!PROJECT_REF_RE.test(refFromHost)) {
    throw new Error("Supabase project URL does not contain a valid project reference.");
  }
  if (projectRef && refFromHost !== String(projectRef).trim().toLowerCase()) {
    throw new Error("Supabase project URL does not match the project reference.");
  }

  return `https://${refFromHost}.supabase.co`;
}

function decodeJwtPayload(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/**
 * Bulwark only needs a publishable/anon key. Reject service-role credentials so
 * a read-only project check cannot become a full database takeover credential.
 */
export function assertLeastPrivilegeKey(apiKey) {
  const key = String(apiKey ?? "").trim();
  if (!key) throw new Error("Missing Supabase API key.");

  if (key.startsWith("sb_secret_")) {
    throw new Error(
      "Bulwark never needs a Supabase secret/service-role key. Use the publishable (anon) key instead.",
    );
  }
  if (key.startsWith("sb_publishable_")) return "publishable";

  if (key.startsWith("eyJ")) {
    const payload = decodeJwtPayload(key);
    if (!payload) throw new Error("That Supabase key is not a readable JWT.");
    if (payload.role === "service_role") {
      throw new Error(
        "Bulwark never needs a Supabase service-role key. Use the anon (publishable) key instead.",
      );
    }
    if (payload.role !== "anon") {
      throw new Error("Use the Supabase publishable/anon key, not a user or service key.");
    }
    return "anon";
  }

  throw new Error(
    "Unrecognized Supabase key. Use the project's publishable key or legacy anon JWT.",
  );
}

export function normalizeSupabaseConnection(input) {
  const projectRef = String(input?.projectRef ?? "").trim().toLowerCase();
  const canonical = canonicalSupabaseUrl(projectRef);
  const suppliedUrl = String(input?.projectUrl ?? "").trim();

  if (suppliedUrl) {
    const normalized = assertSupabaseProjectUrl(suppliedUrl, projectRef);
    if (normalized !== canonical) {
      throw new Error("Supabase project URL does not match the project reference.");
    }
  }

  const keyType = assertLeastPrivilegeKey(input?.apiKey);
  return { projectRef, projectUrl: canonical, keyType };
}
