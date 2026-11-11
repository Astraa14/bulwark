import { PROVIDERS, isProvider } from "./ai.mjs";
import { decrypt, encrypt, maskSecret } from "./crypto.mjs";

function publicKey(row) {
  let preview = "••••••••";
  try {
    preview = maskSecret(decrypt(row.key_encrypted));
  } catch {
    preview = "unreadable";
  }
  return {
    id: row.id,
    provider: row.provider,
    providerLabel: PROVIDERS[row.provider]?.label ?? row.provider,
    label: row.label,
    model: row.model ?? PROVIDERS[row.provider]?.defaultModel ?? null,
    preview,
    monthlyLimitUsd: Number(row.monthly_limit_usd ?? 0),
    lastUsedAt: row.last_used_at,
    createdAt: row.created_at,
  };
}

export async function listKeys(db, userId) {
  const { data, error } = await db
    .from("api_keys")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });
  if (error) throw new Error(`load keys: ${error.message}`);
  return (data ?? []).map(publicKey);
}

export async function addKey(db, userId, input) {
  const provider = String(input?.provider ?? "").toLowerCase();
  const secret = String(input?.key ?? "").trim();

  if (!isProvider(provider)) throw new Error("Choose OpenAI or Anthropic.");
  if (secret.length < 20) throw new Error("That key looks too short to be valid.");
  if (secret.length > 400) throw new Error("That key looks too long to be valid.");

  const model = String(input?.model ?? "").trim() || PROVIDERS[provider].defaultModel;

  const { data, error } = await db
    .from("api_keys")
    .insert({
      user_id: userId,
      provider,
      label: String(input?.label ?? "").trim() || `${PROVIDERS[provider].label} key`,
      key_encrypted: encrypt(secret),
      model,
    })
    .select("*")
    .single();

  if (error) throw new Error(`save key: ${error.message}`);
  return publicKey(data);
}

export async function deleteKey(db, userId, id) {
  if (!id) throw new Error("Missing key id.");
  const { error } = await db.from("api_keys").delete().eq("id", id).eq("user_id", userId);
  if (error) throw new Error(`delete key: ${error.message}`);
}

/** Returns the newest working key for a provider (or any provider if omitted). */
export async function resolveKey(db, userId, provider) {
  let query = db.from("api_keys").select("*").eq("user_id", userId);
  if (provider) query = query.eq("provider", provider);
  const { data, error } = await query.order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw new Error(`load key: ${error.message}`);
  if (!data) return null;

  try {
    return {
      id: data.id,
      provider: data.provider,
      model: data.model || PROVIDERS[data.provider]?.defaultModel,
      apiKey: decrypt(data.key_encrypted),
    };
  } catch {
    throw new Error("The stored AI key could not be decrypted. Remove it and add it again.");
  }
}

export async function markKeyUsed(db, id) {
  if (!id) return;
  await db.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", id);
}
