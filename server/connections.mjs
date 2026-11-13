import { decrypt, encrypt, maskSecret } from "./crypto.mjs";

function publicConnection(row, type) {
  let preview = "••••••••";
  try {
    preview = maskSecret(decrypt(row.token_encrypted ?? row.api_key_encrypted ?? ""));
  } catch {
    preview = "unreadable";
  }
  return {
    id: row.id,
    type,
    label: row.label ?? null,
    preview,
    lastCheckedAt: row.last_checked_at,
    createdAt: row.created_at,
    lastScannedCommit: row.last_scanned_commit ?? null,
    ...(row.github_username ? { githubUsername: row.github_username } : {}),
    ...(row.project_ref ? { projectRef: row.project_ref, projectName: row.project_name } : {}),
  };
}

export async function listConnections(db, userId, table) {
  const { data, error } = await db
    .from(table)
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });
  if (error) throw new Error(`load ${table}: ${error.message}`);
  return (data ?? []).map((row) => publicConnection(row, table.includes("github") ? "github" : "supabase"));
}

export async function addConnection(db, userId, table, input) {
  const secret = String(input?.token ?? input?.apiKey ?? "").trim();
  if (!secret) throw new Error("Missing token or API key.");
  if (secret.length < 10) throw new Error("That token looks too short to be valid.");

  const insertFields = {
    user_id: userId,
    label: String(input?.label ?? "").trim() || null,
    ...(table === "github_connections"
      ? { github_username: String(input?.githubUsername ?? "").trim(), token_encrypted: encrypt(secret) }
      : {
          project_ref: String(input?.projectRef ?? "").trim(),
          project_name: String(input?.projectName ?? "").trim() || null,
          project_url_encrypted: encrypt(String(input?.projectUrl ?? "").trim()),
          api_key_encrypted: encrypt(secret),
        }),
  };

  // Validate required fields per type.
  if (table === "github_connections" && !insertFields.github_username) {
    throw new Error("GitHub username is required.");
  }
  if (table === "supabase_connections" && !insertFields.project_ref) {
    throw new Error("Supabase project ref is required.");
  }
  if (table === "supabase_connections" && !insertFields.project_url_encrypted) {
    throw new Error("Supabase project URL is required.");
  }

  const { data, error } = await db.from(table).insert(insertFields).select("*").single();
  if (error) throw new Error(`save ${table}: ${error.message}`);
  return publicConnection(data, table.includes("github") ? "github" : "supabase");
}

export async function deleteConnection(db, userId, id, table) {
  if (!id) throw new Error("Missing connection id.");
  const { error } = await db.from(table).delete().eq("id", id).eq("user_id", userId);
  if (error) throw new Error(`delete ${table}: ${error.message}`);
}

export async function resolveConnection(db, userId, id, table) {
  const { data, error } = await db.from(table).select("*").eq("id", id).eq("user_id", userId).maybeSingle();
  if (error) throw new Error(`load ${table}: ${error.message}`);
  if (!data) return null;

  try {
    const decrypted = decrypt(data.token_encrypted ?? data.api_key_encrypted ?? "");
    return {
      id: data.id,
      type: table.includes("github") ? "github" : "supabase",
      ...(table === "github_connections"
        ? { token: decrypted, githubUsername: data.github_username, lastScannedCommit: data.last_scanned_commit ?? null }
        : { apiKey: decrypted, projectUrl: decrypt(data.project_url_encrypted ?? ""), projectRef: data.project_ref, projectName: data.project_name }),
    };
  } catch {
    throw new Error("The stored connection could not be decrypted. Remove it and add it again.");
  }
}

export async function setWebhookSecret(db, userId, id, secret) {
  const { data, error } = await db
    .from("github_connections")
    .select("*")
    .eq("id", id)
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw new Error(`load connection: ${error.message}`);
  if (!data) throw new Error("GitHub connection not found.");

  const encrypted = encrypt(secret);
  const { error: updateError } = await db
    .from("github_connections")
    .update({ webhook_secret_encrypted: encrypted })
    .eq("id", id);
  if (updateError) throw new Error(`save webhook secret: ${updateError.message}`);

  return { ok: true };
}
}
