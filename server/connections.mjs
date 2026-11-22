import { decrypt, encrypt, maskSecret } from "./crypto.mjs";
import { normalizeSupabaseConnection } from "./supabase-config.mjs";

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
    lastScanStatus: row.last_scan_status ?? null,
    lastScanError: row.last_scan_error ?? null,
    lastScanCoverage: row.last_scan_coverage ?? null,
    ...(row.github_username ? { githubUsername: row.github_username } : {}),
    ...(row.project_ref ? { projectRef: row.project_ref, projectName: row.project_name } : {}),
    ...(type === "supabase"
      ? {
          autoScanEnabled: row.auto_scan_enabled ?? true,
          scanIntervalMinutes: row.scan_interval_minutes ?? 360,
          nextScanAt: row.next_scan_at ?? null,
        }
      : {}),
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

  const base = {
    user_id: userId,
    label: String(input?.label ?? "").trim() || null,
  };

  let insertFields;
  if (table === "github_connections") {
    const githubUsername = String(input?.githubUsername ?? "").trim();
    if (!githubUsername) throw new Error("GitHub username is required.");
    insertFields = {
      ...base,
      github_username: githubUsername,
      token_encrypted: encrypt(secret),
    };
  } else {
    const { projectRef, projectUrl } = normalizeSupabaseConnection(input);
    insertFields = {
      ...base,
      project_ref: projectRef,
      project_name: String(input?.projectName ?? "").trim() || null,
      project_url_encrypted: encrypt(projectUrl),
      api_key_encrypted: encrypt(secret),
    };
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

export async function updateSupabaseSchedule(db, userId, id, patch = {}) {
  const { data: existing, error: loadError } = await db
    .from("supabase_connections")
    .select("*")
    .eq("id", id)
    .eq("user_id", userId)
    .maybeSingle();
  if (loadError) throw new Error(`load supabase_connections: ${loadError.message}`);
  if (!existing) return null;

  const nextInterval =
    patch.scanIntervalMinutes !== undefined
      ? Number(patch.scanIntervalMinutes)
      : Number(existing.scan_interval_minutes ?? 360);
  if (!Number.isFinite(nextInterval) || nextInterval < 60 || nextInterval > 10080) {
    throw new Error("Supabase scan interval must be between 60 minutes and 7 days.");
  }
  const roundedInterval = Math.round(nextInterval);
  const autoScanEnabled =
    patch.autoScanEnabled !== undefined
      ? Boolean(patch.autoScanEnabled)
      : existing.auto_scan_enabled ?? true;

  const update = {
    auto_scan_enabled: autoScanEnabled,
    scan_interval_minutes: roundedInterval,
    next_scan_at: autoScanEnabled
      ? new Date(Date.now() + roundedInterval * 60_000).toISOString()
      : existing.next_scan_at ?? null,
  };

  const { data, error } = await db
    .from("supabase_connections")
    .update(update)
    .eq("id", id)
    .eq("user_id", userId)
    .select("*")
    .single();
  if (error) {
    if (/auto_scan_enabled|scan_interval_minutes|next_scan_at/i.test(error.message)) {
      throw new Error(
        "Scheduled Supabase scan columns are not set up yet. Run supabase/apply_all.sql in Supabase.",
      );
    }
    throw new Error(`update supabase schedule: ${error.message}`);
  }
  return publicConnection(data, "supabase");
}

export async function listGitHubSchedules(db, userId, connectionId) {
  const { data, error } = await db
    .from("github_repositories")
    .select(
      "id, owner, name, last_scanned_commit, last_scanned_at, auto_scan_enabled, scan_interval_minutes, next_scan_at",
    )
    .eq("user_id", userId)
    .eq("connection_id", connectionId)
    .order("name", { ascending: true });
  if (error) {
    if (/auto_scan_enabled|schema cache/i.test(error.message)) return [];
    throw new Error(`load github schedules: ${error.message}`);
  }
  return (data ?? []).map((row) => ({
    id: row.id,
    owner: row.owner,
    repo: row.name,
    fullName: `${row.owner}/${row.name}`,
    lastScannedCommit: row.last_scanned_commit ?? null,
    lastScannedAt: row.last_scanned_at ?? null,
    autoScanEnabled: row.auto_scan_enabled === true,
    scanIntervalMinutes: row.scan_interval_minutes ?? 1440,
    nextScanAt: row.next_scan_at ?? null,
  }));
}

export async function updateGitHubSchedule(
  db,
  userId,
  connectionId,
  { owner, repo, autoScanEnabled, scanIntervalMinutes } = {},
) {
  const { data: conn, error: connErr } = await db
    .from("github_connections")
    .select("id")
    .eq("id", connectionId)
    .eq("user_id", userId)
    .maybeSingle();
  if (connErr) throw new Error(`load github_connections: ${connErr.message}`);
  if (!conn) return null;

  const cleanOwner = String(owner ?? "").trim();
  const cleanRepo = String(repo ?? "").trim();
  if (!cleanOwner || !cleanRepo) throw new Error("Repository owner and name are required.");

  const minutes = scanIntervalMinutes !== undefined ? Number(scanIntervalMinutes) : 1440;
  if (!Number.isFinite(minutes) || minutes < 360 || minutes > 10080) {
    throw new Error("GitHub scan interval must be between 6 hours and 7 days.");
  }
  const rounded = Math.round(minutes);
  const enabled = Boolean(autoScanEnabled);

  const { data, error } = await db
    .from("github_repositories")
    .upsert(
      {
        user_id: userId,
        connection_id: connectionId,
        owner: cleanOwner,
        name: cleanRepo,
        auto_scan_enabled: enabled,
        scan_interval_minutes: rounded,
        next_scan_at: enabled ? new Date(Date.now() + rounded * 60_000).toISOString() : null,
      },
      { onConflict: "connection_id,owner,name" },
    )
    .select("*")
    .single();
  if (error) {
    if (/auto_scan_enabled|scan_interval_minutes|next_scan_at/i.test(error.message)) {
      throw new Error(
        "Scheduled GitHub scan columns are not set up yet. Run supabase/apply_all.sql in Supabase.",
      );
    }
    throw new Error(`update github schedule: ${error.message}`);
  }
  return {
    id: data.id,
    owner: data.owner,
    repo: data.name,
    fullName: `${data.owner}/${data.name}`,
    autoScanEnabled: data.auto_scan_enabled === true,
    scanIntervalMinutes: data.scan_interval_minutes ?? rounded,
    nextScanAt: data.next_scan_at ?? null,
  };
}
