import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

/** True when .env.local has both public Supabase values. */
export const isSupabaseConfigured = Boolean(
  url && anonKey && !url.includes("YOUR-PROJECT") && !anonKey.includes("YOUR-ANON"),
);

/**
 * Null when Supabase is not configured yet, so the UI can keep rendering
 * with demo data instead of crashing.
 */
export const supabase: SupabaseClient | null = isSupabaseConfigured
  ? createClient(url as string, anonKey as string, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null;
