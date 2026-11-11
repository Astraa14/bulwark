import { supabase } from "./supabase";

function apiBase() {
  const url = import.meta.env.VITE_API_URL;
  return url ? url.replace(/\/$/, "") : "";
}

async function authToken() {
  if (!supabase) throw new Error("Supabase is not configured.");
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("You are signed out. Please sign in again.");
  return token;
}

export async function apiFetch<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const token = await authToken();
  const base = apiBase();
  const res = await fetch(`${base}${path}`, {
    method: init.method ?? "GET",
    headers: {
      authorization: `Bearer ${token}`,
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });

  const json = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(json.error ?? `Request failed (${res.status})`);
  return json as T;
}

export const apiGet = <T>(path: string) => apiFetch<T>(path);
export const apiPost = <T>(path: string, body: unknown) => apiFetch<T>(path, { method: "POST", body });
export const apiPut = <T>(path: string, body: unknown) => apiFetch<T>(path, { method: "PUT", body });
export const apiDelete = <T>(path: string) => apiFetch<T>(path, { method: "DELETE" });
