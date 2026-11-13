-- Read-only Supabase project connections.
--
-- Users connect a Supabase project URL + API key so Bulwark can inspect
-- Row Level Security policies, table exposure, and storage bucket settings.
-- Credentials are encrypted at rest with BULWARK_ENCRYPTION_KEY and are
-- writeable only by the server (service role), never from the browser.

create table if not exists public.supabase_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_ref text not null,
  project_name text,
  -- Encrypted Supabase project URL and API key.
  project_url_encrypted text not null,
  api_key_encrypted text not null,
  label text,
  last_checked_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.supabase_connections enable row level security;

drop policy if exists "supabase_connections_select_own" on public.supabase_connections;
create policy "supabase_connections_select_own" on public.supabase_connections
  for select using (auth.uid() = user_id);

drop policy if exists "supabase_connections_delete_own" on public.supabase_connections;
create policy "supabase_connections_delete_own" on public.supabase_connections
  for delete using (auth.uid() = user_id);

-- No insert/update policy on purpose: connections are written only by the
-- server (service role) so plaintext credentials never pass through the browser.

create index if not exists supabase_connections_user_idx on public.supabase_connections (user_id);
