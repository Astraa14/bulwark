-- Read-only GitHub repository connections.
--
-- Users connect a GitHub personal access token so Bulwark can scan their
-- repositories for hardcoded secrets, dependency issues, and exposed config.
-- Tokens are encrypted at rest with BULWARK_ENCRYPTION_KEY and are writeable
-- only by the server (service role), never from the browser.

create table if not exists public.github_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  github_username text not null,
  -- Encrypted GitHub personal access token (read-only repo scope recommended).
  token_encrypted text not null,
  label text,
  last_checked_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.github_connections enable row level security;

drop policy if exists "github_connections_select_own" on public.github_connections;
create policy "github_connections_select_own" on public.github_connections
  for select using (auth.uid() = user_id);

drop policy if exists "github_connections_delete_own" on public.github_connections;
create policy "github_connections_delete_own" on public.github_connections
  for delete using (auth.uid() = user_id);

-- No insert/update policy on purpose: connections are written only by the
-- server (service role) so plaintext tokens never pass through the browser.

create index if not exists github_connections_user_idx on public.github_connections (user_id);
