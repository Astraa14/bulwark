-- Bulwark v1 schema
-- Run this in Supabase Dashboard -> SQL Editor (or `supabase db push`).

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- profiles
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  full_name text,
  plan text not null default 'free',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id)
  with check (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own" on public.profiles
  for insert with check (auth.uid() = id);

-- ---------------------------------------------------------------------------
-- sites
-- ---------------------------------------------------------------------------
create table if not exists public.sites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  domain text not null,
  display_name text,
  -- pending: awaiting ownership proof | verified: being scanned | paused
  status text not null default 'pending'
    check (status in ('pending', 'verified', 'paused')),
  verify_token text not null default encode(gen_random_bytes(16), 'hex'),
  scan_interval_minutes integer not null default 360,
  autonomy text not null default 'suggest'
    check (autonomy in ('suggest', 'auto_fix')),
  last_scan_at timestamptz,
  next_scan_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (user_id, domain)
);

create index if not exists sites_due_idx on public.sites (next_scan_at)
  where status = 'verified';
create index if not exists sites_user_idx on public.sites (user_id);

alter table public.sites enable row level security;

drop policy if exists "sites_own" on public.sites;
create policy "sites_own" on public.sites
  for all using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  site_id uuid not null references public.sites (id) on delete cascade,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  status text not null default 'running'
    check (status in ('running', 'completed', 'failed')),
  http_status integer,
  response_ms integer,
  checks_total integer not null default 0,
  checks_passed integer not null default 0,
  error text
);

create index if not exists scans_site_idx on public.scans (site_id, started_at desc);

alter table public.scans enable row level security;

drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own" on public.scans
  for select using (
    exists (
      select 1 from public.sites s
      where s.id = scans.site_id and s.user_id = auth.uid()
    )
  );

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------
create table if not exists public.findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  site_id uuid not null references public.sites (id) on delete cascade,
  check_key text not null,
  title text not null,
  severity text not null
    check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  status text not null default 'open'
    check (status in ('open', 'acknowledged', 'resolved', 'ignored')),
  detail text,
  evidence text,
  url text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create index if not exists findings_site_status_idx
  on public.findings (site_id, status, severity);
create index if not exists findings_scan_idx on public.findings (scan_id);

alter table public.findings enable row level security;

drop policy if exists "findings_select_own" on public.findings;
create policy "findings_select_own" on public.findings
  for select using (
    exists (
      select 1 from public.sites s
      where s.id = findings.site_id and s.user_id = auth.uid()
    )
  );

drop policy if exists "findings_update_own" on public.findings;
create policy "findings_update_own" on public.findings
  for update using (
    exists (
      select 1 from public.sites s
      where s.id = findings.site_id and s.user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.sites s
      where s.id = findings.site_id and s.user_id = auth.uid()
    )
  );

-- ---------------------------------------------------------------------------
-- api_keys (BYOK, encrypted server-side; never readable from the browser)
-- ---------------------------------------------------------------------------
create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  provider text not null
    check (provider in ('openai', 'anthropic', 'gemini', 'openrouter')),
  label text,
  -- value is encrypted by the scanner/server with BULWARK_ENCRYPTION_KEY
  key_encrypted text not null,
  model text,
  monthly_limit_usd numeric(10, 2) not null default 5,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.api_keys enable row level security;

drop policy if exists "api_keys_select_own" on public.api_keys;
create policy "api_keys_select_own" on public.api_keys
  for select using (auth.uid() = user_id);

drop policy if exists "api_keys_delete_own" on public.api_keys;
create policy "api_keys_delete_own" on public.api_keys
  for delete using (auth.uid() = user_id);

-- no insert/update policy on purpose: keys are written only by the server
-- (service role) so plaintext never passes through the browser.

-- ---------------------------------------------------------------------------
-- profile bootstrap on signup
-- ---------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
