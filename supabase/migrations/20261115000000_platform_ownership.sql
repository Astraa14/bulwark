-- Platform ownership, repository-level scan identity, and durable scan jobs.
--
-- Website findings/scans are owned through their site. Platform findings
-- (GitHub/Supabase) have no site, so ownership is recorded directly and
-- enforced by RLS. Legacy platform rows without a provable owner are left in
-- place but become invisible until an owner can be established.
--
-- This migration is additive and safe to re-run. It deliberately does not add
-- a hard owner-shape CHECK constraint: the previously deployed code inserts
-- platform rows without an owner, and a CHECK would make those scans fail during
-- the window between running this SQL and deploying the new application code.
-- RLS, not a CHECK, is what prevents unowned rows from being exposed.

-- ---------------------------------------------------------------------------
-- findings: explicit owner + source identity
-- ---------------------------------------------------------------------------
alter table public.findings
  add column if not exists user_id uuid references auth.users (id) on delete cascade,
  add column if not exists platform text,
  add column if not exists connection_id uuid,
  add column if not exists resource text,
  add column if not exists commit_sha text,
  add column if not exists ref text;

-- Backfill only where ownership is provable from the linked site. Platform
-- rows with no site cannot be attributed safely, so they stay unowned and are
-- hidden by RLS below.
update public.findings f
set user_id = s.user_id
from public.sites s
where f.site_id = s.id
  and f.user_id is null;

alter table public.findings
  drop constraint if exists findings_platform_check;
alter table public.findings
  add constraint findings_platform_check
  check (platform is null or platform in ('github', 'supabase'));

create index if not exists findings_user_status_idx
  on public.findings (user_id, status, severity);
create index if not exists findings_platform_identity_idx
  on public.findings (user_id, platform, connection_id, resource, check_key);

-- Ownership-only RLS. Browser clients may read/status-update their own rows;
-- inserts/deletes remain server-only.
alter table public.findings enable row level security;

drop policy if exists "findings_select_own" on public.findings;
create policy "findings_select_own" on public.findings
  for select using (auth.uid() = user_id);

drop policy if exists "findings_update_own" on public.findings;
create policy "findings_update_own" on public.findings
  for update using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- scans: platform identity + idempotency
-- ---------------------------------------------------------------------------
alter table public.scans
  add column if not exists user_id uuid references auth.users (id) on delete cascade,
  add column if not exists platform text,
  add column if not exists connection_id uuid,
  add column if not exists resource text,
  add column if not exists commit_sha text,
  add column if not exists ref text,
  add column if not exists idempotency_key text,
  add column if not exists delivery_id text,
  add column if not exists coverage jsonb;

update public.scans sc
set user_id = s.user_id
from public.sites s
where sc.site_id = s.id
  and sc.user_id is null;

alter table public.scans
  drop constraint if exists scans_platform_check;
alter table public.scans
  add constraint scans_platform_check
  check (platform is null or platform in ('github', 'supabase'));

create unique index if not exists scans_site_idempotency_idx
  on public.scans (site_id, idempotency_key)
  where site_id is not null and idempotency_key is not null;

-- A GitHub delivery is unique per connection, not globally. The same delivery
-- ID must never create a second scan for that connection.
drop index if exists public.scans_delivery_id_idx;
create unique index if not exists scans_connection_delivery_idx
  on public.scans (connection_id, delivery_id)
  where connection_id is not null and delivery_id is not null;

create index if not exists scans_user_idx
  on public.scans (user_id, started_at desc);

alter table public.scans enable row level security;

drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own" on public.scans
  for select using (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- github_repositories: last scanned revision per repository, not per token
-- ---------------------------------------------------------------------------
create table if not exists public.github_repositories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  connection_id uuid not null references public.github_connections (id) on delete cascade,
  owner text not null,
  name text not null,
  last_scanned_commit text,
  last_scanned_ref text,
  last_scanned_at timestamptz,
  created_at timestamptz not null default now(),
  unique (connection_id, owner, name)
);

alter table public.github_repositories enable row level security;

drop policy if exists "github_repositories_select_own" on public.github_repositories;
create policy "github_repositories_select_own" on public.github_repositories
  for select using (auth.uid() = user_id);

create index if not exists github_repositories_user_idx
  on public.github_repositories (user_id);
create index if not exists github_repositories_connection_idx
  on public.github_repositories (connection_id);

-- ---------------------------------------------------------------------------
-- connection-level last-scan summary (coverage is visible in the UI)
-- ---------------------------------------------------------------------------
alter table public.github_connections
  add column if not exists last_scan_status text,
  add column if not exists last_scan_error text,
  add column if not exists last_scan_coverage jsonb;

alter table public.supabase_connections
  add column if not exists last_scan_status text,
  add column if not exists last_scan_error text,
  add column if not exists last_scan_coverage jsonb;

-- ---------------------------------------------------------------------------
-- durable platform scan jobs (webhooks are acknowledged, then queued)
-- ---------------------------------------------------------------------------
create table if not exists public.platform_scan_jobs (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null default gen_random_uuid() unique,
  user_id uuid not null references auth.users (id) on delete cascade,
  platform text not null check (platform in ('github', 'supabase')),
  connection_id uuid not null,
  resource text not null,
  ref text,
  commit_sha text,
  delivery_id text,
  status text not null default 'queued'
    check (status in ('queued', 'running', 'completed', 'failed')),
  attempts integer not null default 0,
  last_error text,
  run_after timestamptz not null default now(),
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz
);

-- One delivery ID is unique per connection. A repeated GitHub delivery must
-- never enqueue a second scan.
create unique index if not exists platform_scan_jobs_delivery_idx
  on public.platform_scan_jobs (connection_id, delivery_id)
  where delivery_id is not null;

create index if not exists platform_scan_jobs_claim_idx
  on public.platform_scan_jobs (status, run_after, created_at);

alter table public.platform_scan_jobs enable row level security;
-- No browser policy: jobs are service-role only.
