-- ===========================================================================
-- Bulwark: run this once in Supabase -> SQL Editor -> New query.
-- Combines every migration in order. All statements are idempotent, so it is
-- safe to re-run this file after updating the app.
-- ===========================================================================

-- >>> supabase/migrations/20261111000000_init.sql
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


-- >>> supabase/migrations/20261111010000_features.sql
-- Bulwark v1.1: AI explanations, alert channels, settings, defacement baseline
-- Fully idempotent: safe to paste into the Supabase SQL editor more than once.

-- ---------------------------------------------------------------------------
-- Faster default scan cadence (60 minutes)
-- ---------------------------------------------------------------------------
alter table public.sites alter column scan_interval_minutes set default 60;
update public.sites set scan_interval_minutes = 60 where scan_interval_minutes = 360;

-- Defacement baseline (normalized visible text of the last accepted homepage)
alter table public.sites
  add column if not exists page_sample text,
  add column if not exists page_sample_at timestamptz;

-- Cached AI explanations so each finding is only paid for once
alter table public.findings
  add column if not exists explanation text,
  add column if not exists explanation_model text,
  add column if not exists explained_at timestamptz;

-- ---------------------------------------------------------------------------
-- user_settings: per-user workspace preferences + alert channel
-- ---------------------------------------------------------------------------
create table if not exists public.user_settings (
  user_id uuid primary key references auth.users (id) on delete cascade,
  scan_interval_minutes integer not null default 60,
  autonomy text not null default 'suggest'
    check (autonomy in ('suggest', 'auto_fix')),
  slack_webhook_url text,
  slack_min_severity text not null default 'high'
    check (slack_min_severity in ('critical', 'high', 'medium', 'low', 'info')),
  alerts_enabled boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.user_settings enable row level security;

drop policy if exists "user_settings_own" on public.user_settings;
create policy "user_settings_own" on public.user_settings
  for all using (auth.uid() = user_id)
  with check (auth.uid() = user_id);


-- >>> supabase/migrations/20261112000000_harden_sites.sql
-- ---------------------------------------------------------------------------
-- Harden ownership verification.
--
-- Before this migration the browser could update its own sites row, including
-- `status`, so "pending -> verified" was possible without proving ownership.
-- Verification must only ever be granted by the API (service role) after the
-- DNS TXT record or meta tag check passes.
--
-- Strategy:
--   1. Trigger: force client inserts to `pending` and freeze server-managed
--      columns on client updates.
--   2. Column privileges: authenticated users may only edit display_name,
--      autonomy and scan_interval_minutes.
-- ---------------------------------------------------------------------------

create or replace function public.guard_site_writes()
returns trigger
language plpgsql
set search_path = public, extensions
as $$
declare
  jwt_claims text := current_setting('request.jwt.claims', true);
  legacy_role text := current_setting('request.jwt.claim.role', true);
  req_role text := coalesce(
    nullif(jwt_claims, '')::jsonb ->> 'role',
    nullif(legacy_role, ''),
    ''
  );
  privileged boolean :=
    session_user in ('postgres', 'supabase_admin')
    or req_role in ('service_role', 'postgres', 'supabase_admin');
begin
  if privileged then
    return new;
  end if;

  if tg_op = 'INSERT' then
    -- A site is never born verified: ownership must be proven first.
    new.status := 'pending';
    new.verify_token := encode(gen_random_bytes(16), 'hex');
    new.next_scan_at := now();
    new.last_scan_at := null;
    return new;
  end if;

  -- UPDATE: server-managed columns are read-only for the browser.
  if new.id is distinct from old.id
     or new.user_id is distinct from old.user_id
     or new.domain is distinct from old.domain
     or new.status is distinct from old.status
     or new.verify_token is distinct from old.verify_token
     or new.last_scan_at is distinct from old.last_scan_at
     or new.next_scan_at is distinct from old.next_scan_at
     or new.created_at is distinct from old.created_at
     or (to_jsonb(new) ->> 'page_sample') is distinct from (to_jsonb(old) ->> 'page_sample') then
    raise exception 'That site field is managed by Bulwark and cannot be changed from the client.'
      using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists guard_site_writes on public.sites;
create trigger guard_site_writes
before insert or update on public.sites
for each row execute function public.guard_site_writes();

-- Defense in depth: even if a future policy is loosened, the browser cannot
-- write status, tokens, scheduling or baseline data.
revoke update on public.sites from anon, authenticated;
grant update (display_name, autonomy, scan_interval_minutes)
  on public.sites to authenticated;


-- >>> supabase/migrations/20261113000000_improve_findings.sql
-- Improve finding identity and lifecycle
-- Add columns for better tracking of findings with affected resources and status history

-- Add new columns to findings table
alter table public.findings
  add column if not exists affected_resource text,
  add column if not exists confidence text default 'medium'
    check (confidence in ('high', 'medium', 'low')),
  add column if not exists what_it_does_not_prove text,
  add column if not exists remediation text,
  add column if not exists status_history jsonb default '[]'::jsonb,
  add column if not exists muted_until timestamptz;

-- Create index on affected_resource for better lookups
create index if not exists findings_affected_resource_idx
  on public.findings (site_id, affected_resource);

-- Create a composite unique constraint for findings by check_key and affected_resource
-- This allows multiple findings for the same check_key if they affect different resources
create unique index if not exists findings_composite_key_idx
  on public.findings (site_id, check_key, coalesce(affected_resource, ''))
  where status in ('open', 'acknowledged');

-- Function to update status history on status change
create or replace function public.update_finding_status_history()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.status is distinct from new.status then
    new.status_history = coalesce(old.status_history, '[]'::jsonb) ||
      jsonb_build_object(
        'status', new.status,
        'at', now()
      );
  end if;
  return new;
end;
$$;

-- Trigger to automatically update status history
drop trigger if exists on_finding_status_update on public.findings;
create trigger on_finding_status_update
  before update of status on public.findings
  for each row execute procedure public.update_finding_status_history();


-- >>> supabase/migrations/20261113010000_scan_outcomes.sql
-- Scan outcome tracking.
--
-- The scanner reports one outcome per check (`passed`, `finding`, `error`,
-- `not_checked`). Persisting those outcomes lets the Scans page distinguish
-- "checked and clean" from "could not check", and stops a partial scan from
-- looking like a fully clean one.
--
-- Idempotent: safe to run more than once.

alter table public.scans
  add column if not exists check_results jsonb,
  add column if not exists checks_errored integer,
  add column if not exists checks_skipped integer;

-- Allow `partial` scans (some checks errored or were skipped).
alter table public.scans drop constraint if exists scans_status_check;
alter table public.scans
  add constraint scans_status_check
  check (status in ('running', 'completed', 'partial', 'failed'));

-- >>> supabase/migrations/20261113020000_scan_claims.sql
-- Cross-process scan claims.
-- An in-memory lock cannot coordinate the API process with the worker or
-- multiple deployed instances. A short database lease makes the claim atomic.

alter table public.sites
  add column if not exists scan_claim_token uuid,
  add column if not exists scan_claim_expires_at timestamptz;

create or replace function public.claim_site_scan(
  p_site_id uuid,
  p_claim_token uuid,
  p_lease_seconds integer default 900
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  claimed boolean := false;
begin
  if p_lease_seconds < 60 or p_lease_seconds > 1800 then
    raise exception 'Invalid scan lease duration';
  end if;

  update public.sites
     set scan_claim_token = p_claim_token,
         scan_claim_expires_at = now() + make_interval(secs => p_lease_seconds)
    where id = p_site_id
      and status = 'verified'
      and (scan_claim_expires_at is null or scan_claim_expires_at < now());

  claimed := found;
  return claimed;
end;
$$;

create or replace function public.release_site_scan(
  p_site_id uuid,
  p_claim_token uuid
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  released boolean := false;
begin
  update public.sites
     set scan_claim_token = null,
         scan_claim_expires_at = null
    where id = p_site_id
      and scan_claim_token = p_claim_token;

  released := found;
  return released;
end;
$$;

revoke all on function public.claim_site_scan(uuid, uuid, integer) from public, anon, authenticated;
revoke all on function public.release_site_scan(uuid, uuid) from public, anon, authenticated;
grant execute on function public.claim_site_scan(uuid, uuid, integer) to service_role;
grant execute on function public.release_site_scan(uuid, uuid) to service_role;

-- >>> supabase/migrations/20261113030000_atomic_scan_persistence.sql
-- Atomic scan persistence and idempotent retries.

alter table public.scans
  add column if not exists idempotency_key text;

create unique index if not exists scans_idempotency_key_idx
  on public.scans (idempotency_key)
  where idempotency_key is not null;

create or replace function public.record_scan_result(
  p_site_id uuid,
  p_status text,
  p_http_status integer,
  p_response_ms integer,
  p_checks_total integer,
  p_checks_passed integer,
  p_checks_errored integer,
  p_checks_skipped integer,
  p_check_results jsonb,
  p_error text,
  p_finished_at timestamptz,
  p_interval_minutes integer,
  p_page_sample text,
  p_page_sample_at timestamptz,
  p_should_update_sample boolean,
  p_idempotency_key text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scan_id uuid;
begin
  if p_idempotency_key is not null then
    select id into v_scan_id
    from public.scans
    where idempotency_key = p_idempotency_key
    limit 1;

    if v_scan_id is not null then
      return v_scan_id;
    end if;
  end if;

  insert into public.scans (
    site_id, status, http_status, response_ms,
    checks_total, checks_passed, checks_errored, checks_skipped,
    check_results, error, finished_at, idempotency_key
  ) values (
    p_site_id, p_status, p_http_status, p_response_ms,
    p_checks_total, p_checks_passed, p_checks_errored, p_checks_skipped,
    p_check_results, p_error, p_finished_at, p_idempotency_key
  )
  returning id into v_scan_id;

  update public.sites
     set last_scan_at = p_finished_at,
         next_scan_at = p_finished_at + make_interval(mins => p_interval_minutes),
         page_sample = case when p_should_update_sample then p_page_sample else page_sample end,
         page_sample_at = case when p_should_update_sample then p_page_sample_at else page_sample_at end
   where id = p_site_id;

  return v_scan_id;
end;
$$;

revoke all on function public.record_scan_result(
  uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, integer, text, timestamptz, boolean, text
) from public, anon, authenticated;
grant execute on function public.record_scan_result(
  uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, integer, text, timestamptz, boolean, text
) to service_role;

-- >>> supabase/migrations/20261113040000_github_connections.sql
-- Read-only GitHub repository connections.

create table if not exists public.github_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  github_username text not null,
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

create index if not exists github_connections_user_idx on public.github_connections (user_id);

-- >>> supabase/migrations/20261113050000_supabase_connections.sql
-- Read-only Supabase project connections.

create table if not exists public.supabase_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_ref text not null,
  project_name text,
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

create index if not exists supabase_connections_user_idx on public.supabase_connections (user_id);

-- ---------------------------------------------------------------------------
-- RLS introspection RPC (run this in each connected Supabase project).
--
-- The scanner calls `bulwark_check_rls` to list public tables and report
-- which ones have Row Level Security enabled. Without this function, RLS
-- introspection is skipped and a setup hint is reported instead.
-- ---------------------------------------------------------------------------

create or replace function public.bulwark_check_rls()
returns table (
  table_schema text,
  table_name text,
  row_security_enabled boolean,
  row_count bigint
)
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  select
    c.relnamespace::regnamespace::text as table_schema,
    c.relname as table_name,
    c.relrowsecurity as row_security_enabled,
    c.reltuples::bigint as row_count
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'r'
    and n.nspname not in ('pg_catalog', 'information_schema', 'auth', 'realtime', 'storage', 'pg_toast')
    and n.nspname not like 'pg_%'
    and n.nspname not like 'information_%';
end;
$$;

revoke all on function public.bulwark_check_rls() from public, anon, authenticated;
grant execute on function public.bulwark_check_rls() to anon, authenticated;

-- >>> supabase/migrations/20261113060000_nullable_site_id.sql
-- Allow connection-based scans (GitHub, Supabase) that aren't tied to a website.
-- site_id becomes nullable so scans can be recorded without a linked site.

alter table public.scans
  alter column site_id drop not null;

alter table public.scans
  drop constraint if exists scans_site_id_fkey;

alter table public.scans
  add constraint scans_site_id_fkey
    foreign key (site_id) references public.sites (id) on delete set null;

alter table public.findings
  alter column site_id drop not null;

alter table public.findings
  drop constraint if exists findings_site_id_fkey;

alter table public.findings
  add constraint findings_site_id_fkey
    foreign key (site_id) references public.sites (id) on delete set null;

-- >>> supabase/migrations/20261113070000_atomic_persist_scan.sql
-- Atomic scan persistence: scan record + finding changes + site schedule
-- in a single database transaction.

create or replace function public.persist_scan_result(
  p_scan_id uuid,
  p_site_id uuid,
  p_status text,
  p_http_status integer,
  p_response_ms integer,
  p_checks_total integer,
  p_checks_passed integer,
  p_checks_errored integer,
  p_checks_skipped integer,
  p_check_results jsonb,
  p_error text,
  p_started_at timestamptz,
  p_finished_at timestamptz,
  p_interval_minutes integer,
  p_page_sample text,
  p_page_sample_at timestamptz,
  p_should_update_sample boolean,
  p_findings jsonb,
  p_resolve_stale boolean
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_finding record;
  v_identity text;
  v_existing uuid;
begin
  -- Idempotent: if this scan was already recorded, return the existing id.
  if exists (select 1 from public.scans where id = p_scan_id) then
    return p_scan_id;
  end if;

  -- Insert the scan record.
  insert into public.scans (
    id, site_id, status, http_status, response_ms,
    checks_total, checks_passed, checks_errored, checks_skipped,
    check_results, error, started_at, finished_at
  ) values (
    p_scan_id, p_site_id, p_status, p_http_status, p_response_ms,
    p_checks_total, p_checks_passed, p_checks_errored, p_checks_skipped,
    p_check_results, p_error, p_started_at, p_finished_at
  );

  -- Update the site schedule in the same transaction.
  update public.sites
     set last_scan_at = p_finished_at,
         next_scan_at = p_finished_at + make_interval(mins => p_interval_minutes),
         page_sample = case when p_should_update_sample then p_page_sample else page_sample end,
         page_sample_at = case when p_should_update_sample then p_page_sample_at else page_sample_at end
   where id = p_site_id;

  -- Process findings: insert new, update existing, reopen resolved,
  -- resolve stale only when the scan fully completed.
  for v_finding in
    select * from jsonb_array_elements(p_findings) as elem(finding)
  loop
    -- Look for an existing finding with the same identity.
    select id into v_existing
    from public.findings
    where site_id = p_site_id
      and check_key = (v_finding.finding ->> 'check_key')
      and coalesce(affected_resource, '') = coalesce(v_finding.finding ->> 'affected_resource', '')
    order by
      case status
        when 'open' then 1
        when 'acknowledged' then 2
        when 'ignored' then 3
        when 'resolved' then 4
      end,
      last_seen_at desc
    limit 1;

    if v_existing is null then
      -- Insert new finding.
      insert into public.findings (
        id, scan_id, site_id, check_key, affected_resource, title,
        severity, status, detail, evidence, url, first_seen_at, last_seen_at
      ) values (
        gen_random_uuid(), p_scan_id, p_site_id,
        v_finding.finding ->> 'check_key',
        nullif(v_finding.finding ->> 'affected_resource', ''),
        v_finding.finding ->> 'title',
        v_finding.finding ->> 'severity',
        'open',
        v_finding.finding ->> 'detail',
        v_finding.finding ->> 'evidence',
        v_finding.finding ->> 'url',
        p_finished_at, p_finished_at
      );
    elsif (select status from public.findings where id = v_existing) = 'ignored' then
      -- Respect explicit ignore.
      continue;
    elsif (select status from public.findings where id = v_existing) = 'resolved' then
      -- Reopen resolved findings.
      update public.findings
         set scan_id = p_scan_id,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             status = 'open',
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             last_seen_at = p_finished_at
       where id = v_existing;
    else
      -- Update existing open/acknowledged finding with latest evidence.
      update public.findings
         set scan_id = p_scan_id,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             last_seen_at = p_finished_at
       where id = v_existing;
    end if;
  end loop;

  -- Resolve stale open findings only when the scan completed successfully.
  if p_resolve_stale then
    update public.findings f
       set status = 'resolved'
     where f.site_id = p_site_id
       and f.status = 'open'
       and not exists (
         select 1 from jsonb_array_elements(p_findings) as elem(f2)
         where (f2.finding ->> 'check_key') = f.check_key
           and coalesce(f2.finding ->> 'affected_resource', '') = coalesce(f.affected_resource, '')
       );
  end if;

  return p_scan_id;
end;
$$;

revoke all on function public.persist_scan_result(
  uuid, uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, timestamptz, integer, text, timestamptz, boolean,
  jsonb, boolean
) from public, anon, authenticated;
grant execute on function public.persist_scan_result(
  uuid, uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, timestamptz, integer, text, timestamptz, boolean,
  jsonb, boolean
) to service_role;
