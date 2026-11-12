-- ===========================================================================
-- Bulwark: run this once in Supabase -> SQL Editor -> New query.
-- It combines (in order) the v1.1 features migration and the ownership
-- verification hardening migration. Both are idempotent and safe to re-run.
-- ===========================================================================
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
