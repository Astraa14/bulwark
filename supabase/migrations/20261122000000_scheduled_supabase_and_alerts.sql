-- Scheduled Supabase scans + Discord and Email alert channels.
-- Fully idempotent: safe to re-run via supabase/apply_all.sql.

-- ---------------------------------------------------------------------------
-- 1. Alert channels on user_settings
-- ---------------------------------------------------------------------------
-- Discord webhook URLs are bearer secrets (same threat model as Slack):
-- store AES-GCM ciphertext only, never plaintext.
alter table public.user_settings
  add column if not exists discord_webhook_encrypted text,
  add column if not exists discord_alerts_enabled boolean not null default false,
  add column if not exists email_alerts_enabled boolean not null default false,
  add column if not exists alert_email text;

-- ---------------------------------------------------------------------------
-- 2. Scheduled scans on supabase_connections
-- ---------------------------------------------------------------------------
alter table public.supabase_connections
  add column if not exists scan_interval_minutes integer not null default 360,
  add column if not exists auto_scan_enabled boolean not null default true,
  add column if not exists next_scan_at timestamptz default now() + interval '6 hours';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'supabase_connections_interval_check'
      and conrelid = 'public.supabase_connections'::regclass
  ) then
    alter table public.supabase_connections
      add constraint supabase_connections_interval_check
      check (scan_interval_minutes >= 60 and scan_interval_minutes <= 10080);
  end if;
end;
$$;

update public.supabase_connections
   set next_scan_at = coalesce(last_checked_at, now()) + make_interval(mins => scan_interval_minutes)
 where next_scan_at is null;

create index if not exists supabase_connections_due_idx
  on public.supabase_connections (next_scan_at)
  where auto_scan_enabled = true;

-- ---------------------------------------------------------------------------
-- 3. Atomic RPC to enqueue due Supabase connection scans without races
-- ---------------------------------------------------------------------------
create or replace function public.enqueue_due_supabase_scans(p_limit integer default 10)
returns setof public.platform_scan_jobs
language sql
security definer
set search_path = public
as $$
  with due as (
    select c.id
    from public.supabase_connections c
    where c.auto_scan_enabled = true
      and c.next_scan_at is not null
      and c.next_scan_at <= now()
      and not exists (
        select 1
        from public.platform_scan_jobs j
        where j.connection_id = c.id
          and j.platform = 'supabase'
          and j.status in ('queued', 'running')
      )
    order by c.next_scan_at asc
    limit greatest(1, least(coalesce(p_limit, 10), 25))
    for update skip locked
  ),
  bumped as (
    update public.supabase_connections c
       set next_scan_at = now() + make_interval(
         mins => greatest(60, least(coalesce(c.scan_interval_minutes, 360), 10080))
       )
      from due
     where c.id = due.id
    returning c.id, c.user_id, c.project_ref
  )
  insert into public.platform_scan_jobs (
    scan_id,
    user_id,
    platform,
    connection_id,
    resource,
    status
  )
  select
    gen_random_uuid(),
    b.user_id,
    'supabase',
    b.id,
    b.project_ref,
    'queued'
  from bumped b
  returning *;
$$;

revoke all on function public.enqueue_due_supabase_scans(integer)
  from public, anon, authenticated;
grant execute on function public.enqueue_due_supabase_scans(integer)
  to service_role;
