-- Phases 1-3: Alert delivery outbox, finding snooze & triage notes,
-- scheduled GitHub repository scans, weekly posture digest, and site stack tags.
-- Fully idempotent: safe to re-run via supabase/apply_all.sql.

-- ---------------------------------------------------------------------------
-- 1. Alert delivery outbox (reliable retries + delivery history)
-- ---------------------------------------------------------------------------
create table if not exists public.alert_deliveries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  channel text not null check (channel in ('slack', 'discord', 'email')),
  kind text not null default 'finding' check (kind in ('finding', 'digest')),
  target_label text not null,
  finding_count integer not null default 1,
  payload jsonb not null,
  status text not null default 'queued'
    check (status in ('queued', 'sending', 'sent', 'failed')),
  attempts integer not null default 0,
  last_error text,
  run_after timestamptz not null default now(),
  created_at timestamptz not null default now(),
  sent_at timestamptz
);

create index if not exists alert_deliveries_claim_idx
  on public.alert_deliveries (status, run_after, created_at);

create index if not exists alert_deliveries_user_idx
  on public.alert_deliveries (user_id, created_at desc);

alter table public.alert_deliveries enable row level security;

drop policy if exists "alert_deliveries_select_own" on public.alert_deliveries;
create policy "alert_deliveries_select_own" on public.alert_deliveries
  for select using (auth.uid() = user_id);

-- No browser insert/update/delete policies: deliveries are managed server-side.

create or replace function public.claim_alert_deliveries(p_limit integer default 10)
returns setof public.alert_deliveries
language sql
security definer
set search_path = public
as $$
  update public.alert_deliveries d
     set status = 'sending',
         attempts = d.attempts + 1
   where d.id in (
     select id
     from public.alert_deliveries
     where attempts < 5
       and (
         (status = 'queued' and run_after <= now())
         or (
           status = 'sending'
           and run_after < now() - interval '10 minutes'
         )
       )
     order by created_at asc
     limit greatest(1, least(coalesce(p_limit, 10), 25))
     for update skip locked
   )
  returning d.*;
$$;

revoke all on function public.claim_alert_deliveries(integer)
  from public, anon, authenticated;
grant execute on function public.claim_alert_deliveries(integer)
  to service_role;

-- ---------------------------------------------------------------------------
-- 2. Finding snooze (temporary ignore) & triage notes
-- ---------------------------------------------------------------------------
alter table public.findings
  add column if not exists ignored_until timestamptz,
  add column if not exists triage_note text;

revoke update on public.findings from anon, authenticated;
grant update (status, ignored_until, triage_note)
  on public.findings to authenticated;

-- Update website scan persistence so expired snoozes reopen automatically.
create or replace function public.persist_scan_result(
  p_scan_id uuid,
  p_idempotency_key text,
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
  v_user_id uuid;
  v_scan_id uuid := p_scan_id;
  v_existing_id uuid;
  v_existing_status text;
  v_finding record;
  v_existing_finding uuid;
  v_existing_finding_status text;
  v_existing_ignored_until timestamptz;
begin
  select user_id into v_user_id
  from public.sites
  where id = p_site_id;

  if v_user_id is null then
    raise exception 'site % not found', p_site_id;
  end if;

  if p_idempotency_key is not null then
    select id, status into v_existing_id, v_existing_status
    from public.scans
    where site_id = p_site_id
      and idempotency_key = p_idempotency_key
    limit 1;

    if v_existing_id is not null then
      if v_existing_status in ('completed', 'partial') then
        return v_existing_id;
      end if;
      v_scan_id := v_existing_id;
    end if;
  end if;

  if v_existing_id is null then
    select id, status into v_existing_id, v_existing_status
    from public.scans
    where id = p_scan_id;

    if v_existing_id is not null then
      if v_existing_status in ('completed', 'partial') then
        return v_existing_id;
      end if;
      v_scan_id := v_existing_id;
    end if;
  end if;

  if v_existing_id is not null then
    update public.scans
       set site_id = p_site_id,
           user_id = v_user_id,
           status = p_status,
           http_status = p_http_status,
           response_ms = p_response_ms,
           checks_total = p_checks_total,
           checks_passed = p_checks_passed,
           checks_errored = p_checks_errored,
           checks_skipped = p_checks_skipped,
           check_results = p_check_results,
           error = p_error,
           started_at = p_started_at,
           finished_at = p_finished_at,
           idempotency_key = coalesce(idempotency_key, p_idempotency_key)
     where id = v_scan_id;
  else
    insert into public.scans (
      id, site_id, user_id, status, http_status, response_ms,
      checks_total, checks_passed, checks_errored, checks_skipped,
      check_results, error, started_at, finished_at, idempotency_key
    ) values (
      p_scan_id, p_site_id, v_user_id, p_status, p_http_status, p_response_ms,
      p_checks_total, p_checks_passed, p_checks_errored, p_checks_skipped,
      p_check_results, p_error, p_started_at, p_finished_at, p_idempotency_key
    );
  end if;

  update public.sites
     set last_scan_at = p_finished_at,
         next_scan_at = p_finished_at + make_interval(mins => p_interval_minutes),
         page_sample = case when p_should_update_sample then p_page_sample else page_sample end,
         page_sample_at = case when p_should_update_sample then p_page_sample_at else page_sample_at end
   where id = p_site_id;

  for v_finding in
    select * from jsonb_array_elements(coalesce(p_findings, '[]'::jsonb)) as elem(finding)
  loop
    select id, status, ignored_until
      into v_existing_finding, v_existing_finding_status, v_existing_ignored_until
    from public.findings
    where site_id = p_site_id
      and user_id = v_user_id
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

    if v_existing_finding is null then
      insert into public.findings (
        scan_id, site_id, user_id, check_key, affected_resource, title,
        severity, status, detail, evidence, url, confidence,
        what_it_does_not_prove, remediation, first_seen_at, last_seen_at
      ) values (
        v_scan_id, p_site_id, v_user_id,
        v_finding.finding ->> 'check_key',
        nullif(v_finding.finding ->> 'affected_resource', ''),
        v_finding.finding ->> 'title',
        v_finding.finding ->> 'severity',
        'open',
        v_finding.finding ->> 'detail',
        v_finding.finding ->> 'evidence',
        v_finding.finding ->> 'url',
        v_finding.finding ->> 'confidence',
        v_finding.finding ->> 'what_it_does_not_prove',
        v_finding.finding ->> 'remediation',
        p_finished_at, p_finished_at
      );
    elsif v_existing_finding_status = 'ignored'
      and (v_existing_ignored_until is null or v_existing_ignored_until > p_finished_at) then
      continue;
    elsif v_existing_finding_status in ('resolved', 'ignored') then
      update public.findings
         set scan_id = v_scan_id,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             status = 'open',
             ignored_until = null,
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             confidence = v_finding.finding ->> 'confidence',
             what_it_does_not_prove = v_finding.finding ->> 'what_it_does_not_prove',
             remediation = v_finding.finding ->> 'remediation',
             last_seen_at = p_finished_at
       where id = v_existing_finding;
    else
      update public.findings
         set scan_id = v_scan_id,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             confidence = v_finding.finding ->> 'confidence',
             what_it_does_not_prove = v_finding.finding ->> 'what_it_does_not_prove',
             remediation = v_finding.finding ->> 'remediation',
             last_seen_at = p_finished_at
       where id = v_existing_finding;
    end if;
  end loop;

  if p_resolve_stale then
    update public.findings f
       set status = 'resolved'
     where f.site_id = p_site_id
       and f.user_id = v_user_id
       and f.status = 'open'
       and not exists (
         select 1 from jsonb_array_elements(coalesce(p_findings, '[]'::jsonb)) as f2(finding)
         where (f2.finding ->> 'check_key') = f.check_key
           and coalesce(f2.finding ->> 'affected_resource', '') = coalesce(f.affected_resource, '')
       );
  end if;

  return v_scan_id;
end;
$$;

revoke all on function public.persist_scan_result(
  uuid, text, uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, timestamptz, integer, text, timestamptz, boolean,
  jsonb, boolean
) from public, anon, authenticated;
grant execute on function public.persist_scan_result(
  uuid, text, uuid, text, integer, integer, integer, integer, integer, integer,
  jsonb, text, timestamptz, timestamptz, integer, text, timestamptz, boolean,
  jsonb, boolean
) to service_role;

-- Update platform scan persistence so expired snoozes reopen and re-alert.
create or replace function public.persist_platform_scan_result(
  p_scan_id uuid,
  p_user_id uuid,
  p_platform text,
  p_connection_id uuid,
  p_resource text,
  p_ref text,
  p_commit_sha text,
  p_status text,
  p_checks_total integer,
  p_checks_passed integer,
  p_checks_errored integer,
  p_checks_skipped integer,
  p_check_results jsonb,
  p_coverage jsonb,
  p_error text,
  p_started_at timestamptz,
  p_finished_at timestamptz,
  p_findings jsonb,
  p_resolve_stale boolean,
  p_delivery_id text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_scan_id uuid := p_scan_id;
  v_existing_id uuid;
  v_existing_status text;
  v_finding record;
  v_existing_finding uuid;
  v_existing_finding_status text;
  v_existing_ignored_until timestamptz;
  v_finding_id uuid;
  v_new jsonb := '[]'::jsonb;
  v_reopened jsonb := '[]'::jsonb;
  v_owner text;
  v_repo text;
begin
  if p_platform not in ('github', 'supabase') then
    raise exception 'unsupported platform %', p_platform;
  end if;

  if p_platform = 'github' then
    if position('/' in p_resource) = 0 then
      raise exception 'github resource must be owner/repo';
    end if;
    if not exists (
      select 1 from public.github_connections
      where id = p_connection_id and user_id = p_user_id
    ) then
      raise exception 'github connection not found for this user';
    end if;
  else
    if not exists (
      select 1 from public.supabase_connections
      where id = p_connection_id and user_id = p_user_id
    ) then
      raise exception 'supabase connection not found for this user';
    end if;
  end if;

  select id, status into v_existing_id, v_existing_status
  from public.scans
  where id = p_scan_id
     or (
       p_delivery_id is not null
       and connection_id = p_connection_id
       and delivery_id = p_delivery_id
     )
  order by (id = p_scan_id) desc
  limit 1;

  if v_existing_id is not null then
    if v_existing_status in ('completed', 'partial') then
      return jsonb_build_object(
        'scanId', v_existing_id,
        'duplicate', true,
        'newFindings', '[]'::jsonb,
        'reopenedFindings', '[]'::jsonb
      );
    end if;
    v_scan_id := v_existing_id;

    update public.scans
       set user_id = p_user_id,
           platform = p_platform,
           connection_id = p_connection_id,
           resource = p_resource,
           ref = p_ref,
           commit_sha = p_commit_sha,
           status = p_status,
           checks_total = p_checks_total,
           checks_passed = p_checks_passed,
           checks_errored = p_checks_errored,
           checks_skipped = p_checks_skipped,
           check_results = p_check_results,
           coverage = p_coverage,
           error = p_error,
           started_at = p_started_at,
           finished_at = p_finished_at,
           delivery_id = coalesce(delivery_id, p_delivery_id)
     where id = v_scan_id;
  else
    insert into public.scans (
      id, site_id, user_id, platform, connection_id, resource, ref, commit_sha,
      status, checks_total, checks_passed, checks_errored, checks_skipped,
      check_results, coverage, error, started_at, finished_at, delivery_id
    ) values (
      p_scan_id, null, p_user_id, p_platform, p_connection_id, p_resource,
      p_ref, p_commit_sha, p_status, p_checks_total, p_checks_passed,
      p_checks_errored, p_checks_skipped, p_check_results, p_coverage,
      p_error, p_started_at, p_finished_at, p_delivery_id
    );
  end if;

  for v_finding in
    select * from jsonb_array_elements(coalesce(p_findings, '[]'::jsonb)) as elem(finding)
  loop
    select id, status, ignored_until
      into v_existing_finding, v_existing_finding_status, v_existing_ignored_until
    from public.findings
    where user_id = p_user_id
      and platform = p_platform
      and connection_id = p_connection_id
      and resource = p_resource
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

    if v_existing_finding is null then
      insert into public.findings (
        scan_id, site_id, user_id, platform, connection_id, resource,
        commit_sha, ref, check_key, affected_resource, title, severity,
        status, detail, evidence, url, confidence, what_it_does_not_prove,
        remediation, first_seen_at, last_seen_at
      ) values (
        v_scan_id, null, p_user_id, p_platform, p_connection_id, p_resource,
        p_commit_sha, p_ref,
        v_finding.finding ->> 'check_key',
        nullif(v_finding.finding ->> 'affected_resource', ''),
        v_finding.finding ->> 'title',
        v_finding.finding ->> 'severity',
        'open',
        v_finding.finding ->> 'detail',
        v_finding.finding ->> 'evidence',
        v_finding.finding ->> 'url',
        v_finding.finding ->> 'confidence',
        v_finding.finding ->> 'what_it_does_not_prove',
        v_finding.finding ->> 'remediation',
        p_finished_at, p_finished_at
      )
      returning id into v_finding_id;

      v_new := v_new || jsonb_build_array(jsonb_build_object(
        'id', v_finding_id,
        'check_key', v_finding.finding ->> 'check_key',
        'title', v_finding.finding ->> 'title',
        'severity', v_finding.finding ->> 'severity',
        'detail', v_finding.finding ->> 'detail',
        'url', v_finding.finding ->> 'url'
      ));
    elsif v_existing_finding_status = 'ignored'
      and (v_existing_ignored_until is null or v_existing_ignored_until > p_finished_at) then
      continue;
    elsif v_existing_finding_status in ('resolved', 'ignored') then
      update public.findings
         set scan_id = v_scan_id,
             commit_sha = p_commit_sha,
             ref = p_ref,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             status = 'open',
             ignored_until = null,
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             confidence = v_finding.finding ->> 'confidence',
             what_it_does_not_prove = v_finding.finding ->> 'what_it_does_not_prove',
             remediation = v_finding.finding ->> 'remediation',
             last_seen_at = p_finished_at
       where id = v_existing_finding;

      v_reopened := v_reopened || jsonb_build_array(jsonb_build_object(
        'id', v_existing_finding,
        'check_key', v_finding.finding ->> 'check_key',
        'title', v_finding.finding ->> 'title',
        'severity', v_finding.finding ->> 'severity',
        'detail', v_finding.finding ->> 'detail',
        'url', v_finding.finding ->> 'url'
      ));
    else
      update public.findings
         set scan_id = v_scan_id,
             commit_sha = p_commit_sha,
             ref = p_ref,
             title = v_finding.finding ->> 'title',
             severity = v_finding.finding ->> 'severity',
             detail = v_finding.finding ->> 'detail',
             evidence = v_finding.finding ->> 'evidence',
             url = v_finding.finding ->> 'url',
             affected_resource = nullif(v_finding.finding ->> 'affected_resource', ''),
             confidence = v_finding.finding ->> 'confidence',
             what_it_does_not_prove = v_finding.finding ->> 'what_it_does_not_prove',
             remediation = v_finding.finding ->> 'remediation',
             last_seen_at = p_finished_at
       where id = v_existing_finding;
    end if;
  end loop;

  if p_resolve_stale then
    update public.findings f
       set status = 'resolved'
     where f.user_id = p_user_id
       and f.platform = p_platform
       and f.connection_id = p_connection_id
       and f.resource = p_resource
       and f.status = 'open'
       and not exists (
         select 1 from jsonb_array_elements(coalesce(p_findings, '[]'::jsonb)) as f2(finding)
         where (f2.finding ->> 'check_key') = f.check_key
           and coalesce(f2.finding ->> 'affected_resource', '') = coalesce(f.affected_resource, '')
       );
  end if;

  if p_platform = 'github' then
    update public.github_connections
       set last_checked_at = p_finished_at,
           last_scan_status = p_status,
           last_scan_error = p_error,
           last_scan_coverage = p_coverage
     where id = p_connection_id
       and user_id = p_user_id;

    if p_commit_sha is not null then
      v_owner := split_part(p_resource, '/', 1);
      v_repo := split_part(p_resource, '/', 2);

      insert into public.github_repositories (
        user_id, connection_id, owner, name,
        last_scanned_commit, last_scanned_ref, last_scanned_at
      ) values (
        p_user_id, p_connection_id, v_owner, v_repo,
        p_commit_sha, p_ref, p_finished_at
      )
      on conflict (connection_id, owner, name) do update
      set last_scanned_commit = excluded.last_scanned_commit,
          last_scanned_ref = excluded.last_scanned_ref,
          last_scanned_at = excluded.last_scanned_at;
    end if;
  else
    update public.supabase_connections
       set last_checked_at = p_finished_at,
           last_scan_status = p_status,
           last_scan_error = p_error,
           last_scan_coverage = p_coverage
     where id = p_connection_id
       and user_id = p_user_id;
  end if;

  return jsonb_build_object(
    'scanId', v_scan_id,
    'duplicate', false,
    'newFindings', v_new,
    'reopenedFindings', v_reopened
  );
end;
$$;

revoke all on function public.persist_platform_scan_result(
  uuid, uuid, text, uuid, text, text, text, text, integer, integer, integer,
  integer, jsonb, jsonb, text, timestamptz, timestamptz, jsonb, boolean, text
) from public, anon, authenticated;
grant execute on function public.persist_platform_scan_result(
  uuid, uuid, text, uuid, text, text, text, text, integer, integer, integer,
  integer, jsonb, jsonb, text, timestamptz, timestamptz, jsonb, boolean, text
) to service_role;

-- ---------------------------------------------------------------------------
-- 3. Scheduled GitHub repository scans (opt-in per repository)
-- ---------------------------------------------------------------------------
alter table public.github_repositories
  add column if not exists auto_scan_enabled boolean not null default false,
  add column if not exists scan_interval_minutes integer not null default 1440,
  add column if not exists next_scan_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'github_repositories_interval_check'
      and conrelid = 'public.github_repositories'::regclass
  ) then
    alter table public.github_repositories
      add constraint github_repositories_interval_check
      check (scan_interval_minutes >= 360 and scan_interval_minutes <= 10080);
  end if;
end;
$$;

create index if not exists github_repositories_due_idx
  on public.github_repositories (next_scan_at)
  where auto_scan_enabled = true;

create or replace function public.enqueue_due_github_scans(p_limit integer default 10)
returns setof public.platform_scan_jobs
language sql
security definer
set search_path = public
as $$
  with due as (
    select r.id
    from public.github_repositories r
    where r.auto_scan_enabled = true
      and r.next_scan_at is not null
      and r.next_scan_at <= now()
      and not exists (
        select 1
        from public.platform_scan_jobs j
        where j.connection_id = r.connection_id
          and j.platform = 'github'
          and j.resource = (r.owner || '/' || r.name)
          and j.status in ('queued', 'running')
      )
    order by r.next_scan_at asc
    limit greatest(1, least(coalesce(p_limit, 10), 25))
    for update skip locked
  ),
  bumped as (
    update public.github_repositories r
       set next_scan_at = now() + make_interval(
         mins => greatest(360, least(coalesce(r.scan_interval_minutes, 1440), 10080))
       )
      from due
     where r.id = due.id
    returning r.user_id, r.connection_id, r.owner, r.name
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
    'github',
    b.connection_id,
    b.owner || '/' || b.name,
    'queued'
  from bumped b
  returning *;
$$;

revoke all on function public.enqueue_due_github_scans(integer)
  from public, anon, authenticated;
grant execute on function public.enqueue_due_github_scans(integer)
  to service_role;

-- ---------------------------------------------------------------------------
-- 4. Weekly posture digest preferences on user_settings
-- ---------------------------------------------------------------------------
alter table public.user_settings
  add column if not exists weekly_digest_enabled boolean not null default false,
  add column if not exists last_digest_sent_at timestamptz;

-- ---------------------------------------------------------------------------
-- 5. Stack profile tag on sites (feeds AI explanations & editor fix prompts)
-- ---------------------------------------------------------------------------
alter table public.sites
  add column if not exists stack text;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'sites_stack_check'
      and conrelid = 'public.sites'::regclass
  ) then
    alter table public.sites
      add constraint sites_stack_check
      check (
        stack is null or stack in (
          'nextjs-vercel',
          'vite-render',
          'cloudflare',
          'nginx',
          'express',
          'supabase',
          'other'
        )
      );
  end if;
end;
$$;

grant update (stack) on public.sites to authenticated;
