-- Atomic scan persistence: scan record + finding changes + site schedule
-- in a single database transaction.
--
-- Replaces record_scan_result. Uses a stable scan_id (UUID) as the
-- idempotency key so retries of the same job are safe.

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
    v_identity := (v_finding.finding ->> 'check_key') || chr(0) ||
                  coalesce(v_finding.finding ->> 'affected_resource', '');

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
