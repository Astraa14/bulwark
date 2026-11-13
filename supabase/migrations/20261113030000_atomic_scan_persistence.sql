-- Atomic scan persistence and idempotent retries.
--
-- Adds an idempotency key to scans so retrying the same scan result is safe,
-- and a record_scan_result RPC that persists the scan record and site schedule
-- update in a single transaction.

alter table public.scans
  add column if not exists idempotency_key text;

create unique index if not exists scans_idempotency_key_idx
  on public.scans (idempotency_key)
  where idempotency_key is not null;

-- Persist a scan result and update the site schedule atomically.
-- Returns the scan id. Safe to retry with the same idempotency key.
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
  -- Idempotent: if this scan result was already recorded, return the existing id.
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

  -- Update the site schedule in the same transaction.
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
