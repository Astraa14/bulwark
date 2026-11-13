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
