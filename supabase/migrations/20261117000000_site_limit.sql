-- ---------------------------------------------------------------------------
-- Free-plan site cap, enforced in the database.
--
-- The UI already refuses a sixth site, but a client can insert straight into
-- public.sites through PostgREST with its own JWT. This trigger makes the cap
-- authoritative regardless of how the row arrives.
--
-- Concurrent inserts are serialised per user with a transaction-scoped
-- advisory lock, so two requests cannot both read four rows and each insert a
-- fifth and sixth.
-- ---------------------------------------------------------------------------

create or replace function public.enforce_site_limit()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  site_limit constant integer := 5;
  current_count integer;
begin
  perform pg_advisory_xact_lock(hashtext('bulwark_sites:' || new.user_id::text));

  select count(*) into current_count
  from public.sites
  where user_id = new.user_id;

  if current_count >= site_limit then
    raise exception 'The free plan covers % sites. Delete one before adding another.', site_limit
      using errcode = 'check_violation';
  end if;

  return new;
end;
$$;

revoke all on function public.enforce_site_limit() from public;

drop trigger if exists enforce_site_limit on public.sites;
create trigger enforce_site_limit
before insert on public.sites
for each row execute function public.enforce_site_limit();
