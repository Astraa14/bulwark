-- Bulwark RLS introspection helper.
--
-- Run this once in the Supabase project you want Bulwark to inspect:
--   Supabase Dashboard -> SQL Editor -> paste this file -> Run.
--
-- What it returns:
--   * table_name, row_security_enabled: factual metadata for public tables.
--   * policy_count, has_permissive_policy: a conservative heuristic only.
--     `has_permissive_policy` is true when a policy's USING or WITH CHECK
--     expression is literally `true`. It does NOT prove the policies are safe.
--
-- It deliberately:
--   * returns metadata for the public schema only;
--   * returns no row counts or table contents;
--   * uses a fixed search_path and SECURITY DEFINER so it can read pg_catalog;
--   * is executable by anon/authenticated because the connecting project key is
--     public by design.
--
-- Bulwark never needs a service-role key to call this function.

drop function if exists public.bulwark_check_rls();

create function public.bulwark_check_rls()
returns table (
  table_name text,
  row_security_enabled boolean,
  policy_count bigint,
  has_permissive_policy boolean
)
language sql
security definer
set search_path = pg_catalog
as $$
  select
    c.relname::text as table_name,
    c.relrowsecurity as row_security_enabled,
    coalesce(p.policy_count, 0)::bigint as policy_count,
    coalesce(p.has_permissive, false) as has_permissive_policy
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  left join lateral (
    select
      count(*)::bigint as policy_count,
      bool_or(
        coalesce(pol.qual, '') = 'true'
        or coalesce(pol.with_check, '') = 'true'
      ) as has_permissive
    from pg_policies pol
    where pol.schemaname = n.nspname
      and pol.tablename = c.relname
  ) p on true
  where c.relkind = 'r'
    and n.nspname = 'public';
$$;

revoke all on function public.bulwark_check_rls() from public;
grant execute on function public.bulwark_check_rls() to anon, authenticated;
