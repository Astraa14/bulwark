-- The RLS introspection helper belongs in each customer's Supabase project,
-- not in Bulwark's own database. Remove the copy created by the earlier
-- connections migration so Bulwark's public schema metadata is not exposed to
-- anon callers.
--
-- The replacement helper lives in supabase/customer/bulwark_check_rls.sql.
drop function if exists public.bulwark_check_rls();
