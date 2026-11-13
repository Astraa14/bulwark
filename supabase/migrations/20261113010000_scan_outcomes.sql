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
