-- Improve finding identity and lifecycle
-- Add columns for better tracking of findings with affected resources and status history

-- Add new columns to findings table
alter table public.findings
  add column if not exists affected_resource text,
  add column if not exists confidence text default 'medium'
    check (confidence in ('high', 'medium', 'low')),
  add column if not exists what_it_does_not_prove text,
  add column if not exists remediation text,
  add column if not exists status_history jsonb default '[]'::jsonb,
  add column if not exists muted_until timestamptz;

-- Create index on affected_resource for better lookups
create index if not exists findings_affected_resource_idx
  on public.findings (site_id, affected_resource);

-- Create a composite unique constraint for findings by check_key and affected_resource
-- This allows multiple findings for the same check_key if they affect different resources
create unique index if not exists findings_composite_key_idx
  on public.findings (site_id, check_key, coalesce(affected_resource, ''))
  where status in ('open', 'acknowledged');

-- Function to update status history on status change
create or replace function public.update_finding_status_history()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.status is distinct from new.status then
    new.status_history = coalesce(old.status_history, '[]'::jsonb) ||
      jsonb_build_object(
        'status', new.status,
        'at', now()
      );
  end if;
  return new;
end;
$$;

-- Trigger to automatically update status history
drop trigger if exists on_finding_status_update on public.findings;
create trigger on_finding_status_update
  before update of status on public.findings
  for each row execute procedure public.update_finding_status_history();
