-- Allow connection-based scans (GitHub, Supabase) that aren't tied to a website.
-- site_id becomes nullable so scans can be recorded without a linked site.

alter table public.scans
  alter column site_id drop not null;

alter table public.scans
  drop constraint if exists scans_site_id_fkey;

alter table public.scans
  add constraint scans_site_id_fkey
    foreign key (site_id) references public.sites (id) on delete set null;

alter table public.findings
  alter column site_id drop not null;

alter table public.findings
  drop constraint if exists findings_site_id_fkey;

alter table public.findings
  add constraint findings_site_id_fkey
    foreign key (site_id) references public.sites (id) on delete set null;
