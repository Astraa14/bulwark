-- ---------------------------------------------------------------------------
-- Security hardening (review S2, S3, S9)
--
-- 1. sites RLS is spelled out as select/insert/delete/update instead of one
--    FOR ALL policy. The trigger and column grants from 20261112 remain the
--    enforcement point: a browser insert is always `pending`, and a browser
--    update can only touch display_name, autonomy and scan_interval_minutes.
-- 2. findings: the browser may only change `status`, and `url` must be an
--    http(s) URL because the UI renders it as a link.
-- 3. user_settings gains a ciphertext column for the Slack webhook. The API
--    encrypts on write and adopts legacy plaintext rows on read.
-- ---------------------------------------------------------------------------

drop policy if exists sites_own on public.sites;

drop policy if exists sites_select_own on public.sites;
create policy sites_select_own on public.sites
  for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists sites_insert_own on public.sites;
create policy sites_insert_own on public.sites
  for insert to authenticated
  with check (auth.uid() = user_id and status = 'pending');

drop policy if exists sites_update_own on public.sites;
create policy sites_update_own on public.sites
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists sites_delete_own on public.sites;
create policy sites_delete_own on public.sites
  for delete to authenticated
  using (auth.uid() = user_id);

-- Findings are read and status-triaged by the browser. Everything else is
-- written by the service role during a scan.
revoke update on public.findings from anon, authenticated;
grant update (status) on public.findings to authenticated;

update public.findings
set url = null
where url is not null and url !~* '^https?://';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'findings_url_scheme_check'
      and conrelid = 'public.findings'::regclass
  ) then
    alter table public.findings
      add constraint findings_url_scheme_check
      check (url is null or url ~* '^https?://');
  end if;
end;
$$;

-- Slack webhook URLs are bearer secrets. New values are AES-GCM ciphertext;
-- slack_webhook_url stays for legacy rows until the API encrypts them.
alter table public.user_settings
  add column if not exists slack_webhook_encrypted text;
