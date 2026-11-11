-- Bulwark v1.1: AI explanations, alert channels, settings, defacement baseline
-- Fully idempotent: safe to paste into the Supabase SQL editor more than once.

-- ---------------------------------------------------------------------------
-- Faster default scan cadence (60 minutes)
-- ---------------------------------------------------------------------------
alter table public.sites alter column scan_interval_minutes set default 60;
update public.sites set scan_interval_minutes = 60 where scan_interval_minutes = 360;

-- Defacement baseline (normalized visible text of the last accepted homepage)
alter table public.sites
  add column if not exists page_sample text,
  add column if not exists page_sample_at timestamptz;

-- Cached AI explanations so each finding is only paid for once
alter table public.findings
  add column if not exists explanation text,
  add column if not exists explanation_model text,
  add column if not exists explained_at timestamptz;

-- ---------------------------------------------------------------------------
-- user_settings: per-user workspace preferences + alert channel
-- ---------------------------------------------------------------------------
create table if not exists public.user_settings (
  user_id uuid primary key references auth.users (id) on delete cascade,
  scan_interval_minutes integer not null default 60,
  autonomy text not null default 'suggest'
    check (autonomy in ('suggest', 'auto_fix')),
  slack_webhook_url text,
  slack_min_severity text not null default 'high'
    check (slack_min_severity in ('critical', 'high', 'medium', 'low', 'info')),
  alerts_enabled boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.user_settings enable row level security;

drop policy if exists "user_settings_own" on public.user_settings;
create policy "user_settings_own" on public.user_settings
  for all using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
