-- Track last scanned commit SHA per GitHub connection for drift detection.
alter table public.github_connections
  add column if not exists last_scanned_commit text;

-- Webhook delivery secret for validating GitHub webhook signatures.
-- Stored encrypted at rest, same as connection tokens.
alter table public.github_connections
  add column if not exists webhook_secret_encrypted text;
