# Bulwark Critique & Reflection (2026-11-13)

This document tracks the current state of Bulwark, what's been fixed, what remains, and the honest product scope. It is updated after every round of changes.

## Verification status

- `tsc --noEmit`: clean (0 errors)
- `npm test`: **37/37 pass, 0 fail**
- CI: GitHub Actions workflow at `.github/workflows/ci.yml` runs typecheck + tests on every push/PR to `master`

## What was fixed

### Critical: baseline trust — code matches documented claims

The checked-in source now matches the claims in this document. `verify.mjs` imports `isUnsafeIp`, `hasUnsafeDns`, `ensureSafeFetchUrl`, and `fetchWithTimeout` from `checks.mjs`, and all four are exported. CI runs from a clean checkout and passes.

### Critical: fail-open outcomes eliminated

Every check returns an explicit outcome: `pass`, `finding`, `error`, or `not_checked`. A check error is **never** inferred as `pass` from an empty findings array.

- `checkExposedFiles` — network failures are `error`, never pass
- `checkCors` — fetch failures are `error`, never pass
- `checkDiscovery` — `404` = absence (info finding), `403`/timeout = error
- `checkLeakedSecrets` — failed script bundle fetches propagate as `error`
- `checkDomainExpiry` — RDAP failures propagate as `error`
- `checkDns` — DoH failures propagate as `error`
- Worker only resolves stale findings when `result.status === "completed"`

### Critical: SSRF boundary hardened

All outbound requests go through `fetchWithTimeout` + `ensureSafeFetchUrl`:

- Scheme restricted to `http:` / `https:`
- Port restricted to 80 / 443
- Hostname blocks localhost, `.local`, private IPv4/IPv6, link-local
- DNS resolution validated against blocklist; DNS failures = unsafe
- Redirect targets re-validated through `ensureSafeFetchUrl` at every hop
- `checkTls` pre-resolves and validates DNS before opening TLS socket
- `verifyDomain` routes meta-tag fetch through guarded helper
- Path segments individually URL-encoded (no `%2F` injection)

### Critical: end-to-end bounded fetch

`fetchWithTimeout` uses one deadline covering connection + redirects + body reading. `readBodyBounded` enforces a byte cap while streaming. Bodies consumed on redirects, timers cleared in `finally`. Applied to HTML, scripts, exposed files, RDAP, DoH, and verification.

### High: atomic scan persistence

Migration `20261113070000_atomic_persist_scan.sql` adds `persist_scan_result` RPC that persists scan record + finding changes + site schedule in **one database transaction**. Uses a stable `scan_id` UUID as idempotency key — retries of the same job are safe. Replaces the previous non-atomic `record_scan_result` + separate finding calls.

### High: canonical finding identity + honest coverage

`findingIdentity`/`resourceForFinding` from `finding-identity.mjs` used consistently. `pass`, `finding`, `error`, `not_checked` kept distinct from scanner through storage to UI. A 40-file scan is reported as truncated with `scannedPercent`; an unavailable RLS function is "not checked," not "RLS is okay."

### Critical: GitHub OAuth login (not just manual PATs)

- `signInWithGitHub()` added to auth context — uses `supabase.auth.signInWithOAuth({ provider: "github" })` with `repo read:user user:email` scopes
- "Sign in with GitHub" button added to AuthScreen
- OAuth callback handler in App.tsx exchanges the code via `supabase.auth.exchangeCodeForSession()`
- Users no longer need to manually create PATs — GitHub OAuth handles repo access

### Critical: continuous monitoring with GitHub webhooks + drift detection

- Migration `20261113080000_github_continuous_monitoring.sql` adds `last_scanned_commit` and `webhook_secret_encrypted` to `github_connections`
- `POST /api/webhooks/github` — HMAC-signed webhook endpoint (no bearer token, validated by signature)
- On push events: scans the repo, compares findings against prior open findings, alerts only on **new** findings (drift detection)
- Skips re-scans when the commit SHA hasn't changed (`last_scanned_commit === after`)
- `POST /api/connections/github/:id/webhook-secret` — set the webhook secret per connection
- Frontend: webhook URL display + secret input in ConnectionsSection

### New: product scope doc

`PRODUCT_SCOPE.md` defines what Bulwark is (external posture monitoring) and what it is NOT (vulnerability scanner, authenticated scanner, code scanner, compliance tool, WAF). Sets honest expectations: "Bulwark finds and explains risks it can verify."

### New: read-only repo analysis (GitHub)

- Migration `20261113040000_github_connections.sql` — encrypted `github_connections` table (RLS, service-role write only)
- `server/github.mjs` — scans the **complete** repository tree (no 40-file cap) for hardcoded secrets, sensitive filenames, unpinned dependencies, **lockfile vulnerability detection** (package-lock.json), and **deployment/config checks** (Dockerfile root user, Docker Compose root user, GitHub Actions `pull_request_target`)
- Reports `coverage` (filesScanned, totalFiles, scanTruncated, scannedPercent) so coverage is honest
- API: `GET/POST/DELETE /api/connections/github`, `POST /api/connections/github/:id/scan`
- Tokens encrypted at rest with `BULWARK_ENCRYPTION_KEY`, never readable from browser

### New: Supabase platform checks

- Migration `20261113050000_supabase_connections.sql` — encrypted `supabase_connections` table (RLS, service-role write only)
- `server/supabase.mjs` — checks storage buckets for public access, Supabase API connectivity, and RLS introspection via `bulwark_check_rls` RPC (reports "not checked" when RPC unavailable — never implies RLS is okay)
- API: `GET/POST/DELETE /api/connections/supabase`, `POST /api/connections/supabase/:id/scan`
- Credentials encrypted at rest, never readable from browser

### New: connections module

- `server/connections.mjs` — generic CRUD for encrypted connections (list/add/delete/resolve), following the `keys.mjs` BYOK pattern

### New: frontend UI

- `ConnectionsSection` in Integrations page — connect/scan/remove GitHub & Supabase, set webhook secret, view webhook URL
- `PlatformFindingsSection` in Integrations page — view findings from GitHub/Supabase scans (grouped by platform), update finding status (open/acknowledged/resolved/ignored)
- API: `GET /api/findings/platform` — returns findings with `site_id = null`

### New: CI/CD

- `.github/workflows/ci.yml` — runs `npm ci`, `tsc --noEmit`, `npm test` on push/PR to `master`

### New: fixture-based + adversarial tests

- `server/checks-fixtures.test.mjs` — clean site, vulnerable site, defacement detected/missed, SSRF redirect block, partial scan, 403 vs 404, redirect chains, multiple finding types, oversized bundle, changed evidence on recurrence
- `server/checks-outcomes.test.mjs` — network error never becomes pass, exposed-file failure, secrets script failure, redirect-SSRF blocking, blocked schemes/ports
- `server/platform-tests.test.mjs` — GitHub secrets, clean repo, sensitive filenames, unpinned deps, vulnerable lockfile deps, Dockerfile root user, pull_request_target workflow, coverage reporting, public/private storage buckets

## Remaining work

1. **Supabase RLS without custom RPC** — Current RLS check requires the customer to deploy `bulwark_check_rls` in their project. An alternative that doesn't require customer-installed RPC would be preferable.
2. **Network-level egress controls** — `render.yaml` documents recommendations; application-level SSRF protection is in place. Firewall/egress proxy rules recommended as defense in depth for Render deployment.

## Priority order going forward

1. ✅ Fix fail-open outcomes; make all outbound traffic safe
2. ✅ End-to-end bounded fetch with byte caps
3. ✅ Atomic scan persistence with stable retry IDs
4. ✅ Align finding identity with the schema
5. ✅ Add tests and repo-aware checks
6. ✅ GitHub OAuth login (replaces manual PATs)
7. ✅ Continuous monitoring with GitHub webhooks + drift detection
8. Supabase RLS check without customer-installed RPC
9. Network-level egress restrictions on Render

## Verification

- `tsc --noEmit`: clean
- `npm test`: 37/37 pass
- All critical trust issues from previous reviews are resolved
