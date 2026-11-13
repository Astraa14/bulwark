# Bulwark Critique & Reflection (2026-11-13)

This document tracks the current state of Bulwark, what's been fixed, what remains, and the honest product scope. It is updated after every round of changes.

## Verification status

- `tsc --noEmit`: clean (0 errors)
- `npm test`: **29/29 pass, 0 fail**
- CI: GitHub Actions workflow at `.github/workflows/ci.yml` runs typecheck + tests on every push/PR to `master`

## What was fixed (this session + previous)

### Critical: fail-open outcomes eliminated

Every check now returns an explicit outcome: `pass`, `finding`, `error`, or `not_checked`. A check error is **never** inferred as `pass` from an empty findings array.

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
- Redirect targets re-validated through `ensureSafeFetchUrl`
- `checkTls` pre-resolves and validates DNS before opening TLS socket
- `verifyDomain` routes meta-tag fetch through guarded helper

### Critical: end-to-end bounded fetch

`fetchWithTimeout` uses one deadline covering connection + redirects + body reading. `readBodyBounded` enforces a 4 MB byte cap while streaming. Bodies consumed on redirects, timers cleared in `finally`. Applied to HTML, scripts, exposed files, RDAP, DoH, and verification.

### High: atomic scan persistence

Migration `20261113030000_atomic_scan_persistence.sql` adds `idempotency_key` to `scans` and `record_scan_result` RPC that persists scan + site schedule atomically. Retries with same idempotency key are safe.

### High: canonical finding identity

`worker.mjs` imports `findingIdentity`/`resourceForFinding` from `finding-identity.mjs`. One canonical identity (site + check + affected resource) used consistently for lookup, insert, touch, reopen, resolve. Reopened findings trigger alerts.

### New: product scope doc

`PRODUCT_SCOPE.md` defines what Bulwark is (external posture monitoring) and what it is NOT (vulnerability scanner, authenticated scanner, code scanner, compliance tool, WAF). Sets honest expectations: "Bulwark finds and explains risks it can verify."

### New: read-only repo analysis (GitHub)

- Migration `20261113040000_github_connections.sql` — encrypted `github_connections` table (RLS, service-role write only)
- `server/github.mjs` — scans GitHub repos for hardcoded secrets, sensitive filenames, unpinned dependencies
- API: `GET/POST/DELETE /api/connections/github`, `POST /api/connections/github/:id/scan`
- Tokens encrypted at rest with `BULWARK_ENCRYPTION_KEY`, never readable from browser

### New: Supabase platform checks

- Migration `20261113050000_supabase_connections.sql` — encrypted `supabase_connections` table (RLS, service-role write only)
- `server/supabase.mjs` — checks storage buckets for public access, Supabase API connectivity
- API: `GET/POST/DELETE /api/connections/supabase`, `POST /api/connections/supabase/:id/scan`
- Credentials encrypted at rest, never readable from browser

### New: connections module

- `server/connections.mjs` — generic CRUD for encrypted connections (list/add/delete/resolve), following the `keys.mjs` BYOK pattern

### New: CI/CD

- `.github/workflows/ci.yml` — runs `npm ci`, `tsc --noEmit`, `npm test` on push/PR to `master`

### New: fixture-based tests

- `server/checks-fixtures.test.mjs` — 7 tests: clean site, vulnerable site, defacement detected/missed, SSRF redirect block, partial scan, 403 vs 404 distinction
- `server/platform-tests.test.mjs` — 6 tests: GitHub secrets, clean repo, sensitive filenames, unpinned deps, public/private storage buckets

## Remaining work

1. **Supabase RLS introspection** — `scanSupabaseProject` attempts an RPC `bulwark_check_rls` which doesn't exist on most projects (silently skipped). A real RLS check needs either a service-role key with SQL access or predefined RPC functions in the user's Supabase project.

2. **Frontend UI for connections** — API endpoints exist but no React screens yet. Users can't connect GitHub/Supabase accounts from the UI.

3. **Frontend UI for findings from repo/platform scans** — Findings from GitHub/Supabase scans aren't stored in the `findings` table yet; they're returned inline from the scan endpoint.

4. **Network-level egress controls** — Application-level SSRF protection is in place; firewall/egress proxy rules recommended as defense in depth for Render deployment.

5. **More adversarial tests** — Clean sites with tricky edge cases, vulnerable sites with multiple finding types, changed evidence scenarios.

## Priority order going forward

1. Add frontend screens for GitHub/Supabase connections
2. Store repo/platform findings in the `findings` table (so they appear in the UI alongside scan findings)
3. Implement real Supabase RLS introspection (service-role SQL or predefined RPC)
4. Add frontend UI for repo/platform findings
5. Network-level egress restrictions on Render

## Verification

- `tsc --noEmit`: clean
- `npm test`: 29/29 pass
- All critical trust issues from previous reviews are resolved
