# Bulwark Critique & Reflection

_Last updated: 2026-11-15. This document tracks what is actually implemented, what was corrected, and what remains. It supersedes the 2026-11-13 version, which contained claims that no longer matched the code._

## Verification status (run locally on 2026-11-15)

| Command | Result |
|---|---|
| `npx tsc --noEmit` | clean (0 errors) |
| `npm test` | **114/114 pass, 0 fail** |
| `npm run build` | success; `dist/assets/index-CZBRBpGs.js` 532.12 kB (149.36 kB gzip) |
| `npm run db:check` | `supabase/apply_all.sql` current (15 migrations) |

CI (`.github/workflows/ci.yml`, Node 22) now runs `npm ci`, typecheck, `npm run db:check`, `npm test`, and `npm run build` on every push/PR to `master`. The previous test entry point (`node --test server`) did not work on Node 24 and silently ran zero test files; the script now uses the quoted glob `node --test "server/**/*.test.mjs"`.

**Not verified yet:** the new migrations have not been applied to any real Supabase project, and the new code has not been deployed. A live GitHub webhook has not been sent end-to-end; webhook behaviour is covered by signed-request tests against an in-memory database. Runtime RLS behaviour is asserted only as SQL policy text; applying the migration is the runtime proof.

## What changed in this round

### Critical: tenant isolation

- `findings` and `scans` now carry an explicit `user_id` and platform identity (`platform`, `connection_id`, `resource`, `commit_sha`, `ref`).
- Ownership is backfilled **only** where it is provable through the linked site. Legacy platform rows with no provable owner remain stored but are invisible to every user; they are not guessed into a tenant.
- RLS is enabled with owner-only `select`/`update` policies. Browser clients cannot insert or delete findings; the server writes through owner-scoped RPCs.
- `GET /api/findings/platform` filters by `user_id` and `site_id is null`; `/api/explain` verifies ownership before explaining anything.
- Platform scans, findings, and last-scanned revisions are scoped to owner + connection + resource. A GitHub delivery is unique per connection, not globally.

### Critical: webhook verification and idempotency

- The GitHub webhook route is registered **before** `express.json()` and uses route-specific `express.raw({ type: "application/json", limit: "1mb" })`, so HMAC verification sees the exact signed bytes.
- Signatures are compared in constant time; missing/invalid signatures are rejected before any database work.
- A connection's webhook secret is matched to the delivery; if two connections share a secret, an unscoped URL is refused as ambiguous. The per-connection URL `/api/webhooks/github/:connectionId` disambiguates.
- The repository named in a signed payload must be readable with that connection's token before work is queued. A valid signature alone is not treated as authorization.
- A unique `(connection_id, delivery_id)` index on `platform_scan_jobs` and `scans` makes redeliveries a no-op. Each job has one stable scan UUID (`platform_scan_jobs.scan_id`), so every retry of that job updates the same scan instead of creating another. The UUID is never derived from user/connection/resource/commit strings, and it is validated with `assertScanId` before any database call.
- Slack alerts are sent only for findings the persistence RPC reports as newly created or reopened. A duplicate delivery returns `duplicate: true`, no actionable findings, and no alert.
- Webhook requests only enqueue work; the worker processes jobs with `FOR UPDATE SKIP LOCKED` and reclaims stale running jobs after 15 minutes.

### Critical: scan identity and alert egress

- `scans.id` and `platform_scan_jobs.scan_id` are `uuid` columns. Scan ids are now real UUIDs: a platform job carries one UUID for every retry, a website slot derives a stable UUIDv5 pair (`scanId`, `idempotency_key`) from `site.id` + `next_scan_at`, and a new slot or manual scan gets a new UUID. `server/scan-id.mjs` centralises this and `assertScanId` rejects non-UUID values before any database call.
- `sendSlack` and `POST /api/alerts/test` accept only `https://hooks.slack.com/services/...`. The test route previously forwarded an arbitrary user-supplied URL to `fetch`, which was an authenticated SSRF; it now returns 400. Slack error responses are no longer echoed back, so response bodies cannot leak through error text.

### High: atomic platform persistence and safe migration window

- `persist_platform_scan_result` writes the scan, finding changes, connection metadata, and repository revision in one transaction, scoped to owner/connection/resource.
- The previous 19-argument `persist_scan_result` signature is kept as a compatibility wrapper so the currently deployed worker keeps working between running the migration and deploying the new code.
- Website scans have a stable `idempotency_key` per claimed slot: `server/scan-id.mjs` derives both the scan UUID and the key with UUIDv5 from `site.id` + `next_scan_at`. Retrying the same slot reuses both values; the next due slot is a new scan. The previous code used `site.id` as both, which made every scan after the first return the first scan id and suppressed all later findings.
- The migration deliberately avoids a hard owner-shape `CHECK` constraint, because the old deployed code inserts platform rows without an owner. RLS hides unowned rows instead of breaking old scans mid-deploy.

### High: GitHub scanner corrections

- The scanner reads the **exact pushed commit** for webhook scans instead of silently scanning a moving branch head.
- Coverage is explicit and bounded: 500 text files, 500 KB per file, binary/large/unreadable files and GitHub tree truncation are all reported. A truncated scan is `partial`, never "complete".
- Every pattern match in a file is reported (previously only the first), with redacted evidence and a link to the line at the scanned commit.
- The hard-coded vulnerability list was removed. Dependency advisories come from OSV, and only for npm `package-lock.json`; OSV receives package names and exact versions only. Other ecosystems are counted as unanalyzed rather than implied safe.
- Repository listing paginates and repository coordinates are validated before requests. Tokens remain read-only and encrypted at rest.

### High: Supabase SSRF and least privilege

- A connection accepts only a canonical `https://<ref>.supabase.co` origin derived from a validated project reference. Arbitrary URLs, custom ports, credentials in URLs, and paths are rejected before DNS resolution.
- Only publishable/anon keys are accepted; `sb_secret_` and service-role JWTs are rejected before any request.
- Checks now return explicit `pass`/`finding`/`not_checked`/`error` outcomes. A denied storage listing or missing RLS helper is shown as **not checked**, never as safe.
- RLS analysis is labelled heuristic. It flags RLS disabled, RLS with no policies (deny-by-default), and literal `true` policies; it does not evaluate policy logic.
- The customer RLS helper lives at `supabase/customer/bulwark_check_rls.sql`. It is no longer installed in Bulwark's own database.
- Unauthenticated explanatory comments that implied full policy review were corrected.

### Corrected documentation and UI

- GitHub sign-in is **identity only**. The `repo` OAuth scope was removed. Repository access is a separately explained, read-only PAT entered by the user; the UI says so explicitly.
- The Supabase connection form no longer reuses the GitHub form's state for its project name and key. It now has distinct fields and explains which key is accepted.
- Connections show their own webhook URL, last scan status, and an explicit coverage summary (files read, truncation, tables inspected, RLS/storage checked).
- Platform findings are grouped by the stored `platform` value rather than guessing from check-key prefixes. Resources, confidence, "what this does not prove", and remediation are displayed.
- `PRODUCT_SCOPE.md` now describes the implemented caps and limitations instead of promised features.
- The previous critique's claims that OAuth with `repo` scopes replaced PATs, and that the repo scan had "no 40-file cap" (it was capped, and is now explicitly capped at 500), were wrong and have been removed.

## Migration and rollout

1. The generated migration bundle is `supabase/apply_all.sql` (15 migrations, idempotent).
2. Review and run it in a **staging/copy** Supabase project first, then in production.
3. Confirm success before deploying code that depends on the new columns and RPCs. The compatibility wrapper keeps the old worker functional in the meantime.
4. Deploy the API/worker and frontend together after confirmation.
5. Configure a disposable repository and a locally entered PAT/webhook secret to verify delivery end-to-end. No credentials belong in chat or source.

The assistant cannot apply the migration: this environment has no `psql`, Supabase CLI, or database connection string.

## Remaining limitations

1. **Production rollout is pending.** Nothing is committed, pushed, or deployed until the migration is confirmed.
2. **Live webhook path is untested.** Signed-request tests use a fake database and fake GitHub API; they do not prove GitHub's real delivery headers, proxy body handling, or Render/network behaviour.
3. **Repository coverage is bounded.** Scans read at most 500 text files of at most 500 KB at one revision. Commit history, git objects, issue/PR text, releases, and generated bundles are not inspected.
4. **OSV coverage is npm-only.** Python, Ruby, Go, Rust, and other lockfiles are reported as unanalyzed.
5. **RLS inspection needs customer setup.** Without the helper, RLS is "not checked". With it, analysis is heuristic and does not evaluate policy expressions or role targeting.
6. **Storage listing may be denied** to a publishable key. That is surfaced as not checked, not as a clean result.
7. **Legacy unowned platform rows stay invisible.** They are preserved, not deleted, but no owner is invented.
8. **No network-level egress controls** are implemented in this repository; SSRF protection is application-level. Firewall/egress proxy rules remain recommended defence in depth.
9. **AI explanations** are user-triggered and send the selected finding's content to the user's chosen provider. They are not an assessment of exploitability.
10. **Secrets in commit history** are out of scope for this round.

## Priority order going forward

1. Run `supabase/apply_all.sql` on a copy/staging project, then production, and confirm.
2. Deploy API/worker/frontend; watch website scans and platform jobs through the migration window.
3. Verify a real webhook against a disposable repository with a locally entered secret, including redelivery and signature failure.
4. Add a second dependency ecosystem to OSV (likely Python `requirements.txt`/`poetry.lock`) with the same name/version-only rule.
5. Explore commit-history secret scanning with explicit performance and rate-limit bounds.
6. Add network-level egress restrictions on Render.
