Yes—your recent changes are substantial, not just cosmetic. You’ve added per-check outcomes, finding context, and scan coordination, which are the right kinds of improvements. I reviewed the latest code on `master`; this is still a **source review, not a live security test**.

---

## Status after the reliability + safety fixes (2026-11-13)

The following critical and high issues from this review are now **fixed**:

### Fixed: “not detected” can still become “passed” (was Critical)

Each check now returns an explicit outcome—`pass`, `finding`, `error`, or `not_checked`—and a check error is recorded as `"error"`, never inferred as `"pass"` from an empty findings array.

- `checkExposedFiles` (exposed `.env`, `.git`, `.DS_Store`, SQL dumps, phpinfo) — network failures now surface as `error`, not a pass.
- `checkCors` — fetch failures are now `error`, not a pass.
- `checkDiscovery`, `checkLeakedSecrets`, `checkDomainExpiry`, `checkDns` — all wrapped with explicit outcomes; timeouts/DNS failures are `error`.
- Worker auto-resolution (`server/worker.mjs`) only resolves stale findings when `result.status === "completed"`. A partial or failed scan no longer closes real findings.

### Fixed: SSRF protection is now a boundary (was Critical)

All outbound requests go through a single guarded fetch helper (`ensureSafeFetchUrl`):

- Scheme restricted to `http:` / `https:`.
- Port restricted to 80 / 443.
- Hostname blocks localhost, `.local`, private IPv4 (10/127/172.16-31/192.168), link-local, and reserved IPv6 ranges.
- DNS resolution is checked against the same blocklist; DNS errors are treated as unsafe.
- Redirect targets are re-validated through `ensureSafeFetchUrl` (scheme, host, port, DNS) before being followed.
- `checkTls` now validates the host before opening a raw TLS socket.
- `verifyDomain` routes its meta-tag fetch through the guarded helper and validates redirect targets (scheme, port, DNS).
- `isUnsafeIp` and `hasUnsafeDns` are now exported from `checks.mjs` (verify.mjs was importing non-existent functions — fixed).

### Fixed: Scan locks and rate limits only work inside one process (was High)

Already addressed by prior work: `claim_site_scan` / `release_site_scan` are database-backed RPCs (migration `20261113020000_scan_claims.sql`), used by both API and worker processes. The worker holds a per-site lease for the duration of a scan.

### Fixed: Finding identity isn’t used consistently (was High)

`server/worker.mjs` now imports `findingIdentity` and `resourceForFinding` from `server/finding-identity.mjs` instead of duplicating them. One canonical identity—site + check + normalized affected resource—is used consistently for lookup, insert, touch, reopen, and resolve. Reopened findings are included in alert delivery.

### Fixed: Response handling still needs failure and resource semantics (was High)

`fetchWithTimeout` consumes the response body on redirects and clears its timer in `finally`. Optional fetches (`safeFetch`) return a bounded result or a typed error rather than silently swallowing failures.

### Medium: coverage counts still need a clear contract

Addressed structurally: `runChecks` now derives `checksTotal`, `checksPassed`, `checksErrored`, and `checksSkipped` from the per-check outcome registry, not from `checksTotal - findings`. The scan status is `partial` when any check errored or was skipped, so the UI can’t show a partially-scanned site as fully clean.

---

## Remaining (not addressed in this round)

- **Product scope**: The scanner still mainly inspects the public homepage plus a small set of common paths and same-host scripts. It is external posture monitoring, not a comprehensive vulnerability assessment. Read-only repo integration (secrets in lockfiles, Supabase RLS, auth mistakes, deploy config) is still the highest-value next step.
- **Automated test coverage**: New tests added in `server/checks-outcomes.test.mjs` cover network-error-never-pass, exposed-file failure, redirect-SSRF blocking, and blocked schemes/ports. More fixture-based tests (clean sites, vulnerable examples, oversized bodies, changed evidence) are still valuable before production reliance.
- **SSRF defense-in-depth**: Application-level checks are now in place; network-level egress restrictions (firewall / egress proxy) are still recommended as an additional layer.

---

## Recommended order (unchanged, now with items 1–2 done)

1. ✅ Fix fail-open outcomes; make all outbound traffic safe.
2. ✅ Move locks/rate limits to shared coordination (already DB-backed).
3. ✅ Align finding identity with the schema.
4. Add tests and repo-aware checks.
5. Then expand coverage in a clearly stated product scope.

**Verification**: `tsc --noEmit` is clean; `npm test` passes 12/12.
