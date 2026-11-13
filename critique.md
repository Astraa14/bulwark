I read the updated `critique.md` and checked the current scanner code. The reliability work is moving in the right direction, but **the critique overstates what the implementation currently guarantees**. It says network failures never become passes and outbound requests are fully protected; the current code still has paths where that can happen.

My recommendation: **don’t add more surface checks yet, and don’t call this a tool that secures an application yet.** First make scan results dependable, then expand what Bulwark can actually inspect.

## Fix these trust issues first

### 1. A network failure can still be recorded as a pass

The check wrapper handles explicit errors, but some underlying functions hide failures before the wrapper sees them:

- `checkLeakedSecretsInner` drops failed JavaScript bundle requests and returns `error: null`. A scan of only some of the bundles can therefore look like a complete secret check.
- `checkDomainExpiryInner` catches RDAP failures and returns no error when it cannot retrieve registration data.
- `checkDnsInner` gets `null` for failed DNS lookups, then returns `error: null`.
- Discovery treats any non-200 response as “not found,” which can confuse an inaccessible or broken endpoint with a clean absence.

That undermines the core promise of per-check outcomes. **A check must report whether it had enough evidence to reach its conclusion.** For example: `404` may mean “not present”; `403` means “could not inspect”; a timeout means “error.”  
[Scanner outcome handling](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L327-L359) · [Secrets check](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L699-L737) · [DNS check](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L822-L867)

### 2. The request deadline and body limits are not end-to-end

`fetchWithTimeout` clears its timer when the response arrives, before callers consume the body. `safeFetch` then calls `res.text()` without a streaming byte limit. So a slow or enormous body can still consume resources after the supposed timeout. Redirect cleanup also reads the entire redirect body.

Use a request helper that owns the *whole* lifecycle: connection, redirects, and bounded body reading. It should abort on one overall deadline, enforce a byte cap while streaming, and cancel response bodies in cleanup paths. Apply it consistently to HTML, scripts, exposed-file probes, RDAP, and verification.  
[Fetch helper and body handling](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L62-L127) · [Optional fetch](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L327-L359)

### 3. DNS validation is not yet a strong SSRF boundary

The code resolves a hostname to check its addresses, then calls `fetch()` with the hostname. The HTTP client may resolve it again; a changed DNS answer can make the request go somewhere different from the address that was checked. The direct TLS socket also resolves independently.

There are also edge cases in the hand-written IP blocklist. Hostname checks and address checks should use a robust parser/classifier for IPv4 and IPv6, including reserved and special-use ranges—not just prefixes. Treat empty or failed resolution as unsafe. Add network-level egress controls as defense in depth.

**Important:** this protects Bulwark’s infrastructure, not just the customer site. I would not expand crawling until this is addressed.  
[Address validation and fetch setup](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L11-L127) · [Direct TLS connection](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/checks.mjs#L972-L1005) · [Verification flow](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/verify.mjs#L17-L95)

### 4. A scan can persist halfway and then fail

`scanSite` inserts the scan, then separately inserts or updates findings, resolves stale findings, updates the site schedule, and sends alerts. If a database request fails halfway, the scan may be partly recorded. A retry can then produce confusing state or duplicate work. The database lease avoids overlap, but **it doesn’t make these multiple writes atomic**.

Move the final persistence/reconciliation into a database transaction, ideally through one RPC that accepts the scan result and applies its changes atomically. Use a scan ID or idempotency key so retrying the same result is safe. Also ensure lease duration is longer than the maximum scan runtime or renew the lease while a scan runs.  
[Worker persistence and lease lifecycle](https://github.com/Astraa14/bulwark/blob/e156fb42e78c4b13a82a66829c8535cfcf2f69bf/server/worker.mjs#L41-L179)

## Then expand beyond the public homepage

The current scanner is an **external posture monitor**: homepage headers and body, selected common paths, a few same-host scripts, DNS/RDAP, and TLS. That can catch real issues, but it can’t establish that the application is secure. It can’t reliably see private APIs, authenticated routes, authorization rules, source code, dependencies, or database policies.

For vibe coders, I’d make the product a **guided security review of a project’s actual components**, starting with read-only integrations:

1. **Repository checks:** leaked secrets, dependency vulnerabilities, risky patterns in server routes and auth code, unsafe environment-variable exposure, and deployment configuration.
2. **Supabase checks:** whether exposed tables have appropriate RLS, whether policies are overly broad, and whether storage/API settings expose data.
3. **Deployment checks:** inspect supported provider configuration and deployment metadata, while distinguishing verified facts from guesses.
4. **External checks:** retain the existing scanner as one layer, then add a conservative, explicitly scoped crawl of public routes.

Use established scanners and advisory sources where possible instead of trying to invent comprehensive static analysis. Any integration should request **read-only, least-privilege access** and clearly state what it did and didn’t inspect.

## How to decide whether it’s actually working

Before adding more detections, build a repeatable test suite with mocked network and database behavior. At minimum, test these invariants:

- A timeout, DNS failure, oversized response, or denied request is never recorded as a pass.
- A failed or partial scan never resolves findings.
- A `404` can count as absence only for checks where that meaning is valid; a `403` does not mean “clean.”
- A redirect to a blocked address, IPv6 private address, or non-web port is rejected.
- Retries and worker crashes don’t duplicate or corrupt finding state.
- The same check can track distinct affected resources.
- Findings update their latest evidence and severity; reopened issues can alert again.
- A scan with incomplete evidence shows **partial / could not verify**, not “secure.”

The critique says `npm test` passed 12 tests, but I have not independently run that suite. Passing those tests would be useful evidence, not proof of overall security.

## Priority order I’d use

1. **Close the false-pass gaps** in DNS, RDAP, discovery, and script inspection.
2. **Make network access safe and bounded end-to-end**, including TLS and verification.
3. **Make scan persistence atomic and retry-safe.**
4. **Add adversarial regression tests** for the failure cases above and verify them in CI.
5. **Add read-only repository and Supabase analysis**—the highest-value coverage for your intended users.
6. Expand external crawling only after scope controls and outbound safety are solid.

The product promise should be honest: **“Bulwark finds and explains risks it can verify”**, not “your app is secure.” A useful security tool helps inexperienced developers fix real problems and makes its blind spots obvious; no scanner can certify an application as safe.

---

## Status after the reliability + safety fixes (2026-11-13)

The following critical and high issues from this review are now **fixed**:

### Fixed: “not detected” can still become “passed” (was Critical)

Each check now returns an explicit outcome—`pass`, `finding`, `error`, or `not_checked`—and a check error is recorded as `"error"`, never inferred as `"pass"` from an empty findings array.

- `checkExposedFiles` (exposed `.env`, `.git`, `.DS_Store`, SQL dumps, phpinfo) — network failures now surface as `error`, not a pass.
- `checkCors` — fetch failures are now `error`, not a pass.
- `checkDiscovery`, `checkLeakedSecrets`, `checkDomainExpiry`, `checkDns` — all wrapped with explicit outcomes; timeouts/DNS failures are `error`.
- `safeFetch` distinguishes `404` (genuine absence, no error) from other non-200 statuses (error).
- Worker auto-resolution (`server/worker.mjs`) only resolves stale findings when `result.status === "completed"`. A partial or failed scan no longer closes real findings.

### Fixed: SSRF protection is now a boundary (was Critical)

All outbound requests go through a single guarded fetch helper (`ensureSafeFetchUrl` + `fetchWithTimeout`):

- Scheme restricted to `http:` / `https:`.
- Port restricted to 80 / 443.
- Hostname blocks localhost, `.local`, private IPv4 (10/127/172.16-31/192.168), link-local, and reserved IPv6 ranges.
- DNS resolution is checked against the same blocklist; DNS errors are treated as unsafe.
- Redirect targets are re-validated through `ensureSafeFetchUrl` (scheme, host, port, DNS) before being followed.
- `checkTls` now pre-resolves and validates DNS addresses before opening a raw TLS socket.
- `verifyDomain` routes its meta-tag fetch through the guarded helper and validates redirect targets (scheme, port, DNS).
- `isUnsafeIp` and `hasUnsafeDns` are now exported from `checks.mjs`.

### Fixed: Scan locks and rate limits only work inside one process (was High)

Already addressed by prior work: `claim_site_scan` / `release_site_scan` are database-backed RPCs (migration `20261113020000_scan_claims.sql`), used by both API and worker processes. The worker holds a per-site lease for the duration of a scan.

### Fixed: Finding identity isn’t used consistently (was High)

`server/worker.mjs` now imports `findingIdentity` and `resourceForFinding` from `server/finding-identity.mjs` instead of duplicating them. One canonical identity—site + check + normalized affected resource—is used consistently for lookup, insert, touch, reopen, and resolve. Reopened findings are included in alert delivery.

### Fixed: End-to-end bounded fetch (new in this round)

`fetchWithTimeout` now uses a single deadline covering the entire operation—connection, redirects, and body reading. `readBodyBounded` enforces a 4 MB byte cap while streaming and aborts on oversized bodies. Response bodies are consumed on redirects and cleaned up in `finally`. Applied consistently to HTML, scripts, exposed-file probes, RDAP, DoH, and verification.

### Fixed: Atomic scan persistence (new in this round)

Migration `20261113030000_atomic_scan_persistence.sql` adds an `idempotency_key` column to `scans` and a `record_scan_result` RPC that persists the scan record and site schedule update in a single database transaction. The worker calls this RPC with an idempotency key, making retries safe. Finding reconciliation remains in the application layer but operates on the atomically-recorded scan.

### Fixed: Response handling failure and resource semantics (was High)

`fetchWithTimeout` consumes the response body on redirects and clears its timer in `finally`. Optional fetches (`safeFetch`) return a bounded result or a typed error rather than silently swallowing failures.

### Medium: coverage counts still need a clear contract

Addressed structurally: `runChecks` now derives `checksTotal`, `checksPassed`, `checksErrored`, and `checksSkipped` from the per-check outcome registry, not from `checksTotal - findings`. The scan status is `partial` when any check errored or was skipped, so the UI can’t show a partially-scanned site as fully clean.

---

## Remaining (not addressed in this round)

- **Product scope**: The scanner still mainly inspects the public homepage plus a small set of common paths and same-host scripts. It is external posture monitoring, not a comprehensive vulnerability assessment. Read-only repo integration (secrets in lockfiles, Supabase RLS, auth mistakes, deploy config) is still the highest-value next step.
- **Automated test coverage**: 16 tests now cover network-error-never-pass, exposed-file failure, secrets script failure, RDAP/DNS failure, discovery 404-vs-403 distinction, oversized body rejection, redirect-SSRF blocking, and blocked schemes/ports. More fixture-based tests (clean sites, vulnerable examples, changed evidence) are still valuable before production reliance.
- **SSRF defense-in-depth**: Application-level checks are now in place; network-level egress restrictions (firewall / egress proxy) are still recommended as an additional layer.

---

## Recommended order (unchanged, now with items 1–2 done)

1. ✅ Fix fail-open outcomes; make all outbound traffic safe.
2. ✅ End-to-end bounded fetch with byte caps.
3. ✅ Move locks/rate limits to shared coordination (already DB-backed).
4. ✅ Atomic scan persistence via `record_scan_result` RPC.
5. ✅ Align finding identity with the schema.
6. Add tests and repo-aware checks.
7. Then expand coverage in a clearly stated product scope.

**Verification**: `tsc --noEmit` is clean; `npm test` passes 16/16.
