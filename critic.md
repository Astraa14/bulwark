Agreed. Bulwark should be a **continuous, evidence-based security monitor that tells a non-expert what to fix**—not a homepage checker that hands out a “secure” badge.

One important issue before adding features: **the current repository code doesn’t match the claims in `critique.md`.** In the latest source I can inspect, `verify.mjs` imports `isUnsafeIp`, `hasUnsafeDns`, `ensureSafeFetchUrl`, and `fetchWithTimeout` from `checks.mjs`, but the checked-in `checks.mjs` doesn’t export those functions. That can stop the API from starting. The checked-in scanner also appears to lack the newer outcome and guarded-fetch behavior the critique says is implemented. So I would **not treat the reported passing tests or “critical issues fixed” as verified** until the actual branch source and CI agree. [Current `verify.mjs`](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/verify.mjs) · [Current `checks.mjs`](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/checks.mjs) · [Current `critique.md`](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/critique.md)

## What I recommend, in order

### 1. Establish a trustworthy baseline

Before broadening coverage, make the shipped code match the documented claims.

- Fix the missing-export/runtime mismatch.
- Run the exact CI workflow from a clean checkout and confirm `npm test` and the build pass.
- Test API and worker startup, and test the Supabase migrations against a disposable project.
- Treat the critique as a set of claims to verify against source and tests—not as evidence by itself.

**Completion bar:** clean install, CI green, API and worker start, migrations apply, and a controlled test scan produces a result.

### 2. Make scan results and finding changes one reliable operation

The worker calls `record_scan_result`, then makes separate database calls to insert, update, and resolve findings. That means scan metadata may commit while finding reconciliation fails. The `Date.now()` idempotency key is also generated anew for each attempt, so it won’t necessarily make a retry of the same job idempotent. [Worker persistence flow](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/worker.mjs#L41-L174)

Move the scan, check outcomes, finding changes, and site schedule update into **one database transaction**. Use a stable job/scan ID across retries. Put alerts in an outbox and deliver them after commit, so a failed alert can be retried without losing findings or duplicating user notifications.

### 3. Measure coverage honestly, check by check

Keep `pass`, `finding`, `error`, and `not checked` distinct all the way from scanner through storage to the UI. A timeout, forbidden response, unsupported check, or incomplete crawl must not become “clean.” Never resolve a finding merely because it wasn’t returned; resolve it only when the specific check/resource was successfully rechecked.

This is particularly important for repository and platform scans: a 40-file scan is not a full-repository scan, and an unavailable RLS-inspection function is “not checked,” not “RLS is okay.”

### 4. Build useful coverage for vibe-coded apps

The existing GitHub integration is a good direction, but it’s currently bounded: it scans up to 40 files, checks a short list of secret patterns and sensitive filenames, and only warns about unpinned dependencies. That can find some real mistakes, but it won’t detect known vulnerable package versions or adequately assess the whole repository. [GitHub scanning limits and checks](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/github.mjs#L1-L5) · [Dependency scan](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/github.mjs#L228-L276)

I’d prioritize these read-only checks:

1. **Secrets:** scan the complete repository tree, clearly report files/commit scanned, avoid storing secret values, and explain revocation and rotation.
2. **Dependencies:** parse lockfiles and match exact direct/transitive versions against a maintained vulnerability advisory source. “Unpinned” is not a substitute for vulnerability detection.
3. **Deployment/config:** flag common dangerous settings in supported hosting and infrastructure configs, with evidence and platform-specific remediation.
4. **Supabase:** make RLS and storage checks genuinely verifiable. The current RLS check depends on the customer installing a custom RPC, so absent that function, actual table-policy coverage is unavailable. Don’t imply otherwise. [Supabase checks and RLS limitation](https://github.com/Astraa14/bulwark/blob/6020c53a7f9a69cfd444eaabece523dc4837a4dc/server/supabase.mjs#L71-L130)

Use least-privilege, read-only integrations. Never ask a user to hand over a service-role key just to simplify inspection.

### 5. Turn detection into continuous monitoring

A monitor needs to notice change, not just offer a button to scan once. Track repository commits, dependency changes, deployment/config changes, domain/TLS/DNS changes, and recurring external checks. Store what revision and asset each result applies to, and alert on meaningful new or reopened risk—not every scan.

### 6. Define the product honestly

Bulwark can credibly say: **“We monitor these assets and report risks we could verify.”** It should not say “your app is secure.” External scans cannot prove authorization is correct or review private application logic. If you later add authenticated tests, require a dedicated test account, explicit scope, and safe, non-destructive test behavior.

## The next implementation I’d choose

**First, reconcile source and tests so the current branch really builds and runs as documented.** Then I’d implement transactional finding persistence and stable retry IDs. Until those are done, adding more checks risks increasing the number of results without making them more trustworthy.

This isn’t flawless yet, and no scanner can guarantee an application is secure. But that order would make Bulwark more credible, more useful in practice, and much less likely to give a vibe coder false reassurance.