# Bulwark Product Scope

_Last updated: 2026-11-22_

## What Bulwark is

Bulwark is an **external security posture monitor** for small products and "vibe coders" who ship fast and aren't security specialists. It checks signals an attacker can see from the outside, plus a deliberately limited read-only view of GitHub repositories and Supabase projects. Findings are explained in plain language with concrete remediation steps.

## Website checks (external layer)

| Layer | What's checked | What it does NOT prove |
|-------|---------------|----------------------|
| DNS | Nameservers (NS), mail records (MX), SPF, DMARC, domain expiry via RDAP | That email actually delivers or DKIM keys are valid |
| TLS | Certificate validity, expiry, issuer | That the application logic is secure |
| HTTP | Status codes, response time, security headers (HSTS, CSP, nosniff, referrer) | That headers are correctly enforced in all contexts |
| Exposed files | `.env`, `.git/config`, `.DS_Store`, SQL dumps, phpinfo | That no other sensitive files exist |
| CORS | Wildcard origins, reflected origins, credentials | That no private data leaks through other endpoints |
| Cookies | Secure, HttpOnly, SameSite flags | That session logic is secure |
| Mixed content | HTTP resources on HTTPS pages | That all sub-resources are safe |
| Directory listing | Index-of pages | That no other directories are exposed |
| Defacement | Homepage text drift vs baseline, defacement markers | That no deeper compromise exists |
| Discovery | robots.txt, sitemap.xml, security.txt | That no hidden routes exist |
| Secrets & source maps | Hardcoded keys/tokens in homepage and same-host JS bundles, plus publicly downloadable `.js.map` source maps | That no secrets exist in server code or other assets |
| API exposure | Public `/openapi.json`, `/swagger.json`, and unauthenticated `/graphql` introspection | That other API routes are properly authorized |

Every check reports one of `pass`, `finding`, `error`, or `not_checked`. A scan is `completed` only when every check reached a conclusion; otherwise it is `partial`, and the UI shows what was not checked.

## GitHub repository checks (read-only)

A connection is a GitHub username plus a **personal access token** with read-only `Contents` (and `Metadata`) access. Signing in with GitHub is **identity only** and does not request repository scopes.

A repository scan:

- reads the repository tree at the default branch head, or at the exact commit named by a verified webhook delivery;
- reads up to **500 text files** up to 500 KB each; larger files, binary files, unreadable blobs, and files beyond the cap are counted and disclosed;
- flags hardcoded credentials in file contents (redacted evidence plus a line link) and scans added lines in up to **10 recent commits** for high-confidence provider secrets;
- flags client-exposed secret environment variable names (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`, `PUBLIC_*` paired with secret/service-role/database variable names);
- flags sensitive filenames (`.env`, private keys, database dumps, etc.);
- flags unpinned dependency declarations;
- queries [OSV](https://osv.dev) for **npm (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) and Python (`requirements.txt`, `poetry.lock`, `uv.lock`)** lockfiles, sending only package names, ecosystems, and exact versions — never source code, paths, tokens, or credentials; other lockfiles are reported as unanalyzed;
- flags container, CI, Vercel CORS, and Supabase SQL migration configuration risks (root Dockerfile user, `pull_request_target`, `permissions: write-all`, Actions pinned to mutable branches like `@main`, wildcard CORS with credentials, `supabase/migrations/*.sql` tables missing `ENABLE ROW LEVEL SECURITY`);
- supports optional per-repository scheduled scans (every 6 hours to weekly) in addition to push webhooks.

It does **not** scan full historical git object packs beyond the recent commit window, issues, pull requests, releases, or server-side authorization logic. It is not a SAST engine.

## Supabase project checks (read-only)

A connection stores the project reference (`https://<ref>.supabase.co`) and a **publishable/anon key**. Service-role keys and `sb_secret_` keys are rejected before any request.

- connectivity with the publishable key;
- storage bucket listing; when the key cannot list buckets, storage is reported as **not checked**, not as safe;
- RLS metadata through the optional helper at `supabase/customer/bulwark_check_rls.sql`, which each customer installs in their own project. Without it, RLS is reported as **not checked**;
- optional scheduled background re-scans (default every 6 hours, configurable from hourly to weekly per connection).

RLS analysis is **heuristic**: it reports tables with RLS disabled, RLS enabled with no policies (deny-by-default, low severity), and policies whose expression is the literal `true`. It does not evaluate policy expressions, role targeting, or query results. A heuristic pass does not prove data is protected.

## Webhooks (GitHub push)

- Per-connection URL: `/api/webhooks/github/:connectionId`.
- The raw request body is HMAC-verified against the connection's encrypted webhook secret before parsing (1 MB limit).
- The delivery's repository must be readable with that connection's token; otherwise it is rejected.
- A delivery ID is unique per connection, so retries and redeliveries do not create duplicate scans or alerts.
- Webhooks only enqueue work; the worker scans and persists later with a stable scan ID.

## What Bulwark is NOT

- **Not a vulnerability scanner** — it does not crawl routes, fuzz parameters, or test for SQL injection, XSS, CSRF, IDOR, etc.
- **Not an authenticated scanner** — it cannot see behind login walls, admin panels, or role-gated content.
- **Not a full code audit** — repository checks cover text files at one revision, not history or runtime behavior.
- **Not a compliance tool** — it does not produce SOC 2, HIPAA, or PCI reports.
- **Not a WAF or runtime protection** — it does not block attacks in progress.
- **Not a guarantee of safety** — clean scans mean the checks that ran found nothing in what they could see.

## The honest promise

> "Bulwark finds and explains risks it can verify — and says what it could not check."

A scan can be:

- **completed** — every check had enough evidence to reach a conclusion.
- **partial** — some checks errored, were skipped, or hit a coverage cap.
- **failed** — the target was unreachable or credentials were rejected; no conclusions were drawn.

## Data handling

- Website, GitHub, and Supabase scans/findings are stored in Supabase with row-level security scoped to the signed-in owner. Legacy platform rows whose owner cannot be proven are retained but hidden from every user.
- GitHub tokens, Supabase keys, and Slack/Discord webhook URLs are encrypted at rest with `BULWARK_ENCRYPTION_KEY` and are never returned to the browser for platform tokens (only a masked preview).
- Email alerts are optional and sent via Resend when `RESEND_API_KEY` is configured on the server.
- Webhook bodies are not stored; only delivery metadata (connection, commit, resource, delivery ID) is queued.
- OSV receives only package names, ecosystems (`npm`/`PyPI`), and exact versions.
- AI explanations and weekly priority briefs run only when a user asks, using the user's own OpenAI, Anthropic, or Google Gemini key; only the selected finding/summary text is sent to that provider.
- Alert deliveries are queued in `alert_deliveries` and retried automatically with backoff on transient Slack, Discord, or email provider failures.
- Outbound scanner requests are SSRF-hardened: HTTP/HTTPS only, ports 80/443, public IPs only, every redirect hop re-validated, bounded response bodies. Supabase hosts are derived from the validated project reference instead of accepting arbitrary URLs.
- Network-level egress restrictions are still recommended as defense in depth (see `render.yaml`).

## Who this is for

Small product teams, indie developers, and "vibe coders" who want a security safety net without becoming security experts. Bulwark is designed to catch obvious, high-impact mistakes and explain how to fix them.
