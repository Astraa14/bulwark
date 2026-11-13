# Bulwark Product Scope

## What Bulwark is

Bulwark is an **external security posture monitoring** tool for small products and "vibe coders" who ship fast and aren't security specialists. It continuously checks surface-level signals that an attacker can also see from the outside, then explains findings in plain language with concrete remediation steps.

## What Bulwark currently checks (external layer)

| Layer | What's checked | What it does NOT prove |
|-------|---------------|----------------------|
| DNS | Nameservers (NS), mail records (MX), domain expiry via RDAP | That email actually works |
| TLS | Certificate validity, expiry, issuer | That the application logic is secure |
| HTTP | Status codes, response time, security headers (HSTS, CSP, nosniff, referrer) | That headers are correctly enforced in all contexts |
| Exposed files | `.env`, `.git/config`, `.DS_Store`, SQL dumps, phpinfo | That no other sensitive files exist |
| CORS | Wildcard origins, reflected origins, credentials | That no private data leaks through other endpoints |
| Cookies | Secure, HttpOnly, SameSite flags | That session logic is secure |
| Mixed content | HTTP resources on HTTPS pages | That all sub-resources are safe |
| Directory listing | Index-of pages | That no other directories are exposed |
| Defacement | Homepage text drift vs baseline, defacement markers | That no deeper compromise exists |
| Discovery | robots.txt, sitemap.xml, security.txt | That no hidden routes exist |
| Secrets | Hardcoded keys/tokens in homepage and same-host JS bundles | That no secrets exist in server code or other assets |

## What Bulwark is NOT

- **Not a vulnerability scanner** — it does not crawl routes, fuzz parameters, or test for SQL injection, XSS, CSRF, IDOR, etc.
- **Not an authenticated scanner** — it cannot see behind login walls, admin panels, or role-gated content.
- **Not a code scanner** — it does not read your source code (yet — repo analysis is planned).
- **Not a compliance tool** — it does not produce SOC 2, HIPAA, or PCI reports.
- **Not a WAF or runtime protection** — it does not block attacks in progress.

## What's coming next (read-only repo + platform analysis)

Per the roadmap, Bulwark will add read-only integrations that inspect the **project itself**, not just the live site:

1. **GitHub repo analysis** — leaked secrets in commit history and files, dependency vulnerabilities in lockfiles, risky patterns in server routes/auth code, exposed environment variables in config files.
2. **Supabase checks** — whether exposed tables have appropriate Row Level Security (RLS), whether policies are overly broad, whether storage buckets are publicly accessible.
3. **Deployment checks** — Render/other provider configuration and deployment metadata.

Each integration requests **read-only, least-privilege access** and clearly states what it did and didn't inspect.

## The honest promise

> "Bulwark finds and explains risks it can verify."

A scan can return:
- **completed** — every check had enough evidence to reach a conclusion.
- **partial** — some checks errored or were skipped; the site may still have issues Bulwark couldn't verify.
- **failed** — the site was unreachable; no checks could run.

Bulwark never reports "secure" when it couldn't verify a check. It reports "could not check" instead.

## Data handling

- Scan results and findings are stored in Supabase with RLS so users only see their own data.
- BYOK AI keys (OpenAI/Anthropic) are encrypted at rest with `BULWARK_ENCRYPTION_KEY` and never logged.
- GitHub/Supabase connection tokens (future) will follow the same encrypted-at-rest pattern.
- Outbound scanner requests are SSRF-hardened: only ports 80/443, only public non-private IPs, redirect targets re-validated.

## Who this is for

Small product teams, indie developers, and "vibe coders" who want a security safety net without becoming security experts. Bulwark is designed to catch the obvious, high-impact mistakes (exposed `.env`, missing CSP, no HSTS, hardcoded keys, open CORS) and explain how to fix them in plain language.
