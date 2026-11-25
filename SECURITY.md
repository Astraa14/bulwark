# Security Policy

## Security Model & Boundaries

Bulwark is an external security posture monitor designed around least privilege:

- **Read-only connectors**: Bulwark never requests write permissions to customer repositories, DNS providers, hosting accounts, or databases. Supabase connections explicitly reject `service_role` and `sb_secret_` keys prior to making any network call.
- **Zero customer row reads**: Supabase `anon` exposure probes use HTTP `HEAD` requests with `Prefer: count=exact` and never download table row contents.
- **SSRF & DNS-rebinding protection**: Outbound scanner fetches are restricted to HTTP/HTTPS on ports `80` and `443`, block private/loopback/link-local/CGNAT/metadata IPv4 and IPv6 ranges, pin validated IP addresses at the socket level, and re-verify every redirect hop.
- **Credential encryption at rest**: User BYOK AI keys, GitHub tokens, Supabase publishable keys, webhook secrets, and alert webhook URLs are encrypted server-side using AES-256-GCM (`BULWARK_ENCRYPTION_KEY`) before database persistence and are never returned to browser clients in plaintext.
- **Tenant isolation**: All workspace tables enforce Postgres Row Level Security (`auth.uid() = user_id`), verified by automated cross-tenant isolation tests in `server/tenant-isolation.test.mjs`.

See [PRODUCT_SCOPE.md](PRODUCT_SCOPE.md) for full details on what Bulwark checks and what it does not claim to prove.

## Reporting a Vulnerability

If you discover a security vulnerability in Bulwark itself (such as an SSRF bypass, tenant-isolation flaw, webhook verification bypass, or credential exposure):

1. **Do not open a public GitHub issue** with exploit details.
2. Report it privately via GitHub's **Report a vulnerability** (Private Vulnerability Reporting) advisories tab on this repository, including reproduction steps and affected files.
3. Please only test against local instances or assets you own and control.
