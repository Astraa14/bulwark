# Bulwark User Guide

Everything you need to connect your live site, GitHub repository, Supabase project, AI copilot, and alert channels in Bulwark.

## Contents
1. [How Bulwark Works (Read-Only Guarantee)](#1-how-bulwark-works-read-only-guarantee)
2. [Understanding Your "Safe to Ship?" Verdict](#2-understanding-your-safe-to-ship-verdict)
3. [Connecting & Verifying a Website](#3-connecting--verifying-a-website)
4. [Connecting GitHub Repositories](#4-connecting-github-repositories)
5. [Connecting Supabase Projects](#5-connecting-supabase-projects)
6. [Fixing, Re-checking & Snoozing Findings](#6-fixing-re-checking--snoozing-findings)
7. [Bring Your Own AI Key (BYOK Copilot)](#7-bring-your-own-ai-key-byok-copilot)
8. [Alerts & Weekly Posture Digests](#8-alerts--weekly-posture-digests)
9. [Reports & Exports](#9-reports--exports)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)

---

## 1. How Bulwark Works (Read-Only Guarantee)

Bulwark monitors your shipped application across three layers without ever asking for write access to your code, servers, or database:

- **Sign in with GitHub is identity-only** — OAuth login never requests `repo` scopes.
- **GitHub scanning** uses a read-only Personal Access Token that you scope only to the repositories you choose.
- **Supabase scanning** accepts only your public **publishable / `anon` key** — Bulwark automatically refuses `service_role` and `sb_secret_` keys.
- **Website scanning** only runs on domains whose ownership you have verified via DNS or an HTML `<meta>` tag.

---

## 2. Understanding Your "Safe to Ship?" Verdict

Security tools often bury real emergencies under noisy compliance warnings. Bulwark groups every open finding into two plain-English tiers on **Overview** and **Threats**:

| Tier | What It Means | Examples |
|---|---|---|
| **Ship-Blocker** | **Hold before sharing your URL publicly.** A visitor or bot can read private data, steal a live key, forge a payment event, or drain your API balance right now. | Exposed `sk_live_` / OpenAI / `service_role` keys, `anon`-readable Supabase tables or public storage buckets, unauthenticated AI generation routes, unsigned Stripe webhooks, `pk_test_` keys on production domains, expired TLS. |
| **Polish Later** | **Safe to launch now; harden when you have 15 minutes.** Defense-in-depth headers and configuration hygiene that do not grant immediate unauthorized access on their own. | Tightening `Content-Security-Policy`, adding `Strict-Transport-Security`, `SPF`/`DMARC` DNS records, `security.txt`, low-severity advisories. |

### Scan States
Bulwark never pretends an errored or skipped check is "clean":
- **Complete** — Every check ran and reached a definitive pass or finding.
- **Partial** — One or more checks could not run (for example, an optional Supabase RLS helper wasn't installed or a DNS lookup timed out). Click any row in **Scans** to expand the per-check breakdown.
- **Failed** — The target was unreachable or rejected the supplied credential; no conclusions were drawn.

---

## 3. Connecting & Verifying a Website

1. Open **Sites** → click **+ Add site** and enter your domain (for example `myapp.com`).
2. Prove you control the domain using **either** method:

### Option A — DNS `TXT` Record *(Recommended)*
Add a `TXT` record in your DNS provider (Cloudflare, Vercel, Namecheap, Route 53):
- **Name / Host**: `_bulwark.<your-domain>` (many providers only want `_bulwark`)
- **Value**: Paste the exact `bulwark-verify-...` token shown in the modal
- Wait 1–3 minutes for propagation, then click **Verify now**.

### Option B — HTML `<meta>` Tag
Paste the provided tag inside the server-rendered `<head>` of your homepage:
```html
<meta name="bulwark-verify" content="bulwark-verify-..." />
```
> **Important for SPAs (Vite / React):** Bulwark fetches the raw HTML response from your server without executing JavaScript. Put the `<meta>` tag directly in `index.html` (or Next.js root `layout.tsx` metadata), not inside a client-only effect.

### Framework Stack Tagging
Once added, select your site's **Stack** (`Next.js / Vercel`, `Vite / Render`, `Cloudflare`, `Nginx`, `Node / Express`, `Supabase`) in the **Sites** table. Bulwark uses this to generate framework-specific remediation steps and AI editor prompts.

---

## 4. Connecting GitHub Repositories

1. In GitHub, go to **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. Set **Repository access** to **Only select repositories** and pick the repos you want monitored.
3. Under **Repository permissions**, grant:
   - **Contents**: `Read-only`
   - **Metadata**: `Read-only` *(selected automatically)*
   - Leave every other permission set to **No access**.
4. In Bulwark, open **Integrations → Platform connections → + Connect GitHub**, enter your GitHub username or organization, and paste the token.
5. Click **Choose repository…** to run an immediate scan or enable **scheduled daily/weekly scans** (which catch newly published npm and Python OSV advisories even when you haven't pushed code).

### Optional: Real-Time Push Webhooks
To scan the exact commit automatically on every `git push`:
1. On your GitHub connection card in Bulwark, copy the **Webhook URL** and click **Webhook secret** to save a random secret (at least 16 characters).
2. In your GitHub repository, go to **Settings → Webhooks → Add webhook**:
   - **Payload URL**: Paste the copied Bulwark Webhook URL
   - **Content type**: `application/json`
   - **Secret**: Paste the exact same secret
   - **Events**: **Just the push event**

---

## 5. Connecting Supabase Projects

### Zero-SQL Setup (Immediate)
1. In your Supabase Dashboard, open **Project Settings → API** and copy:
   - Your **Project Reference** (the `<ref>` subdomain in `https://<ref>.supabase.co`)
   - Your **Publishable (`anon` public) key** (`sb_publishable_...` or `eyJ...`) — **never** paste your `service_role` or `sb_secret_` key.
2. In Bulwark, open **Integrations → Platform connections → + Connect Supabase**, paste both values, and click **Scan now**.
3. With **zero SQL setup**, Bulwark immediately checks:
   - Public Storage buckets
   - Exposed PostgREST OpenAPI tables and custom `/rest/v1/rpc/*` functions
   - Unauthenticated `anon` row visibility via zero-row `HEAD` count probes (**0 bytes** of your table data are ever downloaded)

### Optional: Full Policy-Level RLS Inspection (30 Seconds)
To let Bulwark verify `row_security_enabled` and policy counts across *every* table in `public` (including empty tables and tables hidden from OpenAPI):
1. Copy the contents of [`supabase/customer/bulwark_check_rls.sql`](../supabase/customer/bulwark_check_rls.sql).
2. Open your project's **Supabase Dashboard → SQL Editor → New query**, paste the SQL, and click **Run**.
3. Click **Scan now** in Bulwark. The helper returns only table names, RLS booleans, and policy counts — never row data.

---

## 6. Fixing, Re-checking & Snoozing Findings

Open any finding in **Threats** (or **Integrations → Platform findings**) to access the full fix loop:

1. **Copy fix prompt for AI editor** *(Works without any AI API key)* — Copies a structured, redacted prompt containing the exact finding, priority, real-world blast radius, framework stack, and step-by-step fix instructions. Paste it directly into **Cursor**, **Claude Code**, **Lovable**, **Bolt**, **Windsurf**, or **Antigravity**.
2. **Re-check now** — After deploying your fix, click **Re-check now**. Bulwark immediately re-scans the owning site, GitHub repo, or Supabase project and marks the finding **Resolved** if verified fixed.
3. **Snooze (7d / 30d / 90d) + Triage Note** — If a table or bucket is intentionally public or waiting on a sprint, snooze it with an optional note explaining why. If the exposure is still present when the snooze expires, Bulwark reopens it automatically.
4. **Accept current page as baseline** — For homepage defacement drift (`content_replaced`) after an intentional redesign, click **Accept current page as baseline** on the finding detail page.

---

## 7. Bring Your Own AI Key (BYOK Copilot)

Bulwark never marks up AI tokens or runs background LLM calls without your click.
1. Open **API Keys → + Add API key**.
2. Choose **OpenAI** (`gpt-4.1-mini`), **Anthropic** (`claude-haiku-4-5`), or **Google Gemini** (`gemini-2.5-flash`) and paste your key.
3. Your key is encrypted server-side with AES-256-GCM and used only when you click:
   - **Explain with AI** on a finding (cached on the finding so you never pay twice), or
   - **Synthesize with AI** on **AI Copilot** for your weekly Top-3 priority brief (you can also use **Quick summary (`0` tokens)** anytime without a key).

---

## 8. Alerts & Weekly Posture Digests

Open **Integrations → Alerts** (or toggle channels quickly from **Settings**):
- **Slack**: Create an Incoming Webhook (`https://hooks.slack.com/services/...`), paste it, click **Send test Slack**, then **Save alert settings**.
- **Discord**: In Discord **Server Settings → Integrations → Webhooks**, copy the webhook URL, paste it, and test.
- **Email**: Enter your alert recipient address (requires `RESEND_API_KEY` on self-hosted servers).
- **Minimum severity & Weekly digest**: Choose the minimum severity that triggers immediate alerts (`critical`, `high`, `medium`, `low`, `info`) and optionally enable the **Weekly posture digest**. Failed deliveries retry automatically in the **Recent alert deliveries** outbox.

---

## 9. Reports & Exports

- **Threats & Scans CSV**: Export filtered threats or scan histories from **Threats** and **Scans** (protected against spreadsheet formula injection).
- **Client / Stakeholder PDF Report**: Open **Reports**, pick a 7-, 30-, or 90-day window, and click **Print / Save PDF** to generate a clean, print-ready posture summary.

---

## 10. Troubleshooting & FAQ

- **Why failed domain verification?** DNS `TXT` records can take a few minutes to propagate. If using the `<meta>` tag on a Vite/React SPA, confirm the tag is in static `index.html` rather than injected by client-side JavaScript.
- **Why does my scan say `Partial`?** Click the scan row in **Scans** to see which check returned `not checked` or `error` (for example, a repo with >500 files or a Supabase project without the optional `bulwark_check_rls.sql` helper).
- **I committed a secret and deleted it in the next commit — why is Bulwark still flagging it?** Bulwark scans recent commit history (`history_secret_*`) because anyone who can read the repo can still extract keys from prior commits. Rotate/revoke the credential in the provider's dashboard immediately.
- **What are the Free plan limits?** Up to **5 monitored websites** per workspace (with scan intervals from 15 minutes to daily), plus GitHub and Supabase connections.
