I reviewed the scanner and worker code. This is a \*\*source-level critique, not a live penetration test\*\*. My main conclusion: Bulwark has a useful start for \*\*external website posture monitoring\*\*, but it currently risks presenting uncertain observations as definitive security findingsâ€”and in one case may incorrectly close real findings. Iâ€™d address reliability and safety before adding more checks or AI.



\## Highest-priority issues



\### 1. A failed scan can automatically resolve real findings



The worker treats any previously open finding not seen in the latest result as resolved. But many checks quietly return no findings when a request fails, times out, or returns an unexpected response. A temporary outage can therefore look like â€œthe issue is fixed.â€ Worse, a failed homepage scan only reports `site\_unreachable`, after which other open findings are absent and can be marked resolved.



Thatâ€™s a trust-breaking failure mode: the dashboard can look healthier precisely because the scanner couldnâ€™t check the site. \*\*Do not infer remediation from a missing result unless that check completed successfully.\*\* Store an outcome per checkâ€”such as `pass`, `finding`, or `error`â€”and only auto-resolve after a successful, sufficiently repeated clean result.  

\[Worker finding reconciliation](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/worker.mjs#L26-L87) Â· \[Unreachable-site path](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L918-L935)



\### 2. Scanning creates an outbound-request safety risk



The scanner follows redirects and makes requests to paths and script URLs on a site. Domain ownership verification is valuable, but it does not make every later destination safe: redirects or changing DNS can point requests somewhere other than the verified public site. That creates a \*\*server-side request forgery (SSRF) and network-boundary risk\*\* for the service running Bulwark.



Before expanding scans, enforce outbound network protections: reject loopback, private, link-local, and reserved IP ranges for both IPv4 and IPv6; validate every redirect and DNS resolution; cap redirects; and add network-level egress rules. Apply the same controls to verification and all optional lookups.  

\[Redirect-following fetch helper](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L194-L207) Â· \[Script URL collection and fetching](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L607-L670) Â· \[Ownership verification fetch](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/verify.mjs#L23-L36)



\### 3. Fetch timeouts donâ€™t cover reading response bodies



`fetchWithTimeout` clears its timer once `fetch()` returns the response headers. Several callers then read the body afterward. So the timeout may protect connection setup, but not a slow or endless response body. Thereâ€™s also no consistent response-size cap: the homepage, probe responses, and scripts can consume substantial memory.



Use a single deadline that covers the \*entire\* operation, including body consumption, and enforce byte limits while streaming. Give each check an explicit maximum response size and concurrency budget.  

\[Timeout helper](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L194-L207) Â· \[Homepage body read](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L209-L218) Â· \[Exposed-file body reads](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L255-L273)



\### 4. Overlapping scans can race



A manual scan runs directly in the API, while the worker independently starts due scans on an interval. Thereâ€™s no visible claim/lock preventing the same site from being scanned concurrently. The workerâ€™s `setInterval` can also start another tick while a slow prior tick is still running. Concurrent runs can produce duplicate scan records, competing finding updates, and confusing results.



Add per-site scan claims or a queue with idempotency, and ensure the worker never starts a second tick before the first finishes. Put manual scans through the same controlled path, with per-user and per-site rate limits.  

\[Manual scan endpoint](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/api.mjs#L153-L165) Â· \[Worker scheduling loop](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/worker.mjs#L128-L190)



\## Where the findings can mislead users



\### 5. The scanner is mostly checking a homepage, not the application



Most checks inspect `https://domain/`; secret scanning samples the homepage and up to six same-host JavaScript files. That can catch some useful problems, but it wonâ€™t represent an app with multiple routes, API endpoints, admin areas, or authenticated functionality. The current product should be described as \*\*external posture monitoring\*\*, not a comprehensive vulnerability assessment.



A stronger roadmap is a safe, explicitly scoped crawl of public pages and assets, followed by opt-in integrations for code, dependency, and configuration findings. Keep authenticated testing out of scope unless you build a clear authorization model and safe test mode.



\### 6. Several checks need better context and confidence



\- \*\*CORS:\*\* reflecting an `Origin` is not, by itself, proof that private data is exposed. The check should account for credential support and the sensitivity of the affected response before assigning meaningful severity.  

&#x20; \[CORS checks](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L338-L386)



\- \*\*Cookie flags:\*\* checking whether the raw `Set-Cookie` string contains words like `secure` or `samesite` can confuse cookie values with actual attributes. Parse cookie attributes structurally; assess session cookies separately from harmless preference cookies.  

&#x20; \[Cookie checks](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L388-L415)



\- \*\*Missing headers:\*\* a missing CSP or HSTS header can be worth reporting, but impact depends on the site and deployment. Treat these as configuration guidance with context, not automatic evidence of a concrete exploit.



\- \*\*`robots.txt`, sitemap, and `security.txt`:\*\* missing these is often normal and should not compete with actual exposures or compromise indicators in the main threat queue.  

&#x20; \[Discovery checks](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L460-L545)



Give every finding a confidence level, the exact observation, what it does \*not\* prove, and a prioritized remediation. Make severity reflect impact and evidenceâ€”not just the checkâ€™s fixed default.



\### 7. â€œChecks passedâ€ is not a reliable measure



`checksPassed` is calculated as `checksTotal - number of findings`. But findings are not a one-to-one representation of checks: a check may produce multiple findings, some checks may be skipped or fail silently, and some findings are informational. That makes the scan summary potentially misleading.



Persist a result for each check, including skipped and errored checks, and calculate completion from those results.  

\[Check counting and result calculation](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L895-L916) Â· \[Final result](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/checks.mjs#L1005-L1027)



\### 8. Finding identity and lifecycle are too coarse



Findings are reconciled by `check\_key` alone. That can merge distinct affected resources into one findingâ€”for example, more than one exposed pathâ€”and existing rows are mainly â€œtouchedâ€ by updating `last\_seen\_at`, not their evidence or severity. Ignored findings are also permanently suppressed by key, even if the underlying issue later changes.



Use a stable identity that includes the affected resource where appropriate. Update evidence, severity, and metadata on recurrence; preserve status history; and let users mute a finding with an optional expiry or scope rather than hiding that check forever.  

\[Finding matching and updates](https://github.com/Astraa14/bulwark/blob/c3168fc4041f4731cf1b1b31a5553a93564f9e2f/server/worker.mjs#L26-L87)



\## Make it more intelligentâ€”without pretending AI is the scanner



Today the AI is an \*\*explanation layer\*\*, not the detection engine: deterministic checks produce the finding, then the model explains it. Thatâ€™s a sensible boundary. Keep detection evidence-based and reproducible. Improve the explanation layer by marking scan evidence as untrusted input, requiring the model to stay grounded in the observed facts, and presenting the output as adviceâ€”not verification.



The strongest â€œintelligenceâ€ improvements are likely to come first from \*\*better check outcomes, deduplication, confidence, asset context, and useful remediation\*\*, not from adding a model to decide whether something is vulnerable.



\## Suggested order of work



1\. \*\*Prevent unsafe outbound requests and bound every fetch.\*\*

2\. \*\*Represent per-check pass/fail/error; never resolve findings on scan failure.\*\*

3\. \*\*Prevent overlapping and unbounded scans.\*\*

4\. \*\*Fix noisy or overconfident checksâ€”especially CORS, cookies, and informational discovery checks.\*\*

5\. \*\*Improve finding identity, evidence updates, and mute/reopen lifecycle.\*\*

6\. \*\*Add fixture-based tests for clean sites, vulnerable examples, transient failures, redirects, oversized bodies, and changed evidence.\*\*

7\. Then expand coverage in a clearly stated product scope.



The most important product principle: \*\*when Bulwark canâ€™t verify a check, it should say â€œnot checked,â€ never imply â€œsecure.â€\*\*

