# Cross-Host & Multi-Origin Vulnerability Chaining
Tags: cross-host, chaining, cors, subdomain, oauth, postmessage, sandbox, cookie-scope, dangling-cname
Summary: Combine individually medium/low primitives discovered across two or more distinct approved origins into high-impact verified cross-origin security chains.

## 1. Why Cross-Host Synthesis Matters
Single-host investigations often stop at isolated observations ("wildcard subdomain CORS", "sandbox renders user JS", "dangling CNAME on old subdomain", "open redirect on docs host"). High-impact findings frequently emerge when primitives across **two or more distinct origins** connect across a shared trust boundary (registrable domain, SSO/OAuth provider, shared cookies, or leaked tokens).

## 2. High-Value Cross-Host Chain Archetypes
Evaluate every pair of approved origins `(Origin A, Origin B)` against these defensive chain patterns:

1. **Permissive Subdomain Credentialed CORS + User-Controlled Execution / Sandbox Origin:**
   - **Primitive A (Crown Jewel):** Auth, account, or API host (`clerk.*`, `accounts.*`, `api.*`) reflects `Access-Control-Allow-Origin: https://<any-subdomain>.example.com` WITH `Access-Control-Allow-Credentials: true` (or accepts `Origin: null`).
   - **Primitive B (Execution / UGC / Sandbox Host):** Another subdomain (`sandpack.*`, `preview.*`, `bundler.*`, or a host with DOM XSS / untrusted HTML upload) allows untrusted scripts or user-authored code to execute in that subdomain's origin.
   - **Verification:** Confirm Origin A returns authenticated/session data with `ACAO: <Origin B>` and `ACAC: true`, AND confirm Origin B is a trusted sibling origin capable of executing untrusted script/frames. Verify via `kovo_verify` (`ctx.http` / `ctx.browser` + `ctx.expect` and `ctx.seal_capability` + `ctx.prove_composite` with strictly benign read-only markers—never exfiltrate real credentials).

2. **Wildcard Trust / Cookie Domain (`Domain=.example.com`) + Dangling CNAME / Subdomain Takeover:**
   - **Primitive A:** Crown-jewel host sets session/CSRF cookies scoped to parent domain (`Domain=.example.com`), trusts `*.example.com` in CORS, or allows `*.example.com` in OAuth `redirect_uri` / `postMessage` origin checks.
   - **Primitive B:** Sibling subdomain has an unclaimed third-party CNAME (NXDOMAIN / provider unclaimed fingerprint).
   - **Impact Elevation:** An unclaimed subdomain elevates from informational/medium brand risk to High/Critical session fixation, credentialed CORS read, or OAuth token interception.

3. **OAuth / SSO Redirect Allowlist + Open Redirect or Unmaintained Sibling Host:**
   - **Primitive A:** Auth/OIDC host validates `redirect_uri` / `returnTo` loosely (prefix match, wildcard subdomain, or open path traversal on an allowed sibling host).
   - **Primitive B:** An allowed sibling origin has a confirmed open redirect (`Location: https://example.invalid`) or client-side redirect.
   - **Verification:** Chain the paired `followRedirects: false` checks across Origin A and Origin B using benign `https://example.invalid` targets only.

4. **Cross-Origin Token / Secret Leakage:**
   - **Primitive A:** Staging, docs, preview, or client JS bundle on Host A exposes an internal API key, service token, GraphQL introspection schema, or private endpoint URL.
   - **Primitive B:** Privileged API/admin/billing service on Host B accepts that token or exposes the referenced route without independent authorization.
   - **Verification:** Always verify with a strictly read-only negative-control vs positive-probe check (redacted by Kovo's broker—never print raw secrets).

5. **Cross-Origin `postMessage` & Iframe Trust Mismatch:**
   - **Primitive A:** Host A embeds Host B (or vice versa) and exchanges sensitive state/tokens via `postMessage` with `targetOrigin: '*'` or weak `event.origin.includes(...)` / missing `event.origin` checks.
   - **Verification:** Use `browser_visit` (`domCheck: 'postmessage'`) for discovery and verify via `kovo_verify` (`ctx.browser` + `ctx.expect.domSentinel` / `ctx.prove_composite`) with benign canary strings to prove cross-origin message acceptance without destructive payloads.

## 3. Quality Bar & Zero False Positives
- Every cross-host hypothesis MUST cite concrete recorded `factIds` from **>= 2 distinct approved origins** (or 1 origin + a shared parent-domain trust boundary).
- Do NOT chain benign public `Access-Control-Allow-Origin: *` (without `ACAC: true`) on static assets, or routine missing security headers (HSTS/Referrer-Policy/X-Content-Type-Options).
- Focus cross-host chains on at least one `crown_jewel` origin (auth, billing, API, LLM proxy, uploads, admin, sandbox).
- Never reference unapproved origins in `chainSteps` or `kovo_verify` scripts.
