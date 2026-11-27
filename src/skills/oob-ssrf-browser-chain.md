# OOB Canary SSRF & Broker-Proxied Browser Chain Verification
Tags: ssrf, oob, canary, browser-chain, playwright, postmessage, cors, dom, redirects
Summary: Verify blind server-side outbound fetches using Kovo’s live OOB Canary Broker and validate multi-step client-side or cross-origin browser chains using kovo_verify (ctx.prove_oob_callback, ctx.browser, ctx.prove_composite).

## 1. Strict Defensive Boundaries
- **Zero internal network probing:** Never pass loopback (`127.0.0.1`, `::1`, `localhost`), RFC1918 private IPs, or cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`) in URL parameters or `kovo_verify` scripts. Kovo's broker and schema strictly block them.
- **Zero weaponized payloads:** Never craft exploit shells, credential stealers, persistent defacement, or destructive actions. Prove reachability and policy gaps exclusively with benign signed Kovo canary tokens and non-destructive read-only checks.
- **100% broker-proxied browser:** `browser_visit` and `ctx.browser` route every request through Kovo's RequestBroker and abort any unapproved third-party origin automatically.

## 2. Out-of-Band (OOB) Benign Canary Workflow (`mint_canary` / `check_canary`)
Use OOB canaries to prove blind server-side URL fetching (SSRF sinks, webhook test buttons, OpenGraph/link-preview fetchers, avatar/image importers, PDF/screenshot renderers, Server Actions calling `fetch(userUrl)`):
1. **Mint Benign Canaries:** Call `mint_canary({ purpose: "<short description>" })` to receive `{ token, httpUrl, dnsHost, listenerActive, synthetic }`.
   - Mint a separate token for the negative control and the probe whenever comparing behaviors.
   - Check `listenerActive`: when Kovo's OOB callback listener (or `KOVO_CANARY_PUBLIC_URL`) is active, `httpUrl` is a real reachable benign callback endpoint.
2. **Trigger & Observe:**
   - Submit `httpUrl` to the approved URL-fetching endpoint (respecting Tier 2/3 method rules and non-destructive payloads).
   - Call `check_canary({ token })` to inspect `{ found, hit, triggered, hits }`. Each hit records `{ method, path, query, remoteIp, userAgent, headers, receivedAt }` with sensitive headers redacted.
3. **Evaluate Security Controls:**
   - Does the server fetch arbitrary user-supplied URLs without an allowlist?
   - Does it follow HTTP redirects blindly, expose backend `User-Agent`/internal headers, or leak response bodies back to the caller?
   - Record concrete `endpoint` / `policy_gap` facts referencing the `exchangeId` and canary `token`.

## 3. `kovo_verify` OOB & Browser Verification
- **OOB SSRF Proof:** Call `ctx.prove_oob_callback({ inject: async (canary) => ctx.http('/api/fetch', { method: 'POST', as: 'actor_low', body: { url: canary.url } }), timeoutMs: 6000 })` and `return ctx.result({ title })`.
- **Browser / DOM / CORS / postMessage Proof:** Use `ctx.browser(target, { as?, waitForSelector?, timeoutMs? })` (paired with a clean control URL) and assert DOM execution or state with `ctx.expect.domSentinel(probeEx, sentinel, 'executed')`, `ctx.expect.css(...)`, or `ctx.expect.status(...)` + `ctx.expect.header(...)`, verifying non-SPA target responses before calling `return ctx.result({ title })`.
- **Multi-Hop Browser + API Pivot:** When a browser interaction or OOB callback yields a reusable token or triggers an internal hop, seal any extracted artifact with `ctx.seal_capability`, continue in the same `kovo_verify` script, and confirm the full DAG with `ctx.prove_composite({ replayMode: 'fresh_clean_replay', ... })` (`surface: 'browser'`).
