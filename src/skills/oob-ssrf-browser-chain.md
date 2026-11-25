# OOB Canary SSRF & Broker-Proxied Browser Chain Verification
Tags: ssrf, oob, canary, browser-chain, playwright, postmessage, cors, dom, redirects
Summary: Verify blind server-side outbound fetches using Kovo Hunter’s live OOB Canary Broker and validate multi-step client-side or cross-origin browser chains using Zero-LLM broker-proxied Playwright browser_chain Replay Specs.

## 1. Strict Defensive Boundaries
- **Zero internal network probing:** Never pass loopback (`127.0.0.1`, `::1`, `localhost`), RFC1918 private IPs, or cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`) in URL parameters or Replay Specs. Kovo Hunter's broker and schema strictly block them.
- **Zero weaponized payloads:** Never craft exploit shells, credential stealers, persistent defacement, or destructive actions. Prove reachability and policy gaps exclusively with benign signed Kovo Hunter canary tokens and non-destructive read-only checks.
- **100% broker-proxied browser:** `browser_visit` and `browser_chain` route every request through Kovo Hunter's RequestBroker and abort any unapproved third-party origin automatically.

## 2. Out-of-Band (OOB) Benign Canary Workflow (`mint_canary` / `check_canary`)
Use OOB canaries to prove blind server-side URL fetching (SSRF sinks, webhook test buttons, OpenGraph/link-preview fetchers, avatar/image importers, PDF/screenshot renderers, Server Actions calling `fetch(userUrl)`):
1. **Mint Benign Canaries:** Call `mint_canary({ purpose: "<short description>" })` to receive `{ token, httpUrl, dnsHost, listenerActive, synthetic }`.
   - Mint a separate token for the negative control and the probe whenever comparing behaviors.
   - Check `listenerActive`: when Kovo Hunter's OOB callback listener (or `KOVO_CANARY_PUBLIC_URL`) is active, `httpUrl` is a real reachable benign callback endpoint.
2. **Trigger & Observe:**
   - Submit `httpUrl` to the approved URL-fetching endpoint (respecting Tier 2/3 method rules and non-destructive payloads).
   - Call `check_canary({ token })` to inspect `{ found, hit, triggered, hits }`. Each hit records `{ method, path, query, remoteIp, userAgent, headers, receivedAt }` with sensitive headers redacted.
3. **Evaluate Security Controls:**
   - Does the server fetch arbitrary user-supplied URLs without an allowlist?
   - Does it follow HTTP redirects blindly, expose backend `User-Agent`/internal headers, or leak response bodies back to the caller?
   - Record concrete `endpoint` / `policy_gap` facts referencing the `exchangeId` and canary `token`.

## 3. Multi-Step Browser Chain Verification (`kind: "browser_chain"`)
Use `browser_chain` Replay Specs (Zero-LLM Playwright verification via `ScopedBrowser`) when a vulnerability requires real browser execution across 2–8 steps—for example:
- Cross-origin credentialed `fetch` (`credentials: "include"`) from an approved sibling/sandbox origin (e.g., `sandpack.*`) to a crown-jewel API/auth origin (`clerk.*`, `api.*`) reflecting permissive CORS.
- Cross-origin `postMessage` listener accepting messages from untrusted origins (`action: "postmessage_probe"`).
- Authenticated DOM/storage/XHR exposure or benign DOM reflection checks (`action: "dom_check"` with `checkKind: "dom_xss" | "postmessage" | "client_storage" | "xhr_leak"`).
- Browser-side redirect chains (`action: "redirect_observe"`).

### Exact `browser_chain` Replay Spec Schema
- Top-level fields:
  - `version: 1`, `kind: "browser_chain"`, `origin` (primary approved origin), `title`, `category`, `cwe`, `severity`, `severityRationale`, `impact`, `remediation`, `recheckInstructions`, `assertionsJq`
  - `spaCatchallControl?: boolean` (set `true` on SPA hosts to guard against catch-all HTML false positives)
  - `steps`: array of **2 to 8** `BrowserChainStep` objects, containing at least one `role: "control"` step and at least one `role: "probe"` step.
- Each `BrowserChainStep`:
  - `id`: short slug (`^[a-z0-9_-]{1,32}$`)
  - `role`: `"setup" | "control" | "probe" | "cleanup"`
  - `description`: concise explanation
  - `origin`: approved HTTPS origin
  - `pathAndQuery`: path starting with `/`
  - `persona?`: approved opaque persona handle
  - `action?`: `"navigate" | "dom_check" | "postmessage_probe" | "same_site_fetch" | "redirect_observe"`
  - `checkKind?`: `"dom_xss" | "postmessage" | "client_storage" | "xhr_leak"`
  - `selector?`: optional CSS selector to wait for/inspect
  - `fetchTarget?`: `{ origin, pathAndQuery, method?: "GET"|"HEAD"|"OPTIONS", credentials?: "include"|"same-origin"|"omit" }` (for `same_site_fetch` read-only CORS/session proof)
  - `postMessageOrigin?`, `postMessagePayload?` (benign canary string only), `waitAfterLoadMs?`
- `assertionsJq` runs over `/evidence/replay-results.json`:
  `{ kind, origin, replayedAt, canaryToken, steps, pages, consoleMessages, requests, domResults, control, probe, spaCatchall? }`
  and MUST output `{ "confirmed": boolean, "controlPassed": boolean, "observed": string, "expected": string }`.
