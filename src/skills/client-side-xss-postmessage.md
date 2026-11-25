# Client-Side XSS, DOM Sinks & postMessage Security
Tags: xss, dom-xss, postmessage, csp, browser, client-side, sandbox
Summary: Identify and deterministically verify reflected/DOM XSS, unsafe postMessage handlers, sandboxed iframe escapes, and CSP bypasses using Kovo Hunter’s broker-proxied Playwright browser.

## 1. Static Sink Discovery First
1. Use `analyze_artifact` (`tool: "js-harvest"`) and `derive_evidence` (`rg`) over harvested JS bundles to locate:
   - `addEventListener("message"`, `window.onmessage`, `postMessage(`
   - `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`
   - `eval(`, `new Function(`, `location.href =`, `location.assign(`, `window.open(`
   - URL/hash/query parameter flows (`URLSearchParams`, `window.location.search`, `window.location.hash`, `document.referrer`)
2. Inspect `Content-Security-Policy` headers: look for `unsafe-inline`, `unsafe-eval`, wildcard script hosts (`*.googleapis.com`, `cdn.jsdelivr.net`), missing `frame-ancestors`, or `report-only` mode.

## 2. postMessage Origin-Check Auditing
1. Call `browser_visit` with `domCheck: "postmessage"` on pages hosting interactive widgets, OAuth popups, embedded sandboxes (e.g., Sandpack/preview bundlers), or payment frames.
2. Inspect the registered `message` listener source from JS bundles:
   - Does the handler validate `event.origin` using an **exact allowlist** (`event.origin === "https://app.example.com"`)?
   - Common bypassable bugs:
     - No `event.origin` check at all
     - Substring / `indexOf` / `includes` / unanchored regex (`event.origin.includes("example.com")` → bypassed by `https://example.com.attacker.invalid`)
     - `event.origin.endsWith("example.com")` without leading dot (`https://evilexample.com`)
     - Passing `event.data` into `innerHTML`, `eval`, `location.href`, or returning sensitive tokens via `event.source.postMessage(secret, "*")`!
3. Record exact sink + missing origin validation as `kind: "dom"`.

## 3. Benign Non-Destructive DOM/Reflected XSS Verification
- Never inject destructive or external-exfil scripts (`fetch("https://evil...")`).
- Test reflection first via `request_http` with a unique inert marker (`kovo_xss_probe_9182`). Check exact HTML/JS/attribute context and whether `<`, `>`, `"`, `'`, `/` are unescaped.
- Verify execution deterministically using `browser_visit` (`domCheck: "dom_xss"`) or a TypeScript `kovo_verify` script that calls `ctx.browser(...)` on a clean control URL vs. a probe URL (benign DOM canary that sets a harmless `window.__kovo_dom_canary` or triggers an inert marker in the broker-proxied Playwright DOM—zero external network calls) and asserts execution with `ctx.assert.domSentinel(...)` on the probe while verifying absence on the control.

## 4. Sandboxed Preview / Bundler Isolation
- If the target runs user-code previews (e.g., Sandpack/iframe bundlers), verify:
  - Preview runs on a **distinct origin** (not the authenticated app origin or sibling subdomain sharing `Domain=.root.tld` cookies!).
  - Check `iframe` `sandbox` attribute (having BOTH `allow-scripts` AND `allow-same-origin` on a same-origin iframe negates sandboxing!).
