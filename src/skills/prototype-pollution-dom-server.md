# Prototype Pollution Audit (Client-Side DOM & Server-Side Node.js)
Tags: prototype-pollution, javascript, typescript, node, dom, merge, lodash, qs, xss
Summary: Audit client-side and server-side JavaScript/TypeScript code for unsafe recursive object merges, dotted-path setters, and query-string parsers that permit prototype property tampering.

## 1. Root Cause & High-Risk Sinks
Prototype pollution arises when untrusted keys (`__proto__`, `constructor`, `prototype`) are copied recursively onto plain objects without filtering dangerous keys or using `Object.create(null)` / `Map`.

Audit `/repos` via `run_sast_scan` (`opengrep`, `ast-grep`) and `derive_evidence`:
1. **Custom Deep Merge / Deep Clone / Path Setters:**
   - Search for recursive `merge(target, source)`, `extend(a, b)`, `setByPath(obj, path, val)`, or `obj[key] = value` loops where keys come from `req.body`, `req.query`, `JSON.parse`, `URLSearchParams`, or `location.hash`.
2. **Vulnerable Dependency Versions:**
   - Run `query_cves` against `package.json` / lockfiles for historical prototype-pollution advisories in query parsers, deep-merge libraries, template engines, or config utilities (treat version matches as `cve_hypothesis` until reachable sink is confirmed).
3. **Client-Side Gadgets (`browser_visit`):**
   - Look for query/hash parsers (`qs`, custom `parseQuery`) feeding into DOM libraries, `innerHTML`, script URLs, `fetch` headers, or third-party analytics/widget configs.
4. **Server-Side Impact Analysis (Node.js):**
   - Check whether polluted `Object.prototype` properties could affect auth checks (`if (user.isAdmin)` when `isAdmin` is undefined on regular users), template options, CORS options, or response status/header defaults.

## 2. Strictly Safe Verification Standards
- **Never pollute shared persistent global server state on public targets!** Server-side prototype pollution should be audited statically in `/repos` first, and verified dynamically ONLY in isolated `local-lab` environments or via strictly non-destructive, non-persistent read-only marker checks approved at Tier 3.
- **Client-Side DOM Verification:** Use Kovo’s broker-proxied `browser_visit` with `dom_xss_sink_hook` and a benign non-destructive marker query parameter (comparing clean baseline control vs canary parameter) to detect whether a client-side parser mutates a harmless custom test property or reaches a DOM sink.
- **Offline Proof via `run_offline_script`:** When source code is mounted, validate the exact merge/setter function behavior offline inside the air-gapped `--network none` Node runtime on isolated synthetic inputs.

## 3. Closure & `kovo_verify` Discipline
- Confirm client-side DOM impact via `kovo_verify` using `ctx.browser(target, { as? })` + `ctx.expect.domSentinel(probeEx, sentinel, "executed")` (comparing a clean control URL vs probe URL) + `return ctx.result({ title })`.
- Confirm server-side source sinks via `static_ast_proof` (`static_verified`) citing the exact merge/setter `file:line`, plus concrete `counterevidence` analyzing whether `JSON.parse` / `Object.hasOwn` / schema validation blocks dangerous keys upstream.
- Close safe implementations via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
