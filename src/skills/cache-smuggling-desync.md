# Shared Cache Poisoning, Cache Deception & Request Desync Audit
Tags: cache, cache-poisoning, cache-deception, cache-smuggling, desync, request-smuggling, header-normalization, cdn, edge, verification
Summary: Audit shared caches and front-end/back-end parser differentials offline, then confirm poisoning or deception strictly through Kovo Hunter's cache-busted cache_differential Replay Spec (mandatory ?_gcb=) without ever poisoning a real user's cache entry.

## 1. Cache Key & Normalization Recon (`probe_differential`, `analyze_artifact`)
Start by understanding what the edge treats as the cache key versus what the origin treats as request identity:
1. **Unkeyed Input Harvesting:** Compare two clean requests that differ only in one header (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `X-Host`, `X-Forwarded-Port`, `X-HTTP-Method-Override`) and diff response bodies, `Location`, and `Content-Type`. A header that changes the origin response while leaving the cached object shared is an unkeyed-input poisoning candidate.
2. **Key Normalization Gaps:** Test whether the edge decodes and re-encodes the path differently from the origin: `%2e%2e`, `%2f`, `;` matrix params, trailing `/`, duplicate slashes, `?` in path segments, and case folding (`/Admin` vs `/admin`). Divergence between "is this cached?" and "what does the origin serve?" is the deception primitive.
3. **Cache Deception Candidates:** Static-ish suffixes on dynamic, authenticated routes (`/account/profile.css`, `/api/me.js`, `/invoice/1/bundle.woff2`, `/orders/list/logo.svg`) where the origin still renders private data. Confirm with two personas: if Persona B's request returns Persona A's authenticated body, that is cache deception.
4. **Desync Preconditions:** Mixed `Content-Length` + `Transfer-Encoding: chunked` handling, HTTP/2 downgrade paths, and hop-by-hop header forwarding (`Connection`, `TE`, `Upgrade`, `Keep-Alive`). Treat any successful desync attempt as out of scope for active testing unless the operator supplies a dedicated disposable lab - never attempt cross-user queue poisoning on production.

## 2. Safe Verification With `probe_differential`
- Use `probe_differential` with `probeClass: "cache_poison_deception"`; Kovo Hunter requires explicit cache-buster tokens and refuses requests that could evict or replace a live cache entry.
- Always run a clean baseline/control first; the probe is only meaningful if the control is served from the origin with `cache-control: no-store` or a distinct cache key.
- Record every observation as a fact with the exact `cache-control`, `age`, `vary`, `x-cache`, `cf-cache-status`, and `content-type` values, plus the full `?_gcb=` token used. Never record raw poisoned markup containing secrets.

## 3. Deterministic Zero-LLM Confirmation (`cache_differential`)
- Submit a `cache_differential` Declarative Replay Spec with `mode: "poison"` or `"deception"`, `controlPath` carrying `{{control_gcb}}`, `probePath` carrying `{{probe_gcb}}`, and optional `verifyPath`. Kovo Hunter mints fresh cache-buster tokens, executes control -> probe -> verify, and confirms only when the probe response is served from cache with the attacker-influenced value AND the control is not.
- `spaCatchallControl: true` must be set when the target returns a 200-OK SPA shell for unknown paths, otherwise the verifier will correctly dismiss the finding as a catch-all artifact.
- For header misconfiguration-only observations (CORS/CSP/HSTS/frame protection), use `http_chain` with an explicit cross-origin control/probe pair; do not claim cache poisoning from headers alone.
- Always include non-empty `counterevidence`: a CDN that keys on every forwarded header, a `Vary: *` response, or an origin that never emits cacheable responses closes the hypothesis cleanly via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line or exchangeId>"`).
