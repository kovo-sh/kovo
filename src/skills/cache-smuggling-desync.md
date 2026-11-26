# Shared Cache Poisoning, Cache Deception & Request Desync Audit
Tags: cache, cache-poisoning, cache-deception, cache-smuggling, desync, request-smuggling, header-normalization, cdn, edge, verification
Summary: Audit shared caches and front-end/back-end parser differentials offline, then confirm poisoning or deception strictly through Kovo Hunter's cache-busted kovo_verify scripts (mandatory ?_gcb=) without ever poisoning a real user's cache entry.

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

## 3. Deterministic `kovo_verify` Confirmation
- Run a `kovo_verify` script (`ctx.http` + `ctx.expect`) with unique cache-busted paths (`?_gcb=<unique_control>` for clean baseline control vs `?_gcb=<unique_probe>` for poisoned/deception probe, followed by an unauthenticated readback on the probe cache-buster). Confirm via `ctx.expect.status` / `ctx.expect.header` / `ctx.expect.bodyContains` ONLY when the unauthenticated readback serves the attacker-influenced value/session artifact AND the control does not (verifying non-SPA HTML responses), then `return ctx.result({ title })`.
- For multi-hop cache-prime pivots feeding a downstream step, seal any leaked artifact with `ctx.seal_capability`, pass `entityId` + pre-prime `ablationExchangeIds`, and finalize with `ctx.prove_composite({ replayMode: "fresh_clean_replay", ... })`.
- Always include honest negative evidence: a CDN that keys on every forwarded header, a `Vary: *` response, or an origin that never emits cacheable responses closes the hypothesis cleanly via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line or exchangeId>"`).
