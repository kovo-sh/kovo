# Modern SPA & JavaScript Bundle Reconnaissance
Tags: recon, spa, nextjs, vite, react, sourcemaps, js-harvest
Summary: Harvest hidden API routes, build manifests, source maps, client-side secrets, and framework fingerprints from modern React/Next.js/Vite SPAs without falling for 200 index.html catch-alls.

## 1. Initial Surface Capture
1. Fetch `/` with `request_http` (`GET /`, `followRedirects: false` first, then follow if redirected within scope).
2. Run `analyze_artifact` with `tool: "tech-fingerprint"` on the root headers + body, and `tool: "js-harvest"` on the HTML body.
3. Also fetch lightweight metadata endpoints (Tier 1 read-only):
   - `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/manifest.json`
   - Next.js manifests if Next.js detected: `/_next/static/<buildId>/_buildManifest.js`, `/_next/static/<buildId>/_ssgManifest.js`, and `__NEXT_DATA__` `runtimeConfig`/`props`.
   - Vite markers: check if `/@vite/client` or `/@fs/` responds (dev server accidentally exposed).

## 2. Deep JS Chunk & Source-Map Harvesting
1. Pull the top 5–12 high-signal application chunks (`_app-*.js`, `main-*.js`, `webpack-*.js`, `layout-*.js`, `page-*.js`, route chunks) via `request_http`. Skip third-party analytics/vendor chunks.
2. Run `analyze_artifact` (`tool: "js-harvest"` and `tool: "secret-scan"`) on each staged exchange file.
3. For every `sourceMappingURL` discovered, test whether `<chunk>.map` is publicly served (200 + `application/json` containing `"sources"` and `"mappings"`). Public production source maps often expose server action signatures, internal API paths, admin routes, and business logic.
4. Use `derive_evidence` with `rg` over `/evidence/exchanges/` to extract:
   - `fetch(`, `axios`, `trpc`, `graphql`, `/api/v`, `/internal`, `/admin`, `/webhook`, `/upload`
   - Hardcoded subdomains or external API origins → report unapproved subdomains via `suggest_candidate_host` (never probe unapproved hosts).
   - `window.addEventListener("message"`, `postMessage`, `dangerouslySetInnerHTML`, `NEXT_PUBLIC_*`, `VITE_*` env vars.

## 3. Live Rendered Inspection
- Call `browser_visit` on the root and key SPA routes to capture dynamically fetched XHR/API endpoints, client-side route transitions, console errors, and `postMessage` listeners that static bundle parsing misses.

## 4. SPA Catch-All Defense (Critical)
- Single-page apps return `200 OK` with `text/html` (`index.html`) for unknown paths.
- Before recording any discovered path as a real endpoint, compare it against a guaranteed nonexistent path `/.guardian-nonexistent-check` using `analyze_artifact` (`tool: "diff-response"`). If `likelySpaCatchall: true`, it is NOT a real backend route.

## 5. Recording & Escalation
- Record discovered API routes (`kind: "endpoint"`), stack fingerprints (`kind: "tech_fingerprint"`), leaked non-public keys (`kind: "secret"`), and DOM sinks (`kind: "dom"`).
- Immediately call `query_cves` for any detected framework/version (`next`, `react`, `vite`, etc.).
- Hand off high-signal API routes, auth endpoints, and upload handlers via `record_fact` so the Coordinator Planner dispatches targeted follow-up chains.
