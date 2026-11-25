# Framework Audit: Next.js (App Router, Pages Router, Middleware & Server Actions)
Tags: framework, nextjs, react, server-actions, middleware, rsc, ssr, cache, authz
Summary: Audit Next.js App Router, Pages API, Server Actions, middleware matchers, image optimizer, and caching layers for auth bypasses, IDOR, SSRF, and data leakage using Kovo Hunter’s offline SAST and brokered verification.

## 1. High-Risk Next.js Surfaces
Map the repository (`/repos`) via `run_sast_scan` (`engines: ["opengrep", "ast-grep"]`) and `derive_evidence` before live probing:
1. **`middleware.ts` / `middleware.js` Matcher Gaps:** Inspect `export const config = { matcher: [...] }`. Check for excluded paths (`/api/*`, `/_next/data/*`, webhooks), prefix/regex bypasses, and whether handlers rely solely on middleware instead of enforcing defense-in-depth auth inside each route handler and Server Action.
2. **Server Actions (`"use server"`):** Every exported async function in a `"use server"` module is a directly reachable HTTP `POST` endpoint (`Next-Action` header). Verify every exported action enforces:
   - Session authentication (`getServerSession`, `auth()`, `getUser()`)
   - Object/tenant ownership on every ID argument (never trusting client-supplied `userId` or `orgId`)
   - Strict Zod/schema validation on all parameters (preventing mass assignment or unintended fields)
3. **App Router `route.ts` & Pages `pages/api/*`:** Check HTTP method exports (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`), missing auth on `DELETE`/`PATCH`, and service-role DB clients (`SUPABASE_SERVICE_ROLE_KEY`, Prisma without `where: { userId }`).
4. **RSC / `getServerSideProps` Prop Leakage:** Audit props passed from Server Components to Client Components (`"use client"`) and `/_next/data/<buildId>/*.json` responses for accidental serialization of PII, tokens, or internal admin fields.
5. **Next.js Image Optimizer & Rewrites (`next.config.*`):** Inspect `images.remotePatterns`, `images.domains`, `dangerouslyAllowSVG: true`, `rewrites()`, and `redirects()` for overly broad host wildcards (`hostname: '**'`) or open-redirect patterns.

## 2. Offline Static & AST Triage
- Run `run_sast_scan` with `opengrep` and `ast-grep` targeting `app/`, `pages/`, `middleware.*`, and `next.config.*`.
- Use `derive_evidence` to enumerate every `"use server"` file and every `route.ts` file, verifying an auth + ownership check exists on every code path.
- Check `package.json` / lockfiles via `query_cves` for known Next.js middleware/cache/RSC advisories (e.g., middleware subrequest header handling) — always treat version hits as `cve_hypothesis` until verified dynamically.

## 3. Safe Live Verification (`RequestBroker` & Surface Engine)
- Use `run_safe_templates` with `techTags: ["nextjs"]` and `probe_surface` (`mode: "paths"`, `wordlist: "nextjs-routes"`) to verify exposed routes with automatic SPA-catchall calibration.
- Use `probe_differential` (`probeClass: "authz_matrix"`) with `owner`, `other_persona`, `anonymous`, and safe middleware-header controls to verify route authz and middleware enforcement.
- Use `browser_visit` with `dom_xss_sink_hook` to inspect hydrated RSC payloads (`self.__next_f`) and client-side DOM sinks.

## 4. Closure & Replay Spec Discipline
- **Confirmed runtime gap:** Submit an `http_chain` Replay Spec with `spaCatchallControl: true`, an authenticated owner `control`, an unauthenticated/cross-tenant `probe`, and strict `assertionsJq` verifying non-error status (`requireControlNonError: true`).
- **Source-only confirmed gap:** Submit `static_ast_proof` (`static_verified` tier) citing exact `file:line`.
- **Ruled out:** Record `record_coverage` with `status: "ruled_out"` quoting the exact `file:line` of the enforced auth/ownership guard or negative-control `exchangeId`.
