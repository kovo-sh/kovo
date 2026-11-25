# JWT & Session Token Security
Tags: jwt, session, cookies, auth, jwks, alg-none, kid
Summary: Inspect JWT headers/claims, signature verification discipline, cookie attributes, token leakage in URLs/logs/storage, and session isolation without exposing raw credentials.

## 1. Discovery & Offline Inspection
1. Never print or copy raw persona credentials. When a public/non-persona JWT or Supabase anon token appears in JS bundles, `Set-Cookie` metadata, or responses, inspect it offline with `analyze_artifact` (`tool: "jwt-inspect"`).
2. Inspect `/.well-known/jwks.json` and OpenID discovery metadata to identify signing algorithms (`RS256`, `ES256`, `HS256`) and key IDs (`kid`).
3. Check `browser_visit` (`domCheck: "client_storage"`) to see whether session tokens or refresh tokens are stored in `localStorage`/`sessionStorage` (amplifying any XSS to full account takeover) vs `HttpOnly` cookies.

## 2. High-Signal Checks
- **Algorithm Confusion & `alg: none` (Tier 1/2 Safe Differential):**
  - If an API accepts bearer JWTs, test a synthetic unsigned token (`{"alg":"none","typ":"JWT"}.{"sub":"kovo-probe","role":"user"}.`) against an authenticated endpoint vs a control invalid token (`Bearer invalid.token.sig`).
  - Only propose a finding if the unsigned token produces an authenticated `200` response (distinct from control `401`/`403` and distinct from SPA catch-all).
- **Privileged Claim / Service Role Exposure in Client Bundles:**
  - In Supabase/Firebase/JWT stacks, inspect JS-embedded JWTs with `jwt-inspect`. An `anon` role JWT is expected public client config (NOT a vulnerability by itself unless RLS is broken). A `service_role` or `admin` JWT embedded in client JS is **Critical**!
- **Cookie Security & Subdomain Scope:**
  - Audit all session/auth cookies for `Secure`, `HttpOnly`, `SameSite=Lax|Strict`, `__Host-` prefix, and overly broad `Domain=.example.com`.
  - Pair broad cookie `Domain=.example.com` with any dangling subdomain or XSS on a sibling subdomain to assess chain severity.
- **Token Leakage in Referer / URLs / Caches:**
  - Check whether auth tokens, magic links, or session IDs appear in URL query strings combined with permissive `Referrer-Policy` or missing `Cache-Control: no-store`.

## 3. Verification Rules
- Never hardcode raw `Authorization` or `Cookie` headers in a TypeScript `kovo_verify` script (the broker rejects raw secret injection; use opaque `as` / `persona` handles for legitimate authenticated controls, or sealed capability handles via `ctx.sealCapability` / `ctx.jwtSign`).
- For synthetic invalid/alg-none JWT probes, verify in a TypeScript `kovo_verify` script via `ctx.http(...)` or `ctx.proveAccessBoundary(...)` asserting control `401`/`403` vs. probe `200` with an authenticated JSON payload.
