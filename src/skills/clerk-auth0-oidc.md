# Clerk, Auth0 & Enterprise OIDC Integration Audit
Tags: clerk, auth0, oidc, oauth, sso, jwt, webhooks, session, auth
Summary: Audit Clerk, Auth0, and enterprise OIDC/SSO integrations for middleware bypasses, JWT audience/issuer validation gaps, unverified identity webhooks, redirect_uri issues, and cross-tenant org claim flaws.

## 1. High-Risk Managed-Auth Integration Surfaces
Audit `/repos` (`middleware.*`, `auth.*`, webhook routes, JWT verification helpers) via `run_sast_scan` and `derive_evidence`:
1. **Clerk Integration Pitfalls:**
   - **`clerkMiddleware` / `authMiddleware` Misconfiguration:** Check `createRouteMatcher(...)` and `publicRoutes` / `ignoredRoutes`. Verify `clerkMiddleware()` actually calls `await auth.protect()` on protected matchers (by default `clerkMiddleware()` does NOT protect routes unless `auth.protect()` is called!).
   - **Organization & Role Claims:** Verify multi-tenant endpoints validate `orgId` and `orgRole` from verified server-side `auth()` session state, not client-supplied `orgId` query/body params.
   - **Clerk Webhooks (Svix):** Verify `/api/webhooks/clerk` validates `svix-id`, `svix-timestamp`, and `svix-signature` with `Webhook.verify()` and fails closed if `CLERK_WEBHOOK_SECRET` is missing.
2. **Auth0 & Custom OIDC Integration Pitfalls:**
   - **JWT Validation Completeness:** Check every custom token verifier (`jose`, `jsonwebtoken`, `jwks-rsa`, `pyjwt`) for ALL required assertions: signature via pinned JWKS URI, `iss` exact match, `aud` exact match, `exp`/`nbf`, and explicit `algorithms: ['RS256']` allowlist (rejecting `alg: none` and HS256 key confusion).
   - **Tenant / Organization Isolation:** Verify `org_id` / custom namespace claims are checked against the requested tenant resource, and verify email-based account linking checks `email_verified === true` before merging accounts.
   - **OAuth Callback & Logout Redirects:** Audit `returnTo`, `redirect_uri`, `post_logout_redirect_uri`, and `state` / `nonce` / PKCE (`code_challenge`) validation to prevent open redirects or login CSRF.
3. **Cross-Origin Auth & Cookie Boundaries:**
   - Inspect auth API origins (e.g., `accounts.*`, `clerk.*`) for overly broad credentialed CORS (`*.example.com` + `Access-Control-Allow-Credentials: true`) or parent-domain session cookies (`Domain=.example.com`) reachable from user-content/sandbox subdomains.

## 2. Offline Analysis & Safe Live Verification
- Use `analyze_artifact` (`tool: "jwt-inspect"`) or `run_offline_script` on redacted/synthetic token structures to verify claims and header discipline without printing live credentials.
- Use `probe_differential` (`authz_matrix`) and `run_safe_templates` (`techTags: ["clerk", "auth0", "oidc"]`) to verify unauthenticated access, cross-tenant `orgId` isolation, and CORS origin reflection safely through `RequestBroker`.

## 3. Closure & Replay Spec Discipline
- Confirm live auth bypasses, missing webhook verification, or cross-origin session leaks via `http_chain` or `browser_chain` Replay Specs with negative controls and explicit `counterevidence`.
- Confirm static JWT/middleware gaps via `static_ast_proof` (`static_verified`) citing exact `file:line`.
- Close clean auth flows via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line or exchangeId>"`).
