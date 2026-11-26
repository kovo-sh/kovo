# Authentication, OAuth 2.0, OIDC & SSO Security
Tags: auth, oauth, oidc, sso, clerk, supabase, redirect_uri, state
Summary: Audit OAuth/OIDC authorization flows, redirect_uri validation, state/PKCE enforcement, account linking, magic links, and SaaS auth integrations (Clerk, Auth0, Supabase, NextAuth).

## 1. Auth Surface Mapping
1. Inspect `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, and login/callback routes harvested from JS bundles and `browser_visit` (`followRedirects: false` to observe every `Location` header and `Set-Cookie` flag).
2. Identify the auth stack (`@clerk/nextjs`, `next-auth`, `auth0`, `supabase`, custom OAuth) via headers (`x-clerk-auth-status`, `__session`, `__Host-next-auth.*`, `sb-*-auth-token`) and record as `kind: "auth"` + `kind: "tech_fingerprint"`.

## 2. High-Impact Auth Checks (Tier 1–2 Read-Only / Safe)
- **OAuth `redirect_uri` & Post-Login Open Redirect:**
  - Test login/callback parameters (`redirect_uri`, `redirect_url`, `next`, `returnTo`, `callbackUrl`, `continue`, `state`) with `followRedirects: false`.
  - Check bypass patterns using benign non-resolving/example domain (`https://example.invalid`):
    - Exact external URL: `https://example.invalid`
    - Protocol-relative: `//example.invalid`, `/\example.invalid`
    - Subdomain/prefix confusion: `https://approved-host.example.invalid`, `https://example.invalid?@approved-host`
  - **CRITICAL:** An open redirect on an OAuth authorization or token callback that forwards `code=` or `token=` is **High**; a plain unauthenticated redirect with no token leakage is **Medium/Low**.
- **Missing `state` / CSRF on OAuth Callback:** Inspect whether the authorization URL sets an HttpOnly bound state cookie and whether `/callback?code=invalid` rejects missing/mismatched `state` before calling the IdP.
- **Session Fixation / Cookie Scope:** Inspect `Set-Cookie` headers on auth transitions: check `HttpOnly`, `Secure`, `SameSite`, and overly broad `Domain=.root.tld` (which lets any compromised or dangling subdomain read/plant session cookies!).
- **Middleware Auth Bypass (Framework-Specific):** If Next.js or Edge middleware guards `/dashboard` or `/api/*`, check `cve-runtime-correlation` (e.g., `CVE-2025-29927` `x-middleware-subrequest`) and static-asset path normalization edge cases (`/_next/data/...`, trailing slashes, case sensitivity).
- **Tier 2 Multi-Persona Auth Checks:**
  - Verify logout/revocation invalidates server-side session or JWT (do not mutate operator personas unless Tier 3 approved).
  - Verify auth error responses do not leak session tokens, reset tokens, or cross-tenant metadata.

## 3. `kovo_verify` Verification Discipline
- Always pass `followRedirects: false` to `ctx.http(...)` when proving open redirect or auth bypass redirects.
- Compare a clean control (`next=/dashboard` or unauthenticated gated route returning `302`/`401`/`403`) against an external redirect probe (`https://example.invalid`) using `ctx.expect.status(probe, [301, 302, 303, 307, 308])` and `ctx.expect.header(probe, 'location', { matches: '^https://example\\.invalid(?:/|$)' })` (or `ctx.prove_access_boundary({ boundaryClass: 'auth', ... })` for auth bypasses), then `return ctx.result({ title })`.
