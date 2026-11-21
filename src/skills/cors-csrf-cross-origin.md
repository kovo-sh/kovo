# CORS, CSRF & Cross-Origin Data Leakage
Tags: cors, csrf, cross-origin, credentials, samesite, xssi
Summary: Distinguish real exploitable cross-origin credentialed data leaks from benign public CDN CORS headers using strict origin-reflection and credentialed differential tests.

## 1. High-Signal CORS Testing Matrix
Test API and authenticated endpoints (NOT public static assets/fonts/marketing pages!) with `request_http` varying the `Origin` header:
1. **Control (`control`):** `Origin: https://approved-target.com` (same-origin) or no `Origin` header.
2. **Arbitrary external origin (`probe`):** `Origin: https://attacker.example.invalid`
3. **Null origin (`probe`):** `Origin: null` (exploitable from sandboxed iframes)
4. **Prefix / suffix / subdomain regex bypasses:**
   - `Origin: https://approved-target.com.example.invalid`
   - `Origin: https://evil-approved-target.com`
   - `Origin: https://notapproved.approved-target.com` (check whether arbitrary subdomain + `ACAC: true` pairs with dangling subdomain or XSS!)
   - `Origin: http://approved-target.com` (downgrade to HTTP)

## 2. Exploitability Bar (Zero False Positives)
- `Access-Control-Allow-Origin: *` **WITHOUT** `Access-Control-Allow-Credentials: true` on a **public unauthenticated** endpoint is **NOT** a vulnerability (browsers forbid credentialed reads with `*`).
- **Confirmed High/Medium CORS Vulnerability requires ALL of:**
  1. `Access-Control-Allow-Origin` reflects an untrusted origin (`https://attacker.example.invalid` or `null` or bypass domain), AND
  2. `Access-Control-Allow-Credentials: true` is present, AND
  3. The endpoint actually serves **non-public / authenticated / user-specific** data (verify at Tier 2 with a persona, or prove cookie/session-gated JSON data; if public-only data at Tier 1, verify `Vary: Origin` and rate accurately as `medium` misconfiguration rather than High data theft).
- Also check `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` on `OPTIONS` preflight requests.

## 3. CSRF & Cross-Origin State Integrity
- Inspect state-changing endpoints discovered in JS/OpenAPI:
  - Do session cookies use `SameSite=None` without an anti-CSRF token or custom required header (`X-CSRF-Token`, `X-Requested-With`)?
  - Does the endpoint accept `text/plain` or `application/x-www-form-urlencoded` (bypassing CORS preflight) instead of strictly enforcing `application/json`?
- Never execute state-changing mutations at Tier 1/2; record structural CSRF evidence (`Set-Cookie` flags + missing `Origin`/`Referer`/CSRF token checks on safe `OPTIONS`/invalid-body probes) and request Tier 3 approval if active validation is warranted.

## 4. Replay Spec Assertions
- `kind: "http_chain"`: include `control` (benign origin or no origin) and `probe` (`Origin: https://attacker.example.invalid` or `null`).
- `assertionsJq` must check exact header equality `acao == "https://attacker.example.invalid"` AND `acac == "true"` AND response status `200` with non-HTML API body (not SPA catch-all).
