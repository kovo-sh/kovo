# SSRF Controls, Redirect Validation & Benign Canary Verification
Tags: ssrf, redirects, canary, oast, url-validation, webhooks
Summary: Evaluate URL-fetching parameters, webhook/preview endpoints, and HTTP redirects using Kovo Hunter’s signed benign canaries and strict negative controls without targeting internal networks.

## 1. Surface Identification
1. Search JS bundles, OpenAPI specs, and synced routes for parameters that accept URLs, hostnames, or callback targets (`url`, `target`, `webhook`, `callback`, `redirect`, `next`, `returnTo`, `imageUrl`, `avatarUrl`, `proxy`, `importUrl`).
2. Record candidate endpoints as `kind: "endpoint"` with parameter names and observed validation behavior.

## 2. Open Redirect Verification (Tier 1 Read-Only)
1. Always set `followRedirects: false` on `request_http` when auditing redirect parameters.
2. Run a paired control-vs-probe test:
   - **Control:** Valid same-origin path (e.g., `?next=/dashboard`) to confirm baseline redirect behavior.
   - **Probe:** Benign non-routable external domain (`https://example.invalid`) and protocol-relative variants (`//example.invalid`).
3. Confirm only when the HTTP status is `3xx` AND the parsed `Location` header targets the external origin itself (not merely echoed inside a same-origin query parameter).

## 3. Benign Canary Verification for Server-Side URL Fetchers
1. **Strict Defensive Boundary:** Never supply loopback addresses, RFC1918 private IPs, or cloud metadata hostnames in probe inputs. Kovo Hunter’s schema and broker enforce a strict denylist against internal/metadata targets.
2. When an endpoint legitimately fetches user-supplied external URLs (link previews, webhooks, PDF/image fetchers, Server Actions):
   - Mint two single-use benign tokens via `mint_canary`: one for the control check and one for the probe check.
   - If `KOVO_CANARY_BASE_URL` (or a local lab listener) is active, supply the benign canary URL as the external URL input (subject to Tier 2/3 method rules) and call `check_canary` to observe whether the server initiated an outbound fetch, along with its `User-Agent` and timing.
   - Verify whether the server enforces protocol allowlists (`https:` only), blocks redirects to internal hosts, and validates response `Content-Type` and size limits.

## 4. Replay Spec Standards
- For open redirects: `kind: "http_chain"` with `followRedirects: false` on both `control` and `probe`, asserting exact `Location` host match in `assertionsJq`.
- For server-side fetch / blind callback findings: require both a clean `control` step and a benign Kovo Hunter canary verification proving outbound request initiation without touching private infrastructure.
