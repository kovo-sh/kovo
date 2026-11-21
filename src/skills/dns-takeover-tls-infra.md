# DNS Subdomain Takeover, TLS Hygiene & Infrastructure Audit
Tags: dns, takeover, cname, tls, certificates, hsts, infrastructure
Summary: Deterministically verify dangling CNAME subdomain takeover risks, expired/mismatched TLS certificates, weak transport protocols, and infrastructure exposure.

## 1. Live DNS & Dangling-CNAME Audit (Tier 1 Read-Only)
1. Call `inspect_dns` on every approved host (especially legacy, marketing, docs, staging, preview, status, and third-party SaaS subdomains).
2. Inspect returned `CNAME`, `A`, `AAAA`, `TXT`, and `NS` records:
   - Flag any `CNAME` pointing to external cloud/SaaS providers (`github.io`, `vercel-dns.com`, `netlify.app`, `s3.amazonaws.com`, `cloudfront.net`, `herokuapp.com`, `fastly.net`, `fly.dev`, `pages.dev`, `azurewebsites.net`, `onrender.com`, `up.railway.app`, `webflow.io`, `myshopify.com`, `ghost.io`).
   - Run `request_http` (`GET /`, `followRedirects: false`) on the host and pass DNS + HTTP response data into `analyze_artifact` (`tool: "dns-takeover"`).
3. **Zero-False-Positive Standard for Subdomain Takeover:**
   - A third-party `CNAME` alone is NOT a vulnerability.
   - Confirmation requires BOTH an external cloud `CNAME` AND either (a) an unclaimed-resource provider fingerprint in the HTTP response body (e.g., `NoSuchBucket`, `There isn't a GitHub Pages site here`, `DEPLOYMENT_NOT_FOUND`, `Fastly error: unknown domain`) OR (b) `NXDOMAIN` / dangling target with zero A/AAAA records on a claimable provider.
   - Check whether the root domain sets wildcard session cookies (`Domain=.root.tld`) — if so, note the elevated session-impact context!

## 2. Direct-IP TLS & Transport Audit
1. Call `inspect_tls` on approved hosts to inspect:
   - Protocol version (flag TLS 1.0 / TLS 1.1; confirm TLS 1.2 / TLS 1.3).
   - Certificate validity (`authorized`, expiration date `validTo` — flag expired or expiring within 14 days).
   - Subject Alternative Names (`SANs`) matching the requested hostname (also check SANs for unexpected internal/staging hostnames and report new in-scope candidates via `suggest_candidate_host`).
2. Inspect `Strict-Transport-Security` header (`max-age >= 31536000`, `includeSubDomains`).

## 3. Declarative Replay Specs
- For dangling CNAMEs: submit `kind: "dns_takeover"` with `targetOrigin`, `probePath: "/"`, and `assertionsJq` checking both CNAME provider match AND unclaimed body signature / NXDOMAIN.
- For TLS defects: submit `kind: "tls_audit"` with `targetOrigin` and `assertionsJq` asserting the exact certificate/protocol violation.
