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

## 3. `kovo_verify` & Coverage Discipline
- For HTTP-reachable dangling CNAMEs returning an unclaimed provider fingerprint: confirm via `kovo_verify` (`ctx.http("/", { followRedirects: false })` + `ctx.expect.status` / `ctx.expect.bodyContains` + `ctx.result`) alongside the `inspect_dns` evidence.
- For pure DNS NXDOMAIN or TLS certificate/protocol defects observed via `inspect_dns` / `inspect_tls` / `analyze_artifact`: record structured facts (`record_fact`) and close coverage cleanly via `record_coverage`.
