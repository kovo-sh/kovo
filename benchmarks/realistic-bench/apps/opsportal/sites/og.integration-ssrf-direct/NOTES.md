# og.integration-ssrf-direct

- Title: Integration fetch pulls a connector url straight to internal services
- Class: ssrf (CWE-918), severity high
- Entry routes: integrationFetch
- Trigger routes: integrationFetch
- Oracle: ssrf_internal_fetch @ integrationFetch
- Root cause file: integrations/fetch.ts (symbol register)
- Lure: url is restricted to http scheme but not to an external host allowlist

Spec-only site: approach is to differentiate the twin at integrations/fetch.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
