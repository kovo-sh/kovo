# og.webhook-ssrf

- Title: Saved webhook target fired by a later test-delivery reaches internal services
- Class: ssrf (CWE-918), severity high
- Entry routes: webhookCreate
- Trigger routes: webhookTest
- Oracle: ssrf_internal_fetch @ webhookTest
- Root cause file: integrations/webhook-test.ts (symbol register)
- Lure: create blocks obvious internal hosts; the test path re-parses the stored URL loosely

Spec-only site: approach is to differentiate the twin at integrations/webhook-test.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
