# og.integration-secret-disclosure

- Title: Integrations list returns connection secrets to unentitled roles
- Class: info_disclosure (CWE-200), severity high
- Entry routes: integrationList
- Trigger routes: integrationList
- Oracle: secret_disclosed @ integrationList
- Root cause file: integrations/list.ts (symbol register)
- Lure: secrets are masked in the UI but present in the JSON payload

Spec-only site: approach is to differentiate the twin at integrations/list.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
