# og.flag-bola

- Title: Feature flag fetch leaks another team scoped flag value
- Class: bola (CWE-639), severity medium
- Entry routes: flagGet
- Trigger routes: flagGet
- Oracle: cross_tenant_read @ flagGet
- Root cause file: flags/scope.ts (symbol register)
- Lure: flag lookup keys by name only, ignoring the team scope column

Spec-only site: approach is to differentiate the twin at flags/scope.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
