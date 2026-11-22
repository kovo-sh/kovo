# og.account-bola-write

- Title: Account update writes across the team boundary
- Class: idor (CWE-639), severity high
- Entry routes: accountUpdate
- Trigger routes: accountUpdate
- Oracle: cross_tenant_write @ accountUpdate
- Root cause file: accounts/update.ts (symbol register)
- Lure: ownership is asserted from a request field rather than the loaded row

Spec-only site: approach is to differentiate the twin at accounts/update.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
