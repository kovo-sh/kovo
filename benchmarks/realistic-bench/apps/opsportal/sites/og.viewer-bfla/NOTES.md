# og.viewer-bfla

- Title: Read-only auditor can perform an admin role change
- Class: bfla (CWE-285), severity high
- Entry routes: roleChange
- Trigger routes: roleChange
- Oracle: privilege_escalation @ roleChange
- Root cause file: users/role.ts (symbol register)
- Lure: endpoint checks authentication and a feature flag, but not the actor role

Spec-only site: approach is to differentiate the twin at users/role.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
