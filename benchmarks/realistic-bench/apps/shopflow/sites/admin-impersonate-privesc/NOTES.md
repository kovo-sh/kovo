# admin-impersonate-privesc

- Class: bfla (CWE-269), severity critical
- Root cause (planted at): `src/identity/impersonation.ts`
- Entry routeKeys: adminImpersonate
- Trigger routeKeys: adminImpersonate
- Oracle attribution: kinds [privilege_escalation] on [adminImpersonate]

## Approach (spec only; not yet implemented)

Staff impersonation privilege escalation — guards the route by login but not by the staff role it assumes.
The twin pair registers the `identity/impersonation.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
