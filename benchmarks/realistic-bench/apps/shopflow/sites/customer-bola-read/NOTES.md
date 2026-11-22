# customer-bola-read

- Class: bola (CWE-639), severity medium
- Root cause (planted at): `src/crm/customer-access.ts`
- Entry routeKeys: getCustomer
- Trigger routeKeys: getCustomer
- Oracle attribution: kinds [cross_tenant_read] on [getCustomer]

## Approach (spec only; not yet implemented)

Customer record read across stores — filters the list endpoint by store but not the single-record endpoint.
The twin pair registers the `crm/customer-access.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
