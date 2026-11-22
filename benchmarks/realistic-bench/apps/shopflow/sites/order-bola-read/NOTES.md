# order-bola-read

- Class: bola (CWE-639), severity high
- Root cause (planted at): `src/billing/order-access.ts`
- Entry routeKeys: getOrder
- Trigger routeKeys: getOrder
- Oracle attribution: kinds [cross_tenant_read] on [getOrder]

## Approach (spec only; not yet implemented)

Order detail read across stores — scopes the query by a store header that looks authoritative but is caller-supplied.
The twin pair registers the `billing/order-access.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
