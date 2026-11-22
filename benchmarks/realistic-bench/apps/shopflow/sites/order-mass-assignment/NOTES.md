# order-mass-assignment

- Class: mass_assignment (CWE-915), severity high
- Root cause (planted at): `src/billing/order-update.ts`
- Entry routeKeys: updateOrder
- Trigger routeKeys: updateOrder
- Oracle attribution: kinds [mass_assignment] on [updateOrder]

## Approach (spec only; not yet implemented)

Order update mass assignment — whitelists note and tags but spreads the rest of the body into the row.
The twin pair registers the `billing/order-update.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
