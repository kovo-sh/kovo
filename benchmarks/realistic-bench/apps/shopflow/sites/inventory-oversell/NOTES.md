# inventory-oversell

- Class: race_condition (CWE-362), severity high
- Root cause (planted at): `src/checkout/inventory.ts`
- Entry routeKeys: checkout
- Trigger routeKeys: checkout
- Oracle attribution: kinds [race_double_spend] on [checkout]

## Approach (spec only; not yet implemented)

Inventory oversell race — reserves stock with a read then write that interleaves under concurrency.
The twin pair registers the `checkout/inventory.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
