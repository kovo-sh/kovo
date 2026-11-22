# negative-qty-logic

- Class: business_logic (CWE-840), severity medium
- Root cause (planted at): `src/checkout/cart-items.ts`
- Entry routeKeys: addCartItem
- Trigger routeKeys: addCartItem
- Oracle attribution: kinds [invariant_violation] on [addCartItem]

## Approach (spec only; not yet implemented)

Negative cart quantity — rejects zero quantity but lets negatives through to offset the total.
The twin pair registers the `checkout/cart-items.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
