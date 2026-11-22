# coupon-reuse

- Class: business_logic (CWE-840), severity medium
- Root cause (planted at): `src/checkout/coupon-apply.ts`
- Entry routeKeys: applyCoupon
- Trigger routeKeys: applyCoupon
- Oracle attribution: kinds [invariant_violation] on [applyCoupon]

## Approach (spec only; not yet implemented)

Single-use coupon reuse — marks the coupon used after applying, so a retry slips in a second use.
The twin pair registers the `checkout/coupon-apply.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
