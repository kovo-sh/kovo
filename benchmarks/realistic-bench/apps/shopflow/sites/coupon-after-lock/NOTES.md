# coupon-after-lock

- Class: workflow_bypass (CWE-840), severity high
- Root cause (planted at): `src/checkout/coupon-lock.ts`
- Entry routeKeys: applyCoupon
- Trigger routeKeys: applyCoupon
- Oracle attribution: kinds [workflow_skip] on [applyCoupon]
- Chain: promo-chain step 1

## Approach (spec only; not yet implemented)

Apply coupon after totals locked — lets a coupon apply even once the cart has moved past the pricing lock.
The twin pair registers the `checkout/coupon-lock.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
