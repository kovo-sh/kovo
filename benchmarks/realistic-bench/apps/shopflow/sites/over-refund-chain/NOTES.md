# over-refund-chain

- Class: business_logic (CWE-840), severity high
- Root cause (planted at): `src/billing/refund-overage.ts`
- Entry routeKeys: createRefund
- Trigger routeKeys: createRefund
- Oracle attribution: kinds [invariant_violation] on [createRefund]
- Chain: promo-chain step 2

## Approach (spec only; not yet implemented)

Refund the inflated discount back as cash — refunds against the discounted total, turning the stacked promo into cash.
The twin pair registers the `billing/refund-overage.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
