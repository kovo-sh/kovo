# refund-exceeds-payment

- Class: business_logic (CWE-840), severity high
- Root cause (planted at): `src/billing/refund-approve.ts`
- Entry routeKeys: approveRefund
- Trigger routeKeys: approveRefund
- Oracle attribution: kinds [invariant_violation] on [approveRefund]

## Approach (spec only; not yet implemented)

Refund exceeds captured payment — caps each refund at the order total but ignores prior partial refunds.
The twin pair registers the `billing/refund-approve.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
