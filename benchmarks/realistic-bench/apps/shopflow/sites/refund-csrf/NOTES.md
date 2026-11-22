# refund-csrf

- Class: csrf (CWE-352), severity medium
- Root cause (planted at): `src/billing/refund-create.ts`
- Entry routeKeys: createRefund
- Trigger routeKeys: createRefund
- Oracle attribution: kinds [csrf_state_change] on [createRefund]

## Approach (spec only; not yet implemented)

Refund creation CSRF — accepts a token field but never compares it to the session token.
The twin pair registers the `billing/refund-create.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
