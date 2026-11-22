# checkout-open-redirect

- Class: open_redirect (CWE-601), severity medium
- Root cause (planted at): `src/checkout/return-handler.ts`
- Entry routeKeys: checkoutReturn
- Trigger routeKeys: checkoutReturn
- Oracle attribution: kinds [open_redirect] on [checkoutReturn]

## Approach (spec only; not yet implemented)

Checkout return open redirect — allowlists a prefix match that a foreign host can spoof as a subdomain.
The twin pair registers the `checkout/return-handler.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
