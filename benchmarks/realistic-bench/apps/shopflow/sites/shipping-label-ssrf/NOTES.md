# shipping-label-ssrf

- Class: ssrf (CWE-918), severity medium
- Root cause (planted at): `src/fulfillment/label-import.ts`
- Entry routeKeys: importShippingLabel
- Trigger routeKeys: importShippingLabel
- Oracle attribution: kinds [ssrf_internal_fetch] on [importShippingLabel]

## Approach (spec only; not yet implemented)

Shipping label import SSRF — fetches a label template URL from the manifest without host checks.
The twin pair registers the `fulfillment/label-import.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
