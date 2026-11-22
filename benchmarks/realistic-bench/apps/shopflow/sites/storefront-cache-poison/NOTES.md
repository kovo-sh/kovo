# storefront-cache-poison

- Class: cache_poisoning (CWE-525), severity medium
- Root cause (planted at): `src/catalog/store-page.ts`
- Entry routeKeys: storeProductPage
- Trigger routeKeys: storeProductPage
- Oracle attribution: kinds [cache_poisoned] on [storeProductPage]

## Approach (spec only; not yet implemented)

Storefront product page cache poisoning — caches by path only while echoing a per-viewer store header into the body.
The twin pair registers the `catalog/store-page.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
