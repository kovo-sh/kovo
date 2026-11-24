# storefront-cache-poison

- Class: cache_poisoning (CWE-525), severity medium
- Root cause (planted at): `src/catalog/store-page.ts`
- Entry routeKeys: storeProductPage
- Trigger routeKeys: storeProductPage
- Oracle attribution: kinds [cache_poisoned] on [storeProductPage]

## Approach

Storefront product page cache poisoning — caches by path only while personalizing the page with the
signed-in viewer's loyalty note. The note is resolved only for the authenticated viewer's own store:
an anonymous read (or a forged `x-store` header) gets the store's public display name, so the public
surface never carries a customer canary. The planted impact is the cross-tenant cache HIT: store A
warms the page, store B is served store A's personalized body. The twin pair registers the
`catalog/store-page.ts` module route(s); the solver drives the entry route(s) and impact is proven by
the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
