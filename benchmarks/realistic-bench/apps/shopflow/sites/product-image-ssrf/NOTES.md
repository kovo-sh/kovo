# product-image-ssrf

- Class: ssrf (CWE-918), severity high
- Root cause (planted at): `src/catalog/image-fetch.ts`
- Entry routeKeys: importProductImage
- Trigger routeKeys: importProductImage
- Oracle attribution: kinds [ssrf_internal_fetch] on [importProductImage]

## Approach (spec only; not yet implemented)

Product image import SSRF — blocks obvious metadata hostnames but follows the fetched redirect.
The twin pair registers the `catalog/image-fetch.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
