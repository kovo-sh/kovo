# api-jwt-alg-none

- Class: jwt (CWE-347), severity high
- Root cause (planted at): `src/identity/api-auth.ts`
- Entry routeKeys: salesReport
- Trigger routeKeys: salesReport
- Oracle attribution: kinds [token_forgery] on [salesReport]

## Approach (spec only; not yet implemented)

Sales report JWT alg confusion — verifies the signature but leaves the alg list open to unsigned tokens.
The twin pair registers the `identity/api-auth.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
