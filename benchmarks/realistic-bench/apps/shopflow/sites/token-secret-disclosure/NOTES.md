# token-secret-disclosure

- Class: info_disclosure (CWE-200), severity high
- Root cause (planted at): `src/identity/token-list.ts`
- Entry routeKeys: listTokens
- Trigger routeKeys: listTokens
- Oracle attribution: kinds [secret_disclosed] on [listTokens]

## Approach (spec only; not yet implemented)

API token list secret disclosure — returns a masked preview that still includes the full secret in a sibling field.
The twin pair registers the `identity/token-list.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
