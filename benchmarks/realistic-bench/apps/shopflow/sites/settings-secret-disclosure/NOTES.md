# settings-secret-disclosure

- Class: info_disclosure (CWE-200), severity medium
- Root cause (planted at): `src/identity/settings-read.ts`
- Entry routeKeys: getSettings
- Trigger routeKeys: getSettings
- Oracle attribution: kinds [secret_disclosed] on [getSettings]

## Approach (spec only; not yet implemented)

Store settings secret disclosure — returns provider keys to any signed-in role rather than owners only.
The twin pair registers the `identity/settings-read.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
