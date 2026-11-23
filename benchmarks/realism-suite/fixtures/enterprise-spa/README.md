# enterprise-spa — realism fixture #1

A compact, deterministic enterprise SPA topology: four loopback servers standing in
for `assets.local`, `app.local`, `api.local` and the external OIDC `idp.local`.
Everything is loopback-only and synthetic; no real identity provider, tenant data or
secret is involved.

## Topology

| Host label   | What it serves |
| ------------ | -------------- |
| `assets.local` | CDN manifest + hashed JS/CSS chunks, no auth |
| `app.local`    | SPA shell, `/login` → IdP redirect, `/callback` (HttpOnly `sid` cookie), `/dashboard`, `/inbox`, interactive `/admin?tab=…` tabs and `/admin/modal/member/:id` fragments |
| `api.local`    | REST + GraphQL API; accepts **either** the `sid` cookie **or** `Authorization: Bearer <RS256 JWT>`, plus `X-Tenant-Id` on tenant routes; CORS limited to the app origin |
| `idp.local`     | OIDC discovery, JWKS (RS256), `/authorize`, `/token` |

`start()` returns `origins` (loopback URLs), `hosts` (`hostname → 127.0.0.1:port`),
`personas` (member/admin with synthetic credentials and a pre-minted bearer token),
and an API reference. GraphQL introspection is disabled. The admin moderation view
(`/admin?tab=inbox`) renders stored note bodies as HTML; the member inbox escapes them.

`/app/__realism__/session?persona=alice|admin` mints a browser cookie for lab harnesses
that cannot drive the OIDC redirect chain. The redirect chain itself is fully exercised
by the self-test.

## Truth (never served)

`truth.json` lists five findings (stored XSS in the admin view, GraphQL BOLA, admin
export BFLA, `alg:none` session refresh, and the IdP open redirect), one two-step chain,
and three decoys (tenant-scoped REST profile, disabled introspection, public CDN chunk).

## Self-test

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test benchmarks/realism-suite/tests/
```

`selftest.ts` starts the fixture, walks the full OIDC redirect login, checks the split-origin
shell, exercises GraphQL and the admin export, stores markup, asserts the member view is
escaped and the admin view contains an inline handler (via the DOM shim), forges an `alg:none`
admin token, and stops the fixture twice to prove idempotent teardown.
