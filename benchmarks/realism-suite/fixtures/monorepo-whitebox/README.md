# monorepo-whitebox — realism fixture #4

White-box scale and code-to-runtime binding under enterprise monorepo conditions.

## Materialized repository

`start()` writes a fresh temp tree (`sourceDir`) and initializes a **real** git repository
(loose blob/tree/commit objects, `.git/HEAD`, refs — no `git` process is spawned). The
five-commit history moves from scaffold to billing to a deliberate regression and finally
to reports and admin:

1. `chore: scaffold multi-service monorepo`
2. `feat(billing): add invoice read endpoint` (repo scopes `WHERE id = ? AND tenant_id = ?`)
3. `refactor(billing): drop tenant predicate from invoice lookup` ← **regression commit**
4. `feat(reports): add CSV export endpoint`
5. `refactor(admin): mount admin routes before authz middleware`

`fixture.git.log()` reads the history back, `fixture.git.fileAt(sha, path)` reads blobs at a
commit, and `fixture.git.regressionCommit` names the authz regression.

### Statically extractable shape

The tree is deliberately written so the shipped extractors can see it:

- `services/gateway/src/router.ts` mounts `billingRouter` (`/v2`), `reportsRouter` (`/v2`),
  `adminRouter` (`/v3`) and eight generated service routers (`/v4`). The Program Graph resolves
  the full nested prefixes (`/v2/billing/invoices/:id`, `/v3/admin/users/:id`, …).
- `services/<service>/src/routes.generated.runtime.ts` contains **2,560 literal route
  declarations** (`generatedRouter.get|post('/<service>/resource-<n>/:id', handler)`) under a
  tenant-scope guard, so AST extraction materializes every generated `/v4` route with a
  `file:line` and guard chain. (`routes.generated.ts` keeps the matching manifest.)
- All three sinks sit in their repository layer, four hops from the route:
  `route → controller → service → repo` (`invoice-repo.findById`, `report-repo.rawQuery`,
  `user-repo.saveRole`).

## Live gateway

| Surface | Shape |
| ------- | ----- |
| `GET /v2/billing/invoices/:id` | 4-hop route → controller → service → repo (`WHERE id = ?` only) |
| `GET /v2/reports/export?sort=` | 4-hop; repo concatenates `sort` into `ORDER BY` |
| `PATCH /v3/admin/users/:id` | 4-hop; admin router mounted before `requireAdmin` |
| `GET /v4/<service>/resource-<n>/:id` | 2,560 generated routes across 8 services (2,560 + 5 = 2,565 total) |

`fixture.resolve(path)` returns the mount chain, the four source hops and `hopCount`.
Personas: `mono-alice` (tenant-alpha member), `mono-bob` (tenant-beta), `mono-admin`.

## Briefing

`fixture.api` publishes the **full declared catalog**: one entry per generated `/v4` operation
(concrete path + method + `:id` param) plus the five hand-written routes. The harness turns that
into an OpenAPI document with 2,565 operations; nothing is collapsed into a wildcard and the
document stays well below `maxSpecBytes` (2 MiB), so declared ingestion parses it losslessly.

## Truth (never served)

`truth.json` contains the billing BOLA, report SQLi, admin BFLA and the git-history
regression, a two-step tenant-takeover chain, three decoys, and scale invariants
(≥2,500 routes, 2,565 declared operations, 4 hops, nested mounts, five commits).

## Self-test

Asserts route count/scale, mount depth and hop count, reads the regression commit and its
parent blobs, calls the three sinks over HTTP, checks decoy profile and generated routes,
then stops the fixture and asserts the temp tree is gone.
