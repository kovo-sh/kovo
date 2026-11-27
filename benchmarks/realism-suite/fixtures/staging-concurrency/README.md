# staging-concurrency — realism fixture #3

A shared, stateful tenant that models Kovo's `staging_isolated` contract: mutations
are pre-authorized, every created entity is run-tagged, and teardown must leave the
database indistinguishable from before the run.

## Topology

| Origin label | Role |
| ------------ | ---- |
| `app`        | HTTP/1.1 REST app: tenant invoices, reports, three-step checkout, accounts, staging cleanup endpoints |
| `h2`         | HTTP/2 cleartext (h2c, prior knowledge) transfer service |

Seeded state: two invoices (100 / 200) with canaries, two reports, two accounts
(1000 / 500). Personas `stg-alice` (tenant-alpha) and `stg-bob` (tenant-beta) carry
synthetic bearer tokens.

## Run-scoped entities

Send `X-Kovo-Run-Id: <runId>` on writes. Created carts and orders get IDs shaped
`kovo-qa-<runId>-<label>-<n>`. Mutations of existing rows are journaled so cleanup can
restore them. `POST /__staging__/cleanup?runId=<id>` restores mutations, deletes tagged
rows, and returns `{removed, restored, remaining}`. `GET /__staging__/orphans?runId=` audits.
`stop()` runs the same cleanup for every tracked run and throws if any `kovo-qa-`
record survives.

## Intended surface

- `PATCH /v1/invoices/:id` — no ownership check (**write-BOLA**); `GET` is scoped (decoy).
- `GET /v1/reports/:id` — no tenant check (**IDOR**).
- `POST /v1/checkout/pay` — trusts `unitPrice` and does not require a prior quote
  (**price tampering / workflow skip**); `/quote` is server-priced (decoy).
- `POST /v2/transfers` (h2c) — read-then-write with no compare-and-set; two streams sent
  in the same packet both observe 1000 and both return 200 with one debit applied
  (**double spend**), and the idempotency key is not enforced.

## Truth (never served)

`truth.json` holds four findings, one two-step cross-tenant chain, three decoys, and the
cleanup invariants (`kovo-qa-` prefix, zero orphans, mutation restore).

## Self-test

Exercises the cross-tenant write and its read-back, the report IDOR and scoped invoice
decoy, the checkout price/workflow bypass, the h2c race (two same-tick streams), then
calls cleanup and asserts zero orphans plus the restored seed invoice. A final run-tagged
entity is left for `stop()` to clean, proving teardown safety without explicit cleanup.
