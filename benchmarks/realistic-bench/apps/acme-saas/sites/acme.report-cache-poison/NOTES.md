# acme.report-cache-poison — Public report cache poisoning

- Class: cache_poisoning (CWE-524), severity medium
- Entry route(s): publicReport
- Oracle: cache_poisoned attributed to publicReport
- Root cause file (materialized): src/reports/public.ts, symbol register

## Intended vulnerable behaviour
caches the rendered report across all callers while embedding tenant-scoped data.

## Intended hardened behaviour (hard decoy)
keys the cache per tenant or omits tenant-scoped data from the cached public view.

## Lure (why the hardened twin looks exploitable)
caches the public report keyed only by id and includes tenant-scoped figures, so a warm entry can be served across tenants.

## Solver approach
owner of tenant A warms the public report cache; a tenant-B caller receives the cached body carrying tenant-A canary data.
