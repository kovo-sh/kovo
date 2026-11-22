# acme.billing-tamper — Plan change price tampering

- Class: business_logic (CWE-472), severity high
- Entry route(s): updatePlan
- Oracle: invariant_violation attributed to updatePlan
- Root cause file (materialized): src/billing/plan.ts, symbol register

## Intended vulnerable behaviour
applies a caller-supplied price when switching plans instead of the catalog price.

## Intended hardened behaviour (hard decoy)
ignores any body price and always applies the catalog price for the chosen plan.

## Lure (why the hardened twin looks exploitable)
reads the target plan by id but trusts a price field in the body instead of the catalog price.

## Solver approach
owner switches plan while supplying a mismatched price and the invariant monitor sees plan price inconsistent with the catalog.
