# acme.credit-double-spend — Credit application double spend

- Class: race_condition (CWE-362), severity high
- Entry route(s): applyCredit
- Oracle: race_double_spend attributed to applyCredit
- Root cause file (materialized): src/billing/credits.ts, symbol register

## Intended vulnerable behaviour
applies a credit using read-modify-write without guarding against concurrent use.

## Intended hardened behaviour (hard decoy)
applies the credit in a single conditional update that cannot drive the balance negative.

## Lure (why the hardened twin looks exploitable)
reads the balance, checks it, then writes the new balance in separate steps so concurrent applies both pass the check.

## Solver approach
owner applies the same credit concurrently and the invariant monitor sees the balance driven negative.
