# acme.seat-invariant — Seat allocation invariant bypass

- Class: business_logic (CWE-840), severity medium
- Entry route(s): addSeat
- Oracle: invariant_violation attributed to addSeat
- Root cause file (materialized): src/billing/seats.ts, symbol register

## Intended vulnerable behaviour
increments seats used without atomically enforcing the plan seat limit.

## Intended hardened behaviour (hard decoy)
enforces the seat limit in the same guarded step as the increment.

## Lure (why the hardened twin looks exploitable)
checks the seat limit before incrementing but reads a stale count so a burst can exceed the plan limit.

## Solver approach
owner adds seats past the plan limit and the invariant monitor sees seats_used exceed the plan seat cap.

## Monitor scoping
the seats `invariant_violation` fires only when the audited row mutates `seats_used`. A plan change
that leaves the tenant above its new tier's limit (owner self-service downgrade) is not a seat
invariant and must not emit `(invariant_violation, updatePlan)`: that pair belongs to
`acme.billing-tamper`. See `truth/POLICY.md`.
