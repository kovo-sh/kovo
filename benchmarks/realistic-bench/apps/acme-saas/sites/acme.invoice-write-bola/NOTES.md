# acme.invoice-write-bola — Invoice update cross-tenant write

- Class: bola (CWE-639), severity high
- Entry route(s): updateInvoice
- Oracle: cross_tenant_write attributed to updateInvoice
- Root cause file (materialized): src/billing/update.ts, symbol register

## Intended vulnerable behaviour
updates the invoice by id without confirming it belongs to the caller tenant.

## Intended hardened behaviour (hard decoy)
updates only when the invoice tenant matches the session tenant.

## Lure (why the hardened twin looks exploitable)
confirms the invoice exists before updating, which looks careful but omits the tenant match on the update.

## Solver approach
owner of tenant B updates a tenant-A invoice amount; audit diff shows a write to a foreign tenant row.
