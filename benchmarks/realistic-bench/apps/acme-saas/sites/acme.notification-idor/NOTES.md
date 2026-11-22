# acme.notification-idor — Notification cross-tenant read

- Class: idor (CWE-639), severity medium
- Entry route(s): getNotification
- Oracle: cross_tenant_read attributed to getNotification
- Root cause file (materialized): src/notifications/read.ts, symbol register

## Intended vulnerable behaviour
returns a notification by id without scoping to the caller tenant.

## Intended hardened behaviour (hard decoy)
returns a notification only when it belongs to the caller tenant.

## Lure (why the hardened twin looks exploitable)
filters notifications by id and marks them read for the session user, but the fetch itself is not tenant scoped.

## Solver approach
persona_b requests a tenant-A notification id and receives a body carrying a foreign tenant canary.
