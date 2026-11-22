# acme.file-list-bola — File listing cross-tenant exposure

- Class: bola (CWE-639), severity medium
- Entry route(s): listFiles
- Oracle: cross_tenant_read attributed to listFiles
- Root cause file (materialized): src/files/list.ts, symbol register

## Intended vulnerable behaviour
lists files for any project id supplied, ignoring tenant ownership of that project.

## Intended hardened behaviour (hard decoy)
lists files only for projects owned by the caller tenant.

## Lure (why the hardened twin looks exploitable)
filters files by the project id query param and looks scoped, but trusts the project id without checking project ownership.

## Solver approach
persona_b lists files for a tenant-A project id and receives rows carrying a foreign tenant canary.
