# acme.project-mass-assign — Project create mass assignment

- Class: mass_assignment (CWE-915), severity medium
- Entry route(s): createProject
- Oracle: mass_assignment attributed to createProject
- Root cause file (materialized): src/catalog/create.ts, symbol register

## Intended vulnerable behaviour
merges the request body over the defaults, letting the caller set tenant_id or owner_id.

## Intended hardened behaviour (hard decoy)
constructs the row from named fields only and always forces tenant_id from the session.

## Lure (why the hardened twin looks exploitable)
defaults tenant_id from the session but still merges the request body afterward, so a supplied tenant_id wins.

## Solver approach
owner creates a project with a foreign tenant_id in the body; audit diff shows a row written outside the caller tenant.
