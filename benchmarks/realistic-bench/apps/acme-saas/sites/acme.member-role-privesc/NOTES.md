# acme.member-role-privesc — Member update role privilege escalation

- Class: mass_assignment (CWE-269), severity high
- Entry route(s): updateMember
- Oracle: privilege_escalation attributed to updateMember
- Root cause file (materialized): src/members/roles.ts, symbol register

## Intended vulnerable behaviour
spreads the whole request body into the member update, letting a viewer set role=owner.

## Intended hardened behaviour (hard decoy)
writes only name/avatar and ignores role unless the caller is already an owner.

## Lure (why the hardened twin looks exploitable)
copies an allowlist of profile fields but leaves role in the same object spread so a crafted body still reaches it.

## Solver approach
viewer updates own member record with role elevated to owner; audit diff shows a role change the caller was not entitled to make.
