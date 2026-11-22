# acme.admin-bfla — Admin user delete function-level authz bypass

- Class: bfla (CWE-285), severity critical
- Entry route(s): adminDeleteUser
- Oracle: privilege_escalation attributed to adminDeleteUser
- Root cause file (materialized): src/admin/users.ts, symbol register

## Intended vulnerable behaviour
deletes any user given authentication, without verifying the caller holds an admin role.

## Intended hardened behaviour (hard decoy)
requires the caller to hold an admin role in the target tenant before deleting.

## Lure (why the hardened twin looks exploitable)
lives under an /admin path and checks authentication, which looks gated, but never checks the admin role.

## Solver approach
a non-admin viewer calls the admin user-delete route and the audit diff shows a privileged delete the role did not permit.
