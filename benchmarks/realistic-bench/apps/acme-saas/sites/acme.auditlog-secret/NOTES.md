# acme.auditlog-secret — Admin audit log secret leakage

- Class: info_disclosure (CWE-532), severity medium
- Entry route(s): adminAuditLog
- Oracle: secret_disclosed attributed to adminAuditLog
- Root cause file (materialized): src/admin/audit.ts, symbol register

## Intended vulnerable behaviour
includes raw secret references in the audit log details returned to the caller.

## Intended hardened behaviour (hard decoy)
redacts secret references from audit log details before returning them.

## Lure (why the hardened twin looks exploitable)
returns audit entries with a details blob that still contains the secret reference captured at event time.

## Solver approach
a non-entitled caller reads the audit log and receives a secret canary embedded in the details.
