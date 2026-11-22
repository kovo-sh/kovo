# acme.import-xxe — Project import XML external entity

- Class: xxe (CWE-611), severity high
- Entry route(s): importProjects
- Oracle: xxe_entity_resolved attributed to importProjects
- Root cause file (materialized): src/integrations/import.ts, symbol register

## Intended vulnerable behaviour
parses the import XML with external entity resolution enabled.

## Intended hardened behaviour (hard decoy)
parses the import XML with external entities disabled.

## Lure (why the hardened twin looks exploitable)
parses the uploaded XML with entity support enabled to support legacy exports, which looks like a compatibility feature.

## Solver approach
attacker uploads a project import document declaring an external entity that resolves a virtual system file.
