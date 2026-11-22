# acme.export-cmd-injection — Report export command injection

- Class: command_injection (CWE-78), severity critical
- Entry route(s): exportReport
- Oracle: command_injection_simulated attributed to exportReport
- Root cause file (materialized): src/reports/export.ts, symbol register

## Intended vulnerable behaviour
interpolates the export name into a shell archive command.

## Intended hardened behaviour (hard decoy)
passes the export name as a fixed argument with no shell metacharacters reaching the command template.

## Lure (why the hardened twin looks exploitable)
quotes the export filename in the archive command but the quoting is single-pass so an embedded quote re-opens the argument.

## Solver approach
owner requests an export whose name contains a shell separator and the command simulator parses more than the single intended command.
