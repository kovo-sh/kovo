# acme.report-ssti — Report template server-side template injection

- Class: ssti (CWE-1336), severity high
- Entry route(s): createReport  |  trigger route(s): renderReport
- Oracle: template_code_exec attributed to renderReport
- Root cause file (materialized): src/reports/render.ts, symbol register

## Intended vulnerable behaviour
stores the caller-supplied template body and later renders it as template source.

## Intended hardened behaviour (hard decoy)
treats the stored body as plain text / data context and never evaluates it as template source.

## Lure (why the hardened twin looks exploitable)
offers a small set of placeholder tokens and escapes output, so it looks like a data-only templating feature while rendering the stored source as a live template.

## Solver approach
owner creates a report whose template body embeds an expression, then requests the render route which evaluates it.
