# acme.project-stored-xss — Project description stored XSS

- Class: xss_stored (CWE-79), severity high
- Entry route(s): updateProject  |  trigger route(s): renderProjectCard
- Oracle: stored_xss_rendered attributed to renderProjectCard
- Root cause file (materialized): src/catalog/card.ts, symbol register

## Intended vulnerable behaviour
stores the description and renders it as raw HTML with an incomplete sanitizer.

## Intended hardened behaviour (hard decoy)
stores the description but escapes or strips active markup when rendering the card.

## Lure (why the hardened twin looks exploitable)
renders a rich-HTML description and runs a naive tag filter that removes <script> but misses event-handler attributes.

## Solver approach
owner saves a project description containing an event-handler attribute, then loads the card render route which emits the active markup.
