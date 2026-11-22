# acme.export-open-redirect — Export download open redirect

- Class: open_redirect (CWE-601), severity low
- Entry route(s): exportRedirect
- Oracle: open_redirect attributed to exportRedirect
- Root cause file (materialized): src/legacy/redirect.ts, symbol register

## Intended vulnerable behaviour
redirects to a caller-supplied next URL with no origin check.

## Intended hardened behaviour (hard decoy)
redirects only to relative same-origin paths.

## Lure (why the hardened twin looks exploitable)
redirects to a signed download URL but falls back to a caller-supplied next parameter when the signature is absent.

## Solver approach
attacker requests the export download with a next parameter pointing off-origin and the redirect sink flags it.
