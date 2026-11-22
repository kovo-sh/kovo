# acme.reflected-search-xss — Legacy search reflected XSS

- Class: xss_reflected (CWE-79), severity medium
- Entry route(s): reflectedSearch
- Oracle: reflected_xss_rendered attributed to reflectedSearch
- Root cause file (materialized): src/legacy/search.ts, symbol register

## Intended vulnerable behaviour
reflects the raw query term into an HTML response on the empty-results path.

## Intended hardened behaviour (hard decoy)
escapes the query term in every branch before reflecting it.

## Lure (why the hardened twin looks exploitable)
echoes the query inside a titled HTML fragment and escapes angle brackets in one branch but not in the no-results branch.

## Solver approach
attacker requests the legacy search with an active-markup term and the response inspector sees it unescaped in the HTML.
