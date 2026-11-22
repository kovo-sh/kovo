# acme.apikey-disclosure — API key secret disclosure to viewer

- Class: info_disclosure (CWE-200), severity high
- Entry route(s): listApiKeys
- Oracle: secret_disclosed attributed to listApiKeys
- Root cause file (materialized): src/members/keys.ts, symbol register

## Intended vulnerable behaviour
returns the full API key secret to any member including viewers.

## Intended hardened behaviour (hard decoy)
returns only a masked prefix of the secret and never the full value to non-owners.

## Lure (why the hardened twin looks exploitable)
masks the secret in the list view for most roles but returns the full secret when a verbose flag is set.

## Solver approach
viewer lists API keys and receives a full secret canary they are not entitled to see.
