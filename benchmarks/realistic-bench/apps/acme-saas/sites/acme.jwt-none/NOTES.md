# acme.jwt-none — API token alg:none forgery

- Class: jwt (CWE-347), severity high
- Entry route(s): refreshToken
- Oracle: token_forgery attributed to refreshToken
- Root cause file (materialized): src/auth/token.ts, symbol register
- Chain: acme.takeover step 2

## Intended vulnerable behaviour
verifies the refresh token while still accepting the none algorithm.

## Intended hardened behaviour (hard decoy)
verifies the refresh token against HS256 only and rejects alg:none.

## Lure (why the hardened twin looks exploitable)
checks the token signature and expiry but leaves alg:none in the accepted algorithm list.

## Solver approach
attacker crafts an alg:none token for another subject and the verify sink flags acceptance of a token it never issued.
