# acme.legacy-auth-bypass — Legacy login authentication bypass

- Class: auth_bypass (CWE-287), severity high
- Entry route(s): legacyLogin
- Oracle: auth_bypass attributed to legacyLogin
- Root cause file (materialized): src/auth/legacy.ts, symbol register

## Intended vulnerable behaviour
issues a session for any email matching a weak legacy domain suffix check with no password.

## Intended hardened behaviour (hard decoy)
requires a valid password and never issues a session from the legacy path alone.

## Lure (why the hardened twin looks exploitable)
supports a legacy password-less SSO hand-off for one domain but the domain check is a suffix match any email can satisfy.

## Solver approach
attacker logs in through the legacy path with only an email and the auth monitor flags a session issued without credentials.
