# acme.settings-csrf — Account settings CSRF

- Class: csrf (CWE-352), severity medium
- Entry route(s): updateSettings
- Oracle: csrf_state_change attributed to updateSettings
- Root cause file (materialized): src/members/settings.ts, symbol register

## Intended vulnerable behaviour
applies the settings change on a cookie-authenticated form POST without validating a CSRF token.

## Intended hardened behaviour (hard decoy)
requires a valid CSRF token before applying the settings change.

## Lure (why the hardened twin looks exploitable)
checks for a session cookie and a same-site referer in one branch but applies the change before the token check on the form path.

## Solver approach
attacker submits a cross-origin cookie-authenticated settings change with no CSRF token and the change still succeeds.
