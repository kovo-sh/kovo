# acme.sso-open-redirect — SSO callback open redirect

- Class: oauth (CWE-601), severity high
- Entry route(s): ssoCallback
- Oracle: open_redirect attributed to ssoCallback
- Root cause file (materialized): src/auth/sso.ts, symbol register
- Chain: acme.takeover step 1

## Intended vulnerable behaviour
redirects to the caller-supplied return URL after a weak prefix check.

## Intended hardened behaviour (hard decoy)
only redirects to a fixed allowlist of same-origin relative paths.

## Lure (why the hardened twin looks exploitable)
checks that the return target starts with a slash OR matches a known prefix, but the prefix test is a substring match that a foreign host can satisfy.

## Solver approach
attacker completes the SSO callback with a return URL pointing at a foreign origin and the redirect sink flags an off-origin input-derived redirect.
