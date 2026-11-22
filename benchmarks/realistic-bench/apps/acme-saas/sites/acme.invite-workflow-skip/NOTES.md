# acme.invite-workflow-skip — Invite acceptance workflow skip

- Class: workflow_bypass (CWE-841), severity medium
- Entry route(s): acceptInvite
- Oracle: workflow_skip attributed to acceptInvite
- Root cause file (materialized): src/members/invites.ts, symbol register

## Intended vulnerable behaviour
accepts an invite by token regardless of its current state, allowing re-accept or skipping verification.

## Intended hardened behaviour (hard decoy)
accepts only invites currently in the pending state and transitions them exactly once.

## Lure (why the hardened twin looks exploitable)
looks the invite up by token and marks it accepted but never checks the invite is still in the pending state.

## Solver approach
attacker accepts an already-consumed or non-pending invite and the workflow monitor flags a skipped state transition.
