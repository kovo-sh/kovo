# fc-11 chain note (merge follow-up outside this stream's lease)

Observed order on seed 1: `secret_disclosed` at `graphql` (seq 8) precedes `privilege_escalation` at
`deployments.promote` (seq 11), sharing the runner-token actor and server clock.

`ChainOracle` cannot credit the chain yet because the host monitor emission in `truth/inspect.ts`
carries `{ token, owner }` with no artifact alias (`artifact`, `causalArtifact`, `chainArtifact`,
`correlationId`, `artifactId`), so `recordOracleEvent` records nothing and `completed()` returns
`no causal artifacts observed`. Fix: carry the run external id (or preview token id) as `artifact`
on the disclosure and the promotion event.

`truth/blueprint.ts` also has no `chains` entry, and this stream may not edit it, so the causal
spec is registered from this site spec at discovery time (`appBlueprint.chains = [...]`).
