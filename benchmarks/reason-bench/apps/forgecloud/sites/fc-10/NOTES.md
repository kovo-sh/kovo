# fc-10 chain note (merge follow-up outside this stream's lease)

Observed order on seed 1: `secret_disclosed` at `webhooks.deliveries` (seq 2) precedes
`webhook_forgery` at `webhooks.receive` (seq 4), sharing the same actor and server clock.

`ChainOracle` cannot credit the chain yet because every host monitor emission (in `truth/inspect.ts`
and `truth/audit.ts`) carries a detail bag without one of the artifact aliases
(`artifact`, `causalArtifact`, `chainArtifact`, `correlationId`, `artifactId`), so
`recordOracleEvent` records nothing and `completed()` returns `no causal artifacts observed`.
Fix: add `artifact` (for example the delivery id or hook external id) to the `secret_disclosed`
and `webhook_forgery` details.

`truth/blueprint.ts` also has no `chains` entry, and this stream may not edit it, so the causal
spec is registered from this site spec at discovery time (`appBlueprint.chains = [...]`).
