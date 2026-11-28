# Multi-Hop Chain Playbook
Tags: multihop, hop-checkpoint, composite-receipt, derived-custody, async-pivot
Summary: Verify multi-hop causal chains end-to-end with ctx.chain, sealed capability custody, and CompositeProofReceipt.

## 1. Checkpoint & Exploration Discipline
- When given a `hopCheckpoint` (`doNotRediscover: true`), start from its verified `capabilityHandles[]` (`cap:hop_<id>:<slot>`) and advance `nextGoal` instead of repeating earlier hops or re-probing `prunedBranches[]`.
- Explore routes and parameters with `http_request`/`kovo_http` first; never call `kovo_verify` solely to seal a single hop. Execute the full causal sequence inside one `kovo_verify` script ending in `ctx.chain(...).prove()` / `ctx.prove_composite`.

## 2. Derived Capability Custody & Helpers
- **Seal intermediate artifacts (`ctx.seal_capability`):** Assert `2xx` before sealing, and use structured selectors (`jsonPath`, `header`, `cookie`, or `value` — NEVER `regex`). Inject sealed handles (`cap:hop_<id>:<slot>`) into downstream requests via `{ capability: { handle, target: "bearer" | "header" | "cookie" | "url" }, role: "probe" }` (omit `as` when sending a minted bearer/session token).
- **Cryptographic derivation:** Use `ctx.hmac_sign` / `ctx.jwt_sign` over a sealed key handle to produce host-attested `derivedFromCapabilityId` signatures/tokens without exposing raw key bytes.
- **Bounded async convergence:** Use `ctx.await_async({ pollRequest, matchPredicate, triggerExchangeId, correlationId })` for background jobs or delayed side effects instead of unbounded sleep loops.

## 3. Connected `CompositeProofReceipt` DAG (`ctx.chain` / `ctx.prove_composite`)
Prefer `ctx.chain({ chainId, terminalVulnClass })` to auto-track hops, targets, and causal edges (`value_binding`, `derived_crypto_binding`, `state_transition_binding` with pre-mutation `{ arm: "control" }` `ablationExchangeIds` as the same actor, and `async_pivot_binding`):

```ts
const actor = 'actor_low'
const chain = ctx.chain({ chainId: 'chain-authz-1', terminalVulnClass: 'broken_access_control' })
const ctl = await ctx.http('/api/v1/terminal', { as: actor, arm: 'control' })
chain.control(ctl)
const cap = await chain.hop('hop_1', { claimedDelta: 'Obtained scoped capability.' }, async () => {
  const ex = await ctx.http_send('/api/v1/resource', { as: actor, role: 'probe' })
  if (!(ex.status >= 200 && ex.status < 300)) throw new Error(`Hop 1 failed: ${ex.status}`)
  return ctx.seal_capability({ exchange: ex, hopReceiptId: 'hop_1', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
})
const fin = await chain.hop('hop_2', { claimedDelta: 'Crossed terminal boundary via sealed capability.' }, () =>
  ctx.http_send('/api/v1/terminal', { capability: { handle: cap.handle, target: 'bearer' }, role: 'probe' }),
)
chain.readback(fin)
await chain.prove({ claimedImpact: 'Unauthorized cross-boundary access confirmed.' })
return ctx.result({ title: 'Multi-hop capability pivot' })
```

- Declare every causal hop from Hop 1 through `terminalHopId` connected via `causalEdges[]` (no orphan exploratory hops); with prerequisite setup hops, always finish with `ctx.chain(...).prove()` / `ctx.prove_composite` rather than standalone single-hop helpers.

## 4. Attacker-Origin Provenance & Clean Settlement
- **Attacker-Origin Provenance:** Start from a low-privilege attacker persona (or anonymous) and derive every downstream capability inside the DAG; reserve privileged/victim personas strictly for `{ arm: "control" }` baselines.
- **Terminal impact vs. quarantined capabilities:** Intermediate IDs, metadata, or handles remain `capability_only` — do not file standalone `CWE-200` when the downstream boundary holds.
- **Clean settlement:** When the terminal boundary enforces authorization or state invariants, stop retrying after failed controls and close cleanly with `record_coverage` (`ruled_out` with `enforcingControl`, or `needs_follow_up`) and `complete_intent`.
