# lf-13 author notes

Chain intent: `activityFeed` (reference discovery) -> `delegateApproval` (hand-off that also settles
the linked payout). The team feed is read-only, so the observable hops live on the hand-off route:

- hop `d2-delegation`: `stale_privilege_use` on `delegateApproval` (non-admin delegation accepted).
- final impact: `self_approval_bypass` on `delegateApproval` (payout approved by its own maker).

Ordering is guaranteed: `truth/monitors.ts` runs `checkAuthorization` before `checkPayoutShadow`, so
the delegation event precedes the settlement event within one request.

Blocked outside this stream's lease: `truth/blueprint.ts` ships no `chains: CausalChainSpec[]`, so
`solver.causalChainId` cannot be set without failing `validateBlueprint` ("causalChainId has no chain
spec"). Suggested spec once truth lands:

```ts
{ id: 'lf-13-approval-takeover',
  hops: [{ hopId: 'd2-delegation', routeKey: 'delegateApproval', kind: 'stale_privilege_use' }],
  finalImpactKind: 'self_approval_bypass', finalRouteKey: 'delegateApproval' }
```

The generic monitors also do not attach `detail.artifact`, which `ChainOracle` requires; the hop
events currently carry the approval/payout ids under other keys. Both gaps are truth-side.
