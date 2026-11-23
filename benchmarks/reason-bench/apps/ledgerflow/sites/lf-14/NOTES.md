# lf-14 author notes

Chain intent: plant a footer note on an invoice (`createInvoice`) -> run the background PDF worker
(`exportInvoicePdf`) -> the worker resolves a ledger seal mark to the internal metadata service and
the egress guard records `ssrf_internal_fetch` for `ledger-metadata`.

The web preview (`previewInvoice`) escapes the note, so markup probes against the UI surface are
clean; only the worker sink resolves the seal mark.

Blocked outside this stream's lease: `truth/blueprint.ts` has no `chains: CausalChainSpec[]`, so the
site cannot carry `causalChainId` without failing `validateBlueprint`. Suggested spec once truth lands:

```ts
{ id: 'lf-14-pdf-seal-fetch',
  hops: [{ hopId: 'd1-plant-note', routeKey: 'createInvoice', kind: 'stored_xss_rendered' }],
  finalImpactKind: 'ssrf_internal_fetch', finalRouteKey: 'exportInvoicePdf' }
```

Caveat: no current monitor emits `stored_xss_rendered`, and none of the emitted events carry
`detail.artifact`, which `ChainOracle` requires. Both are truth/monitor-side gaps.
