# Stream backlog (parallel dispatch queue)

Rule: keep at least **3 active streams** while any `ready` task has a free lease.
One stage per stream; split tasks that touch >2 files or span >1 milestone.
Leases are exclusive: a task may start only if its files are not held by an active stream.

Format:
`- [ ] <task> | status: ready|active|blocked | lease: <files> | deps: <task ids or -> | stream: <branch or ->`

## Active

- [ ] M0 ProofReceipt + DSL retirement | status: active | lease: src/server/execution.ts, src/server/replay-verifier.ts, src/replay-spec.ts, src/server/proof-tools.ts | deps: - | stream: agents/v7-proofreceipt
- [ ] M0 smoke battery (Tier 0/1 + precision trap) | status: active | lease: scripts/smoke-agentic.ts, benchmarks/realism-suite/traps/** | deps: - | stream: agents/smoke-battery
- [ ] M1 white-box dataflow slices in briefs | status: active | lease: src/server/program-graph.ts, src/server/semantic-audit.ts, src/server/assignment-brief.ts | deps: - | stream: agents/v7-whitebox
- [ ] M1 realism #3 race/workflow capability | status: active | lease: src/server/deterministic-engine.ts, src/server/probes/** | deps: - | stream: agents/v7-realism-race
- [ ] v7 docs + scorecards | status: active | lease: VERIFICATION-v5.md, HANDOVER-v5.md, plans/v7.md, docs/** | deps: - | stream: agents/v7-docs

## Ready (dispatch when a lease frees or active < 3)

- [ ] Phase0 crawlStateGraph paging (3 remaining unpaged reads) | status: ready | lease: src/server/phase0-recon.ts | deps: - | stream: -
- [ ] Realism #2 pending_oob promotion -> finding conversion | status: blocked | lease: src/server/execution.ts | deps: proofreceipt-cut2 | stream: -
- [ ] M2 4-hop confirmations from white-box slices | status: blocked | lease: src/server/execution.ts | deps: v7-whitebox | stream: -
- [ ] Certification 3-app 600 s generous smoke | status: blocked | lease: scripts/** (measurement only) | deps: proofreceipt-cut1, smoke-battery | stream: -
- [ ] Held-out unified baseline (salted, n=1) | status: ready | lease: none (measurement) | deps: - | stream: -
- [ ] Diminishing-returns precision guard (cap re-investigation, 2 dry rounds) | status: blocked | lease: src/server/execution.ts | deps: proofreceipt-cut1 | stream: -
- [ ] Stale worktree cleanup + docs/AGENTS hygiene | status: ready | lease: none | deps: - | stream: -

## Completed

- [x] Budget decoupling (phase allowances, 50 RPS) | stream: agents/budget-split
- [x] Agentic precision triage (evidence-first class labelling) | stream: agents/agentic-fp
- [x] Floor restore 26 -> 31/59 + XSS all-occurrence scan | stream: agents/floor-regress, agents/xss-occurrence
