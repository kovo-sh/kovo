# Stream backlog (parallel dispatch queue)

Rule: keep at least **3 active streams** while any `ready` task has a free lease.
One stage per stream; split tasks that touch >2 files or span >1 milestone.
Leases are exclusive: a task may start only if its files are not held by an active stream.

Format:
`- [ ] <task> | status: ready|active|blocked | lease: <files> | deps: <task ids or -> | stream: <branch or ->`

## Active (2026-11-24)

- [ ] P0 dispatch killer (opsportal 1/7, acme 2/19 planned steps stranded) + funnel invariant | status: active | lease: src/server/execution.ts, src/server/graph-leads.ts, scripts/worker-gate.sh, tests/v7-dispatch-funnel.test.ts | deps: - | stream: agents/dispatch-funnel
- [ ] Cut 3a strict strangler (wire 6 recipe families, delete their VM branches, no-fallback assert) | status: active | lease: src/server/deterministic-engine.ts, src/server/deterministic-specs.ts, src/server/replay-verifier.ts, src/replay-spec.ts, src/server/floor-recipes.ts, tests/v7-cut3a.test.ts | deps: - | stream: agents/cut3a
- [ ] Realism gate split (oob_wiring_fnr vs fixture_capability_recall) + #4 3-number funnel | status: active | lease: scripts/benchmark-realism.ts, benchmarks/realism-suite/** (gates only), docs/SMOKE-BATTERY.md, tests/v6-realism-gates.test.ts | deps: - | stream: agents/realism-gates

## Active additions (2026-11-24, post-autopsy)

- [ ] SQLi boolean arms grounded in target's own baseline rows | status: active | lease: src/server/probes/injection.ts, tests/v7-sqli-baseline.test.ts | deps: - | stream: agents/sqli-baseline
- [ ] Spec-or-proof-gap mandatory at settlement (19/23 route-hit targets submitted no spec) | status: active | lease: src/server/agent-session.ts, src/server/assignment-brief.ts, tests/v7-spec-submission.test.ts | deps: - | stream: agents/spec-submission

## Ready (dispatch when a lease frees)

- [ ] Cut 3b: migrate remaining legacy kinds (browser_chain, rce_proof, auth_protocol_proof, cache_differential, http_chain traversal/redirect/xss/ssti/cmdi, dns_takeover, tls_audit, ws_chain, upload_probe, static_ast_proof) -> execution.ts < 8.5K, replay-verifier < 1.0K | status: blocked | lease: src/server/replay-verifier.ts, src/replay-spec.ts, src/server/floor-recipes.ts, src/server/proof-receipt.ts | deps: cut3a | stream: -
- [ ] Realism #4 4-hop conversion 0/3 (act on the funnel verdict: brief depth vs proof conversion) | status: blocked | lease: src/server/execution.ts, src/server/assignment-brief.ts | deps: dispatch-funnel, realism-gates | stream: -
- [ ] Realism #2 remaining capability: blind-SQLi + chain leg 3/3 | status: blocked | lease: src/server/deterministic-engine.ts, src/server/probes/** | deps: cut3a, realism-gates | stream: -
- [ ] Realism #2 FP corpus: add both held-out unmatched FPs as Tier-0 archetypes once triaged | status: blocked | lease: benchmarks/realism-suite/traps/** | deps: heldout-lift | stream: -
- [ ] Tier-1 smoke calibration study (8 varied builds vs reference) | status: ready | lease: scripts/smoke-agentic.ts, benchmarks/realism-suite/traps/** | deps: dispatch-funnel | stream: -
- [ ] Certification matrix on post-Cut-3a code (dev n=3, held-out n=2-3, 600 s) at the +6pp bar | status: blocked | lease: none (measurement) | deps: cut3a, dispatch-funnel, realism-gates | stream: -
- [ ] Pre-existing suite hang: `tests/v4-m4-surface-orchestration.test.ts` file-level teardown >15 min | status: ready | lease: tests/v4-m4-surface-orchestration.test.ts | deps: - | stream: -

## Completed

- [x] Budget decoupling (phase allowances, 50 RPS) | stream: agents/budget-split
- [x] Agentic precision triage (evidence-first class labelling) | stream: agents/agentic-fp
- [x] Floor restore 26 -> 31/59 + XSS all-occurrence scan | stream: agents/floor-regress, agents/xss-occurrence
- [x] Held-out floor restore 17 -> 24/58 (+ dev 31 -> 33/59) | stream: agents/heldout-floor-regress
- [x] Injection impact class precedence (CWE-89 not rebranded by narrative; shopflow rotation 3/19 @100%) | stream: agents/shopflow-fp
- [x] Phase0 crawl paging (last 3 unpaged crawlStateGraph reads) | stream: agents/crawl-paging
- [x] Realism #3 capability: write-BOLA, h2 race, checkout tampering | stream: agents/v7-realism-race
- [x] Realism extractor: submit declared probe targets only (#3 precision 100%) | stream: agents/realism-extract
- [x] Floor recipe library (6 typed recipes + boolean receipt rule) | stream: agents/cut3-recipes, agents/v7-proofreceipt
- [x] Brief slices + precision guard + spec-shape/stall/turn fixes + canonical receipt category | stream: agents/v7-brief-slice
- [x] Realism #2 OOB attribution (traceId) + engine selection (query carriers, self-trigger) -> async SSRF+XXE confirmed | stream: agents/realism-oob, agents/realism-oob-engine
- [x] Realism metrics: receipt promotions counted; micro-slice snapshot fallback | stream: agents/realism-metrics-fix
- [x] Worker gate lease guard (dirty main checkout fails) | coordinator
- [x] Held-out 5-stage funnel autopsy (loss = no_spec_submitted 19/23, not coverage) + shopflow owner/cart hardening -> held-out unified 25/58 @100% | stream: agents/heldout-lift
- [x] Stale parity-diff worktree removed (plan archived to /tmp/opencode/PARITY-DIFF-SEED1.archived.md) | coordinator
