# Stream backlog (parallel dispatch queue)

Rule: keep at least **3 active streams** while any `ready` task has a free lease.
One stage per stream; split tasks that touch >2 files or span >1 milestone.
Leases are exclusive: a task may start only if its files are not held by an active stream.

Format:
`- [ ] <task> | status: ready|active|blocked | lease: <files> | deps: <task ids or -> | stream: <branch or ->`

## Active (2026-11-24, 11:15)

- [ ] `spec-authz` — canonical actor-echo authz jq + fingerprinted 5xx SQL proof; delete the two bounded fallbacks; add monorepo admin readback | lease: deterministic-specs, deterministic-engine, probes/authz, probes/injection, execution.ts (fallbacks only), monorepo fixture, tests | stream: agents/spec-authz
- [ ] `persona-binding` — hard per-request persona scope `Map<workerId,Map<personaHandle,IsolatedSession>>`; served-store table; invalidate mismatched evidence | lease: broker, surface-engine, probes/context, tests | stream: agents/persona-binding
- [ ] `retest-receipts` — patch retest + benchmark-live onto receipts/recipes, then delete the legacy VM | lease: patch-workflow, floor-recipe-engine (retest), scripts/benchmark-live.ts, replay-verifier, replay-spec, tests | stream: agents/retest-receipts
- [ ] `gap-validation` — validate each coded proof gap against the Layer-1 transcript per route | lease: agent-session, tests | stream: agents/gap-validation

## Ready (dispatch when a lease frees)

- [ ] Capability lane: `api-jwt-alg-none` (JWT boundary), `giftcard-race` (h2 race), `coupon-reuse` (workflow), `inventory-oversell` (race/stateful) — worth ~+4–5 held-out | lease: probes/*, deterministic-engine/specs | deps: spec-authz | stream: -
- [ ] #2 blind SQLi + chain leg 3/3 | lease: probes/injection, deterministic-engine | deps: spec-authz | stream: -
- [ ] Wire `onProofObligation` + `assignedTargetRoutes` + early-exit stat into `execution.ts` | lease: execution.ts | deps: spec-authz | stream: -
- [ ] Profile-aware no-token watchdog (28 s aborts cost 552 turns) + demote unstarted trial duplicates (287 turns) + planner coverage assert | lease: execution.ts | deps: spec-authz | stream: -
- [ ] Tier-1 smoke calibration study (8 varied builds vs reference) | lease: scripts/smoke-agentic.ts, traps | deps: persona-binding | stream: -
- [ ] Pre-existing suite: `tests/v5-engine-coverage.test.ts` 2 failures (content vs template param pick; OR-branch baseline) | lease: tests + engine | deps: - | stream: -
- [ ] Pre-existing hang: `tests/v4-m4-surface-orchestration.test.ts` file-level teardown >15 min | lease: tests | deps: - | stream: -

## Blocked (needs a test-migration stream first)

- [ ] `browser-vm-delete` — delete the remaining `browser_chain` interaction half of the legacy VM. Blocked: five e2e suites drive navigate/fill/click/dom-sink proofs through `verifyReplaySpec` directly (v3-protocol-browser, v4-e2e T2-05e/T3-05/T3-20, v4-m2 M2.6); each must move onto a `browser_sink` envelope + real `runBrowserSession` before the branch can go. | status: blocked | lease: replay-verifier, tests | stream: agents/cut3d-browser-retire

## Sequence after the current batch

1. Persona fix → **Tier-1 smoke (~6 min, ~$1.30, precision trap)** → full dev+held-out agentic matrix (serialized).
2. Certificate erratum: 26/58 vs 28/58 per the bisect outcome.
3. Capability lane (4 named misses), then #2 blind SQLi/chain.
4. Engine-lane cleanup behind it (watchdog profile, trial demotion, coverage assert).

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
