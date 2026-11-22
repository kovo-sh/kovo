# Guardian v5 — Active Build Roadmap & Ownership Board

**GOAL (binding):** Complete v5 such that every release gate below passes, measured on `main`, with 0 false positives and 0 benchmark hardcoding:
- xben-25 ≥ 23/25; held-out-saas ≥ 18/20 with 0/6 decoy FPs and ≥ 14/20 verified patches
- realistic-bench dev: High/Critical recall ≥ 65% grey-box / ≥ 80% white-box; precision ≥ 95%; decoy FP ≤ 5%; chain completion ≥ 50%
- realistic-bench salted held-out: within 10% of dev recall, precision ≥ 95%, 0 unattributed FPs
- 100% of v2/v3/v4/v5 unit, boundary, E2E and Board UI suites; 0 skips; 0 Docker orphans
- `VERIFICATION-v5.md` records every before/after iteration honestly

**Swarm lanes (parallel, exclusive leases):**
1. **Engine recall** — probes/specs/state-graph; owns `benchmark-probes.ts`, `surface-engine.ts`, `benchmark-specs*.ts`, `execution.ts`, `store.ts`, `phase0-recon.ts` (one stream at a time per file).
2. **Orchestration & UI** — board tools/posters/warm specialists; owns `agent-session.ts`, board components, `schema.ts`.
3. **Validation & docs** — gate suites, agentic matrix evaluation, `VERIFICATION-v5.md`; owns `tests/**` and docs, never engine files.
4. **Integration** — coordinator merges each stream, re-runs xben/held-out/realistic after every merge, and reverts any change that loses a floor.

**Sources:** [`plans/v5.md`](v5.md) (M0–M6), [`plans/message-board.md`](message-board.md) (M5 sub-spec)
**Status snapshot:** 2026-11-22 (v4/M7 final gates met on merged main @ `9793d2d`: xben 25/25, held-out 20/20, patches 20/20; v5 M0/M1/M2/M5 running)
**Rule:** one exclusive file lease per stream. A stream must not edit another stream's files. New work is added only by taking an unowned file or by explicit hand-off.

---

## 1. Milestone Board

| # | Milestone | Objective (short) | Status | Owner / worktree | Depends on |
|---|---|---|---|---|---|
| **M0** | True E2E realistic-bench harness | Drive real `Execution` loop, baseline scorecard, `benchmark:realistic` CLI | **DONE** (deterministic baseline; agentic run needs model profile) | `m5-m0` / `agents/m0` | — |
| **M1** | P0 wiring & correctness | broker/browser args, second-order/OOB canaries, dedupe + route templates, specialist routing/skills, `InlineVerifyFeedback` + Phase-3, guard/sanitizer, CVE semver | **DONE** (merged) | `m5-m1-core`, `m5-m1-static` | M0 baseline |
| **M2** | State graph, recon, auth/session | endpoint_params/api_dependencies, soft-404/auth recon, state-graph crawl, jars/CSRF/subdomain/401/circuit | **DONE** (2.1–2.4 merged) | `m7-spa`, `m5-m2-auth`, `m5-m2-state` | — |
| **M3** | Real-world probes & verifiers | CSRF state-change, webhook forgery, open redirect, write-BOLA, race setup, noise normalization | **RUNNING** | `m5-m3-probes`; spec contracts merged (specs2) | M1-core for verifier/schema additions |
| **M4** | Templates, AST, SAST→DAST, Patch Gate 6 | 2021–2026 corpus, multi-framework AST, bridge, real patch retest | **DONE** (merged; execution/recon wiring pending) | `m5-m4` / `agents/m4` | — |
| **M5** | Swarm Message Board + Board UI | schema/store/SSE/UI, deterministic posters, warm specialists, operator routing | **DONE** (UI, tools, posters, warm lifecycle merged) | `m5-board`, `m5-board2` | — |
| **M6** | Hill-climb + anti-overfitting + v5 gate | dev seeds, salted held-out, `VERIFICATION-v5.md` | **READY** (v4 baseline met; awaits M0–M5) | — | M0–M5 |

---

## 2. Current Parallel Streams (all exclusive leases)

| Stream | Worktree | Files owned | Maps to |
|---|---|---|---|
| heldout2 (merged) | `m7-heldout2` | `scripts/benchmark-probes.ts` | M3 probes complete: IDs/state/race/second-order/BFLA; 20/20 held-out, 25/25 xben |
| spa (merged) | `m7-spa` | `src/server/phase0-recon.ts`, `src/server/surface-engine.ts` | M2.2/M2.3 done: route maps, soft-404, auth pass, YAML/$ref, tRPC; `normalizeDiscoveryTemplate` |
| specs2 (merged) | `m7-specs2` | `scripts/benchmark-specs*.ts` | M3 benchmark synthesis + identifier-bound authz: realistic precision 100% (dev 17/172, held-out 15/171), 0 unmatched/decoy FPs |
| m3-probes | `m5-m3-probes` | `scripts/benchmark-probes.ts`, `src/server/surface-engine.ts` | M3 probes: CSRF state-change, webhook forgery, open redirect, write-BOLA, NoSQLi, noise tolerance |
| m4 (merged) | `m5-m4` | `scripts/transpile-nuclei-templates.ts`, `src/templates/**`, `worker/**`, `semantic-audit.ts`, `cve-broker.ts`, `patch-workflow.ts`, `surface-engine.ts` | M4 done: 1,724 templates / 492 CVEs ≥2021, multi-framework AST, bridge, Gate 6 |
| orch | `m7-orch` | `scripts/benchmark-live.ts`, `benchmark-recall.ts`, `benchmark-env.ts`, `benchmark-core.ts`, `benchmark-realistic-matrix.ts` | M6 speed/budget + all-patches attribution |
| m0 (merged) | `m5-m0` | `scripts/benchmark-realistic.ts` (new), `package.json`, `tests/v5-m0-*.test.ts` | M0 |
| m1-core | `m5-m1-core` | `src/server/execution.ts`, `canary-broker.ts`, `dedupe.ts`, `agent-session.ts`, `replay-verifier.ts`, `skills.ts`, `src/skills/**`, `tests/v5-m1-*.test.ts` | M1.1, 1.2, 1.3 (dedupe), 1.4, 1.5 |
| m1-static (merged) | `m5-m1-static` | `worker/analyzers.ts`, `src/server/semantic-audit.ts`, `src/server/cve-broker.ts`, `tests/v5-m1-static.test.ts` | M1.6 done |
| m2-auth (merged) | `m5-m2-auth` | `src/server/broker.ts`, `scoped-browser.ts`, `persona-auth.ts`, `approval-judge.ts`, `tests/v5-m2-auth.test.ts` | M2.4 done |
| board-ui (merged) | `m5-board` | `src/domain.ts`, `src/actions.ts`, `src/server/schema.ts`, `src/server/store.ts`, `src/components/run-board.tsx` (new), `run-workspace.tsx`, `run-state.ts`, `src/app.css`, SSE route, board tests | M5 Phase 1 done |

Retired/merged: `agents/heldout2` (v4 climb: 20/20 held-out, 25/25 xben, 20/20 patches), `agents/rb` (realistic-bench hardening), `agents/docs` (VERIFICATION-v4), `agents/m0` (M0 harness + isolation), `agents/m1-static`, `agents/m1-core`, `agents/m2-auth`, `agents/m2-state`, `agents/spa`, `agents/recon2`, `agents/board-ui` (M5 Phase 1), `agents/board-tools` (board tools), `agents/specs2` (M3 synthesis + contracts), `agents/orch`, `agents/m4`, `agents/docs-v5`.

Open discrepancy: held-out `allPatches=regressed` is a phantom — fresh synthesis re-confirms always-on GraphQL introspection and credits it to both GraphQL challenges. Per-patch retests are 20/20 fixed. The orchestration stream owns replaying baseline attributed specs for the all-patches pass.

---

## 3. Conflict Rules (binding)

1. **No cross-lease edits.** If a fix needs another stream's file, post the requirement to the coordinator instead of editing.
2. **`src/server/execution.ts` is M1-core's.** Board posters (M5 Phase 1b) are wired after M1-core merges, by a short follow-up stream.
3. **`src/server/store.ts` is board-ui's** until Board Phase 1 merges. M2.1 (`sample_resource_id`, `updateEndpointCoverage`) lands after that, as a small additive migration.
4. **`src/server/phase0-recon.ts` is spa's.** M1.3's `normalizeDiscoveryTemplate()` and M2.2/M2.3 checks are spa deliverables.
5. **`src/server/replay-verifier.ts` is M1-core's.** M3 verifier kinds are a post-M1 follow-up.
6. **`benchmarks/realistic-bench/**` is stable** (merged, 142/142). M0 consumes it read-only; changes need a new lease.
7. **Merge cadence:** merge each stream to `main` as it reports, run `npm run check` + its tests, then re-run the three benchmarks before the next dependent stream starts.

---

## 4. Sequencing

```
M0 (harness) ──┐
M1-core ───────┼─▶ M3 (probes/verifiers) ─┐
M1-static ─────┤                          ├─▶ M6 (hill-climb + held-out + v5 gate)
M2-auth ───────┤                          │
spa (M2.2/2.3) ┘                          │
board-ui (M5 P1) ──▶ M5 P1b posters (after M1-core) ──▶ M5 P2/P3 warm specialists
M4 (templates/AST/bridge/patch) ──────────┘   (after M1-static)
```

---

## 5. v4 Carry-Over Baseline (M6 starting point)

| Gate | v4 result | v5 target |
|---|---|---|
| xben-25 | **25/25 (100%)**, 0 FP, 25/25 signals | ≥23/25 |
| held-out-saas | **20/20 (100%)**, 0/6 decoys, **20/20 patches fixed**, allPatches=fixed | ≥18/20, ≥14/20 patches |
| realistic-bench dev | **78/172 matched (45.3%), precision 100%**, 0 decoy/unmatched FPs; 9 cells at concurrency 9 | H/C recall ≥65% grey-box / ≥80% white-box, precision ≥95% |
| realistic-bench held-out | **62/171 matched (36.3%)**, 98.4% precision (**1/63 decoy FP**, under investigation), 0 unmatched; dev→held-out gap **+0.3 pp** | within 10 pp of dev; decoy FP ≤5% |
| Gate suites | 519/519, 0 skip | 100% + v5 suites |

Known v4 blockers carried into v5: trigger quality on real apps; authz ID-binding precision; patch attribution ambiguity on shared `/graphql`; budget exhaustion on phlow-style flows.

### Agentic (`Execution`) baseline — acme-saas seed 1, grey-box

| Run | Wall | Spend | Confirmed | Precision | Notes |
|---|---|---:|---:|---:|---|
| deterministic | 11 s | $0 | 0/22 | 100% | 43 endpoints discovered, no probing |
| agentic, 10 min | 600 s | $0.17 | 0/22 | 0% (1 unmatched) | 65 facts, 24 steps, 12 oracle events, 3 worker bootstrap failures |
| agentic, 20 min | 1200 s | $0.47 | **2/22 (9.1%)** | 66.7% | planted legacy-auth-bypass + inbox BOLA; 1 novel admin-activity BFLA (oracle-evidenced, not planted) |

Agentic reality: 59 endpoints, 663 requests, 43 oracle impacts, 7 findings persisted / 3 submitted. Wall-clock, not `--budget-usd`, is the limiter. Recurring **worker bootstrap failure** (3–4 assignments, 0 turns) and the **single-process data-dir lock** block parallel cells; both have owners (M1-core, M0 harness isolation).

### M6 agentic matrix (6 cells, Docker, isolated data dirs, $5 & 20 min caps, concurrency 3)

| Metric | Value |
|---|---|
| Confirmed | **12/117 (10.3%)** |
| Precision | 66.7% (5 unmatched, **1/39 decoy FP**) |
| Cost | **$1.848 total, $0.154/finding** |
| Matrix wall | 2065 s (cell-wall sum 5608 s) |
| Funnel | 117 → 71 surface → 31 hypothesis → 24 signal → 13 spec → 12 confirmed |
| Assignments | 37 completed / **24 failed (39.3%)** |
| Splits | dev 5/59 (8.5%, 55.6% precision); held-out 7/58 (12.1%, 77.8%) |

Root cause of the worker failures: Docker removal race in `src/server/worker-backend.ts` (`--rm` + explicit `rm --force` + double removal on close) → daemon "removal already in progress", session failed, runs can end `complete` while truncated. Dominant funnel stall: **surface → hypothesis (43.7%)**, then spec synthesis.

---

## 6. Milestone Acceptance (condensed)

- **M0:** `npm run benchmark:realistic -- --app acme-saas --seed 1 --mode grey-box` completes, emits valid scorecard JSON+MD, 0 orphans, `tests/v5-m0-*` green.
- **M1:** wired args end-to-end; canary mint→OOB→cross-persona surface correlation; dedupe preserves all 14 spec kinds + `(method,param)`; 100% skill-slug resolution; routing fixtures; guard≠sanitizer; semver `affectedRange`.
- **M2:** soft-404 calibration, authenticated Phase-0, JS chunk recursion, template-deduped crawl, subdomain cookies/rotating CSRF/401 refresh, per-route circuit breaker, local-lab approvals.
- **M3:** new probes/verifiers confirm vulnerable fixtures and stay silent on hardened decoys; noise-normalized SQL diff.
- **M4:** ≥2021 CVEs prioritized; no appliance templates on Express; NestJS/Express/FastAPI call graph; Gate 6 never `passed` when skipped.
- **M5:** Board tab replaces Coordinator; redaction/scope-taint/injection-boundary tests; provenance; deterministic posters; warm specialists; A/B vs baseline on cost/confirmed.
- **M6:** `VERIFICATION-v5.md` with before/after per milestone, dev vs held-out gap ≤10%, 0 unattributed FPs, full gate transcripts.
