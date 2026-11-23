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
| realistic-bench dev | **115/172 matched (66.9%), precision 100%**, 0 decoy/unmatched FPs | H/C recall ≥65% grey-box / ≥80% white-box, precision ≥95% (G4 MET) |
| realistic-bench held-out | **111/171 matched (64.9%)**, precision **100%**, 0 decoy/unmatched FPs; dev gap **−2.0 pp** | within 10 pp ✓ |
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

---

## Consult log (Antigravity second opinions)

### 2026-11-22 — post-50% realistic climb

- **Threshold:** realistic dev 86/172 (50.0%), held-out 87/171 (50.9%), 100% precision; release gate 980/980.
- **Reviewer top points:** (1) broker pre-redaction secret fingerprints; (2) fresh/non-consuming resources for workflow/race/CSRF; (3) real BFLA DELETE + state/role delta; (4) split-echo command-injection matching; (5) cache two-actor / JWT refresh alg:none / webhook inline-key.
- **Accepted:** #1 `secretMatches` (merged `e18a775`); #2–#5 routed to climb2. Recommended gate split (deterministic vs real `Execution`) and the procedural-vs-agentic divergence risk adopted into M6 reporting.
- **Rejected/deferred:** renegotiating the 65% gate (65% judged achievable without app redesign); business-logic procedural heuristics (assigned to agentic/white-box instead).
- **Follow-ups filed:** deterministic Phase-1.5 sweep inside `Execution` (exec-hybrid stream); identifier-bound checks for LLM-authored specs.

### 2026-11-22 — negative Phase-1.5 result (agentic divergence)

- **Threshold:** Phase-1.5 sweep-on 3/59 at 60% precision vs same-session sweep-off 3/41 at 60%; `Execution --no-llm` 0/59 while the procedural pipeline scores 50%.
- **Reviewer root cause:** the 50% loop lives in `scripts/benchmark-*` (deterministic hypothesis enumeration + identifier-bound spec synthesis + ReplayVerifier); inside `Execution`, `surface-engine` only emits anomalies, so `--no-llm` can never submit a spec. The 12-endpoint/90 s half-bridge added noise without closing the loop.
- **Accepted:** rebuild the deterministic engine in `src/server/` (risk-ranked full surface → probe → spec → verifier), persist only verified findings, hide confirmed pairs from specialists, and treat real `Execution` as the primary product gate.
- **Rejected:** merging the hybrid Phase-1.5 sweep (no lift, precision regression).
- **Follow-up:** `engine-port` stream; interim framing = deterministic 50% / agentic 12%, not a shippable gate.

### 2026-11-22 — engine-port: deterministic closed loop inside `Execution`

- **Threshold:** real `Execution --no-llm` 0/59 → **25/59, 100% precision, 0 decoy/unmatched FP** (3-app realistic dev seed 1, grey-box, docker); agentic same cells **26/59, 100% precision, $0.206**. Deterministic vs procedural surfaces are now separate but both measured.
- **Reviewer top points:** (1) conventional REST wordlists are overfitting-prone; prefer evidence-derived/JS-router discovery and gate wordlists to local-lab; (2) unlock Tier-3 local-lab first (PATCH/PUT/DELETE + rce/race) for +8–12; (3) reserve wall clock for specialists and run the fast wave first; (4) store dedupe by origin+CWE loses distinct same-class endpoints; hide-confirmed must not cancel chain steps.
- **Accepted:** #1 wordlist gated to local-lab (public targets use discovered routes only); #3 deterministic pass kept at 240 s in both modes (a measured 180 s agentic cap lost 3 confirmations); #4 conservative chain/dependency guard on step cancellation; #2 and the store-dedupe fix filed as follow-ups for the next tier/dedupe streams.
- **Rejected/deferred:** rebuilding the whole dedupe key in `store.ts` inside this stream (out of ownership; the per-endpoint persistence workaround is temporary and documented); workflow/business-logic heuristics stay with specialists.
- **Commit:** `agents/engine-port` (see stream report).

### 2026-11-22 — engine-port threshold: product deterministic floor

- **Threshold:** real `Execution --no-llm` 0/59 → **25/59 at 100% precision**; agentic 25/59 at 100%, 0 decoys/unmatched, $0.255. Floors: xben 25/25, held-out-saas 20/20 + 20/20 patches.
- **Reviewer accepted:** conventional REST expansion only on local-lab; keep 240 s deterministic budget (180 s measured worse); preserve chain steps; freeze engine-confirmed class families from specialists.
- **Reviewer rejected:** broad wordlist discovery on public targets; benchmark-specific literals.
- **Next (owners):** Tier-3 local-lab unlock (harness now sets tier 3 for realistic grey-box), proper structural dedupe key, JS/router surface discovery, generic race/workflow/JWT/cache/webhook probes.
- **Procedural position:** dev 111/172 (64.5%), held-out 109/171 (63.7%), 100% precision — one confirmation short of the 65% gate.


### 2026-11-22 — procedural gate crossed; freeze decision

- **Threshold:** dev **115/172 (66.9%)**, salted held-out **112/171 (65.5%)**, 100% precision, 0 decoys/unmatched; xben 25/25; held-out-saas 20/20 + 20/20 patches. G4 (≥65%) MET.
- **Reviewer verdict:** **freeze v5 now** with two scorecards — (A) real `Execution` (--no-llm 25/59; agentic 28/59, 100%, 0 worker failures) and (B) deterministic engine harness (procedural results). Document the ~19 pp convergence gap and the temporary specialist scope guard; neither is release-blocking.
- **Accepted:** freeze; two-scorecard framing; Tier-3 safety not blocking; scope guard documented as a v5.0 precision guardrail.
- **Follow-ups (v5.1):** port remaining procedural engine converters + full surface ingestion into `src/server`; replace scope guard with ReplayVerifier proof-strength guards; fix agentic wall-clock allocation/opsportal early stop; salted/white-box Execution matrices.


### 2026-11-22 — engine-port reverted; v5.0 freeze

- The in-`Execution` deterministic engine delivered 25/59 no-LLM and 28/59 agentic at 100%, but broke **25 existing tests** (planner budgets, specialist tool scopes, multi-trial, M1 fallback). It is preserved on `agents/engine-port` for v5.1; **not shipped**.
- Fixes kept: workflow-quantity synthesis restored to dispatch; DELETE/multipart/RCE escalation ordered before local-lab auto-approval; Tier-3 safety/containment merged.
- Final v5.0: procedural dev **115/172 (66.9%)**, held-out **111/171 (64.9%)**, 100% precision, 0 decoys/unmatched; xben 25/25; held-out-saas 20/20 + 20/20 patches. Product `Execution`: 7/59 agentic (11.9%), `--no-llm` 0/59 — honest gap documented for v5.1.

### 2026-11-22 — engine-port integration plan (v5.1)

- **Slices:** (1) standalone engine modules + structural dedupe key `(origin, endpoint, method, param/resolver, cwe)`; (2) explicit `deterministicOnly` path outside the M1 fallback, verified-only persistence + `det_lead` facts; (3) non-blocking concurrent agentic lane behind a default-off flag with seeded-step guard, 30%/180 s cap, K=6/budget isolation, no step cancellation; (4) replace specialist scope guard with ReplayVerifier proof-strength + endpoint binding; (5) flip flag on after parity port.
- **Accepted traps:** never auto-cancel specialist steps or hide confirmed routes (chains!); inject read-only “Already Confirmed” context; preserve white-box `static_verified`; persist unconfirmed leads; per-endpoint structural dedupe.
- **Gate before flag flip:** full suite green with flag forced ON, dynamicStepBudget/K=6/fallback invariants, `Execution --no-llm` ≥25/59 at 100%, agentic strictly additive at ≥95% precision with ≤10 pp held-out gap, 0 orphans, legacy floors.
- **Proceeding:** Slices 1–2 launched in `m5-integrate-port`; Slices 3–5 gated on their results.

### 2026-11-22 — engine-port integration architecture (v5.1)

- **Question:** safest way to re-land the deferred deterministic engine after 25 regressions.
- **Reviewer plan (accepted):** 5 slices — (1) standalone engine modules + structural dedupe key; (2) explicit `deterministicOnly` path outside M1 fallback with verified-only persistence + `det_lead`; (3) non-blocking concurrent lane behind default-off flag with seeded-step guard, 30%/180 s cap, budget/K=6 isolation; (4) replace specialist scope guard with ReplayVerifier proof-strength + endpoint binding; (5) flip flag and retire duplicate script logic.
- **Accepted traps:** never cancel specialist steps or hide confirmed routes (chains); inject read-only "Already Confirmed" context; preserve white-box `static_verified`; per-endpoint dedupe; keep late OOB leads.
- **Deferred:** Slices 3–5 until 1–2 clear the full gate.
- **Owner streams:** integrate-port (1–2), verifier-guards (4 foundation), compat-audit (failure classification for 3).

### 2026-11-22 — meta-process P0 + security sprint

- **Meta-process (accepted):** freeze harness-only recall work; report `Execution --no-llm` + agentic increment on dev and held-out; split monolith probes into per-class modules for structural parallelism; build inner loop (`worker-gate.sh`, `bench-slice.sh`, `--reuse-recon`).
- **Security audit triage (all accepted):** HIGH (1) auto-approval path-prefix reuse → exact single-use context-bound approval ledger; HIGH (2) `--repo` symlink escape → link-free copy, `lstat`/`O_NOFOLLOW` walkers, realpath-contained patch writes; MED (3–8) bootstrap-only session issuance, PSL/Clerk host allowlist, no-follow credential POSTs, WS/WebRTC blocking, DNS-rebinding checks, sandbox-by-default; MED (9) 0700 telemetry + non-root lab container; MED (10) parsed-JSON/multipart fast paths, 64 KiB keyword scan, untrusted rationale; MED (11) bounded worker output.
- **Evidence:** security suites 11/11, 10/10, 12/12; boundaries 46/46; Playwright v2/v4/v5-board 9/9 after bootstrap harness fix; realistic seed-42 smoke 39/56 at 100% precision.
- **Kept intentional:** public-target RCE/upload/time-diff replay gates now fail closed without operator pattern or local-lab authorization (binding rule).

### 2026-11-22 — adversarial security re-audit (second pass)

- **Threshold:** independent refutation pass over the 11 merged fixes; 33/33 security tests still pass, but 3 findings remain **HIGH**.
- **Accepted (all):**
  1. **Idempotent-POST pre-approval bypass** — broker skips the Tier-3 gate on a path-substring predicate. Fix: broker authorizes every non-GET through the judge/ledger; read-only POSTs are approved by exact envelope checks only.
  2. **307/308 redirect re-send** — an approved state change is re-sent to a different path without a new grant, and the exchange records the original path. Fix: re-authorize non-GET redirects (or fail closed) and record the final path.
  3. **Registrable-domain widening** — hardcoded suffix list collapses shared-tenant suffixes (`github.io`, `vercel.app`, `s3.amazonaws.com`, `com.co`), so sibling tenants are in scope; form login never validated `loginUrl`. Fix: real PSL data, reject shared-suffix targets, exact-host IdP pins, validate form login.
- **Also accepted:** pin credential connections (deny zero/unknown resolution, no 60 s unknown-safe cache), apply scoped-browser guards to the persona form browser, reject dangling symlinks in `safeResolveUnderRoot`, parse `GUARDIAN_LAB_USER` numerically, per-run telemetry mount, duplicate-JSON-key/gzip/oversize fast-path parity, pattern depth/ID-only wildcards + no pattern coverage of RCE.
- **Deferred to post-Slice-2 (`execution.ts` owner):** per-request-instance grants for identical race bursts, `request_http_batch` approval path, tightening/removing `isSafeIdempotentPost`.
- **Streams:** sec2-approvals (broker/approval-judge), sec2-auth (persona-auth/scoped-browser), sec2-lab (lab-runner/patch-workflow), verifier-guards (approval context for Tier-3 replay).
- **Control:** procedural seed-42 stays 39/56 at 100% precision, 0 decoy/unmatched; product baseline `Execution --no-llm` 0/59, 2 unmatched FP.

### 2026-11-22 — product deterministic floor crossed (0 → 26/59)

- **Threshold:** real `Execution --no-llm` 0/59 → **26/59 (44.1%) at 100% precision**, 0 decoy/unmatched (acme 13/22, shopflow 7/19, opsportal 6/18); control on the same tree 0/59 with 2 unmatched FP. Gate 1086/1086, 0 skips, 0 orphans. Floors xben 25/25, held-out-saas 20/20 + 20/20 patches.
- **Reviewer points (accepted):**
  1. Agentic consumption = **read-only** context: "Already Confirmed (may chain/escalate)" table + top-8/10 `det_lead` summary in the planner prompt; no auto-queued chain steps (preserves `dynamicStepBudget`/K=6). Pair with Slice 4 so novel business-logic/workflow targets are not censored.
  2. Lane deadline **per run**: `min(240 s, 40% of maxDurationMs)`, linked to the run AbortSignal; do not gate the planner; `deterministicOnly` stays unrestricted; fast high-yield probes first.
  3. Diagnose the 44% vs 67% gap with a **4-bucket diff** on seed 1 (`not_in_surface`, `not_probed_before_deadline`, `probed_no_signal`, `signal_no_confirm`) before building parity converters; prior is surface ingestion + converter parity + Tier-3 wiring.
  4. Ordering: **wave-2 security + deferred `execution.ts` items first** (per-instance grants for identical race bursts, batch approval path, remove `isSafeIdempotentPost` with a fast exact-envelope read-only judge path), then Slice 3 behind a default-off flag, then Slice 4, then flip.
- **Rejected/deferred:** per-assignment or planner-shared caps (240 s per-run chosen); auto-queued deterministic chain steps (planner-decided only, for now).
- **Owner streams:** sec2-approvals, sec2-auth, sec2-lab (wave 2), exec-approvals (race/batch grants), parity-diff (bucket classification), verifier-guards (Slice 4 + Tier-3 context).

### 2026-11-22 — parity diff triage (seed 1)

- **Measured:** procedural 38/59 (64.4%) vs product `--no-llm` 26/59 (44.1%); intersection 21, procedural-only 17, product-only 5.
- **Root cause (accepted):** class coverage, not deadline — 24/33 product misses had no probe port for their class; the engine enumerates ~10 intents while `src/server/probes/` ships 8 unused classes. Remaining: surface drops (4, all DELETE/body-only routes), signal→spec converters (3), genuine caps (2).
- **Fixes accepted, in order:** (1) stop dropping briefing routes/DELETE in `execution.ts` + engine DELETE gate; (2) close authz/boolean signal→spec gaps; (3) mass-assignment on PATCH/PUT; (4) wire existing probe classes (`ssti_math`, `command_injection`, `workflow_invariant`, cache, webhook); (5) stored-XSS lifecycle + collection secret scan.
- **Notable:** the product floor is **not** a subset of the harness — 5 targets confirmed by the product had no procedural signal. Treat both scorecards as independent evidence.
- **Caveat carried:** part of procedural parity comes from the conventional route wordlist, so every fix must be re-checked on a salted held-out seed.
- **Owner streams:** surface-filter (`execution.ts`), engine-coverage (`deterministic-engine.ts`/`-specs.ts`), exec-approvals (race/batch grants, merged `7a6dd98`).

### 2026-11-22 — agentic value-add consult (same model: deepseek-v4.1-flash)

- **Diagnosis (reviewer):** the agentic layer is not failing on intelligence first; it is throughput-starved (2–4 assignments per 600 s, $0.14 of $2 spent) and blocked by raw-JSON spec friction (13 signals → 7 specs). Flash-class models do well on short, batched, typed micro-tasks and poorly on 30-turn open exploration plus hand-written jq.
- **Top 5 changes (accepted, in rank order):**
  1. Slice 3 concurrent deterministic lane + **specialists only on hard classes** (det_lead upgrades, business logic/workflow/second-order/race, chains, white-box suspects).
  2. Batched micro-specialists: 8–10 turns, 75–90 s wall, 4–5 concurrent, `request_http_batch` 4–8 probes/turn, parallel read-only tool calls → target 18–28 assignments/cell.
  3. Pre-packaged ≤1.5 KB evidence brief per assignment (routes/params/encodings/CSRF, harvested persona IDs, baseline status/keys, producer + read-back routes) so turn 1 probes instead of exploring.
  4. **Typed proof-compiler tools** (`prove_authz_read_diff`, `prove_state_mutation_diff`, `prove_business_invariant`, `prove_canary_or_redirect`) that compile identifier-bound, proof-strength-compliant specs in TS instead of asking the model for raw JSON+jq; structured 1-turn repair feedback; hard settlement at N-2 turns.
  5. Typed coordinator artifact registry (leaked IDs, token handles, second-order canaries, draft resources) + 4 explicit chain archetypes (leak→authz, token→BFLA, plant→trigger, create→skip/mutate).
- **Measurement plan (accepted):** 6-cell A/B (`--no-llm` control vs agentic) across 3 apps × dev seed 1 + one salted held-out seed, plus one white-box cell; report net additive confirmed by class, precision/decoy FP, chains, assignments/cell, signal→spec rate, marginal $ per additive vuln. Default-ON bar: **≥ +8–10 pp additive** on both dev and held-out, ≥95% precision, chains ≥3/6, ≤$0.35/additive vuln.
- **Kill switch (accepted):** if after all five changes additive lift stays <+5 pp on dev+held-out, or precision <95%/decoy FP >0, or variance exceeds the mean lift, agentic becomes opt-in (`--deep`) with `--no-llm` as default. White-box evaluated separately (Flash gains more from exact source handlers).
- **Owner streams:** agentic-prompts (`agent-session.ts`), agentic-lane (`execution.ts`, Slice 3 + tool handlers), proof-tools (typed compilers), artifact-registry/chains (after lane).

### 2026-11-22 — agentic fast-loop consult (traces, snapshots, parallelism)

- **Decision:** agentic is non-negotiable; 30–60 min production runs are acceptable. Iteration speed must come from trace capture + snapshot resume + parallel cells, not from shortening production runs.
- **Primary inner loop (accepted):** **resume-from-snapshot at post-floor/turn N with the live model** (15–45 s) for prompt/tool/proof-compiler/chain changes; fresh reduced live runs (60–120 s) for planner/concurrency/wall-clock changes; full LLM-response VCR replay (1–3 s, $0) as the CI regression gate for code below the LLM.
- **Trace format (accepted):** `.guardian/traces/<id>/` = `manifest.json` (schema/git/model/params/prompt+tool hashes) + content-addressed `blobs/<sha256>` (prompt prefixes, tool schemas, ≤4 KiB sanitized previews) + `events.jsonl` with 4 record types (turn, tool_result, planner_decision, lifecycle). Redaction to deterministic placeholders (`<<SECRET:persona_a:cookie>>`, `<<CANARY:c_19>>`); live secret map stays in memory and is re-bound on resume.
- **Snapshot/resume (accepted):** checkpoint at phase/assignment/planner-round boundaries only (never mid-turn); SQLite snapshot (`VACUUM INTO`) + coordinator state (artifact registry, planner round, k6 streak, budget, scope/goal revisions, spend) + target rehydration spec (app/seed/mode/mutating log); stamp schema/migration/contract versions and fail fast on incompatible resume.
- **Metrics (accepted):** ΔConfirmed by hard class, precision/decoy FP, time-to-first-probe, assignments/10 min, signal→spec conversion, wasted-turn ratio, batching efficiency, context-growth slope, $/additive vuln. Two mandatory gates per change: (1) precision ≥95%, 0 decoy FP, no `--no-llm` regression; (2) non-regressing ΔConfirmed with signal→spec ≥80% **or** ≥15 assignments/10 min.
- **Parallelism (accepted):** 6–9 isolated cells (own data dir, ephemeral app/canary ports, WAL SQLite), 4–5 specialists each; warm worker container per cell; shared Chromium per cell with per-persona contexts; global OpenRouter semaphore (~28 in-flight) with 429 backoff; RAM watermark guard; cell-labeled reaper for 0 orphans.
- **Cadence (accepted):** Tier 0 seconds (worker-gate + VCR), Tier 1 60–90 s (post-floor snapshot, 6–9 hard-class slices), Tier 2 5–6 min fresh 6-cell smoke, Tier 3 12–18 min 12-cell dev+held-out+white-box. Every merged prompt/tool/planner batch needs one fresh Tier-2; flag flips need a fresh Tier-3. Never snapshot salted held-out; rotate dev seeds.
- **Production budget (accepted):** 45-min shape = recon 0–1, concurrent deterministic lane ≤5 min, Wave 1 hard-class breadth 1–18, Wave 2 det_lead/chains/second-order 18–32, Wave 3 variant/deep crown-jewel 32–41, final refinement 41–45; coverage ledger + wave novelty early exit + per-wave spend partitions.
- **Owner streams:** trace-capture + trace-metrics; snapshot-resume (`execution.ts`/`store.ts`); parallel-matrix + warm workers; agentic-prompts (running); agentic-lane (Slice 3).
