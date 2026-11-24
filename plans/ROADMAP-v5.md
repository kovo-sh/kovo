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

### 2026-11-22 — product floor +9pp; held-out gap flagged

- **Threshold:** `Execution --no-llm` dev seed 1 **26/59 → 35/59 (59.3%) at 100% precision**, 0 decoy/unmatched. Salted held-out seed 1000042: **22/58 (37.9%)**, 100% precision. Dev→held-out gap **21.4pp**.
- **Reviewer verdict (accepted):** the generalizable floor today is ~38%, not 59.3%; the dev surplus tracks the conventional noun wordlist. Do **not** benchmark agentic lift on a wordlist-inflated floor.
- **Floor gate adopted now:** 100% precision on both splits; **|dev − held-out| ≤ 10pp (target ≤ 8pp)**; **≥ 50% on salted held-out with noun wordlists OFF**.
- **Diagnostic (accepted, <10 min):** run seed 1 and 1000042 with `conventionalWordlist` OFF vs ON; split the gap into (a) wordlist inflation, (b) surface-ingestion misses, (c) class-selection overfitting.
- **Generalization work (accepted, ranked):** lossless grey-box OpenAPI/API-ref ingestion (incl. DELETE/PATCH/body-only POST); JS bundle + SPA router extraction; form/link/XHR crawl; response-driven REST sibling derivation; OPTIONS/405/Allow and 400/422 validation-schema hints. Benchmarks turn noun wordlists OFF (universal paths only).
- **Intent model (accepted):** replace English route/param regexes with structural evidence — method+role matrix, wire format/value shape, one benign canary reflection probe per string param, response/resource signals (secret fingerprints, created-id → downstream action).
- **Priority (accepted):** parallel tracks — Track A surface/intents (phase0-recon + deterministic engine), Track B agentic lane (already running). Sync, then measure agentic vs `--no-llm` on dev **and** held-out against the honest floor.
- **Next measurement (accepted):** 12-cell `--no-llm` matrix = 3 apps × seeds 1,2 + 1000042 + a fresh held-out seed, wordlists OFF; pass = 0 decoy/unmatched, gap ≤8pp overall (≤12pp per app), held-out ≥50%, no class drop >20pp.
- **Owner streams:** heldout-gap (phase0-recon + engine intents), agentic-lane (running), parallel-matrix (running).

### 2026-11-22 — v6 pivot + honest floor baseline

- **P0 pivot:** `plans/better-architecture.md` adopted. Phase 1 (store/WAL/pagination/recover, dedupe, always-on floor, regex de-overfit) and Phase 2–4 streams launched in disjoint worktrees.
- **Wordlist-off floor (new honest number):** dev seed 1 **26/59 (44.1%)**, 100% precision, 0 decoy/unmatched (acme 8/22, shopflow 10/19, opsportal 8/18). Wordlist ON remains 35/59 (59.3%). Salted held-out (wordlists off) 22/58 (37.9%) → **gap 6.2pp**, inside the ≤8pp gate but below the ≥50% held-out bar.
- **Interpretation:** the previous +9pp dev move was largely conventional-noun inflation; the structural intents + declared-surface ingestion hold the held-out floor and narrow the gap. No English route/param heuristics may be reintroduced to recover dev points.
- **Merged:** agentic Slice 3 lane (`3df2821`) — acme seed 1 flag OFF 1/22 → ON 7/22 at 100% precision, $0.39; held-out generalization `ae3308d`.

### 2026-11-23 — hourly v6 architecture check-in (reviewer pane 0:2.1)

- **Trigger:** first hourly architecture review of the v6 pivot (~65% code merged, ~45% wired).
- **Reviewer verdict (accepted):** velocity is good, but the loud risk is "dual-architecture cake bloat" — v6 primitives sit unwired beside the v5 path while `execution.ts` grew 9.5K→10.25K and `store.ts` 4.8K→5.7K. Freeze net-new features; flip defaults and delete v5 paths in the same PR.
- **Accepted ordering:** (1) floor + Layer-1 contract wiring in `execution.ts` (scopePolicy, envMode, approvalLeases, park/resume, floor default-on); (2) verify-loop (expose `guardian_verify`, make it the default agentic proof path, delete the OOB poll); (3) graphwire into recon/store; (4) realism baseline through shipped Execution; (5) Graph Coordinator + v5 deletion.
- **Accepted gates:** Phase 1 = (a) agentic ≥ `--no-llm` on **every** app, dev + salted held-out, 100% precision, and (b) ≥ **+10pp** aggregate lift on dev, ≥ **+8pp** on held-out, plus ≥25–30% agentic on reason-bench while `--no-llm` stays **0/28**.
- **Held-out ruling:** do **not** add deterministic heuristics for race/business_logic/workflow (v5 overfitting trap). Fix only mechanical misses in Layer 2; judge semantic classes on combined Layer-2+3 (`Execution` target ≥60% held-out, ≤8pp gap).
- **Chains:** defer truth-side causal-artifact wiring until verify-loop + coordinator land, then wire credit before the Phase-4 chain gate (≥4/6).
- **Always-on floor traps (accepted):** filter mutating hypotheses under `prod_readonly`; cap staging floor budget 15–25% requests / 60–90 s with run-tag cleanup; a parked HITL item must never block the floor sweep.
- **Deletion gate (accepted):** remove `runChainPlanner`, `ColdGraphCompactor`, `filterHandlersForSpecialist` strips, 6-dry-step kill, keyword escalation storms, synchronous approval waits, and the 4 JSON proof compilers from agentic exposure; **`execution.ts` < 7.5K LOC by end of Phase 4** is a release requirement.
- **Reviewer LOC estimate:** ~75–80% of total product investment carries forward; ~20–25% of backend (~14K LOC) is throwaway — mostly the replay VM/compilers (~5.5K), monolithic orchestrator glue (~4K), tool silos/compaction (~2K), keyword HITL (~1K), brittle lab/benchmark scaffolding (~1.5–2K).

### 2026-11-23 — hourly architecture check-in #2 (post v6-floor/verify-loop)

- **Trigger:** first hour after the always-on floor + script-first verify loop merged; `execution.ts` at 10,557 LOC.
- **Reviewer verdict:** v6 is accreting on v5 rather than replacing it. Hard rule adopted: no feature PR touches `execution.ts` unless it is **net-negative LOC**.
- **Deletion order (accepted):** (1) keyword escalation storms + synchronous approval waits **now** (they corrupt `staging_isolated`/Realism #3); (2) 6-dry-step global kill before the Phase-1 agentic A/B; (3) `filterHandlersForSpecialist` strips before chains; (4) `runChainPlanner` + `ColdGraphCompactor` + `CrossHostSynthesizer` atomically in the Coordinator PR.
- **Metric definition (accepted):** count each `(origin, normalizedRoute, vulnClass, mutatedInput)` once. Report `floor_recall`, `total_product_recall` (deduped union), `agentic_incremental_lift = agent∖floor`, and `floor_preservation_ratio ≥0.95` (target 1.00). Phase-1 gate = 100% precision + preservation ≥0.95 + total ≥ floor on every app + incremental lift ≥+10pp dev / ≥+8pp held-out + reason-bench ≥25–30% with `--no-llm` 0/28.
- **Realism order (accepted):** re-run #2 and #3 immediately after the keyword/sync deletion, then #1; hold #4 until graphwire lands. Wiring bug vs capability gap distinguished by early dismissal (#2), BrokerDenied/leaked entities (#3), 401s/asset scope (#1).
- **Graphwire rule (accepted):** store all routes losslessly, but rank/cluster before probing; suppress speculative sibling/path derivation when AST/declared routes exist; probe order A (sinks/missing guards/git hotspots/CVE) → B (mutating/role-exclusive) → C (sampled/on-demand).
- **Coordinator MVP (accepted):** `graph-coordinator.ts` ~350–500 LOC with `query_endpoints`, `query_program_graph`, `query_facts`, `query_findings`, `dispatch_investigations`; deterministic ~80-LOC scheduler guard outside the LLM; typed chain primitives + explicit chaining round; delete ~1,200 LOC in the same PR (net −700).
- **Red flags accepted:** replay-verifier still has live legacy guards (−49 LOC only); pending_oob must be drained before `writeReport`; floor and agent must share only per-worker cloned sessions.
- **Streams launched:** v6-delete (storms, dry-step, OOB drain, session isolation), v6-fluid (capability bundles), graphwire steering (two-tier ranking).

### 2026-11-23 — agentic precision triage (acme unmatched findings)

- **Result:** both reported unmatched findings were **agentic over-claims**, not missing truth. No targets added (that would inflate recall).
  - Viewer same-tenant `PATCH` is in-policy (object boundary is tenant, not row owner); cross-tenant `DELETE` returns 200 but is a no-op; no oracle event.
  - Plan "mass assignment" echoed the free-tier catalog price (`price:0`), not an injected field; `billing-tamper` was mounted hardened; seat event no longer borrowable.
  - A third pattern (CSRF on `POST /api/projects`) was also an over-claim: `SameSite=Lax` cookie attached regardless of foreign Origin, and only `updateSettings` owns the CSRF oracle.
- **Truth-side fix (merged `93a10e6`):** seat `invariant_violation` fires only when `seats_used` is mutated, so a plan downgrade can no longer borrow another site's impact; `truth/POLICY.md` + `acme-policy.test.ts` pin the object/role/pricing policy. 144/144 benchmark tests, procedural acme 15/22, xben 25/25.
- **Measured after:** acme agentic sample 8/22 at 100% precision, 0 unmatched, $0.259 (stochastic; the engine was not changed).
- **Verifier gaps accepted for immediate fix:** (1) `assessBflaImpact` accepts any 2xx; (2) a denied control is treated as a spec error instead of boundary proof; (3) no role hierarchy (`owner>admin>member>viewer`); (4) mass assignment confirmed by `ok` echo without an impact event; (5) CSRF ignores `SameSite`/bearer.
- **Stream launched:** v6-verifier-harden (replay-verifier) with `expectControlDenied` evidence support and tests derived from the merged policy fixture.

### 2026-11-23 — hourly architecture check-in #3

- **Trigger:** after graphwire/fluid/fts/delete/coordinator-module merges and the over-claim triage.
- **Immediate sanity check (P0):** confirm whether agentic 8–11/22 is **total unified** or agentic-only. If unified and `floor_preservation_ratio < 0.95`, the floor and agent are starving each other inside 600 s — a wiring bug, not a capability result. Standing measurement started.
- **Agentic certification protocol (accepted):** n=3 independent runs per app (dev + salted held-out); gate on **median [min–max]**; gate precision on the **worst** run (min precision = 100%); target recall spread ≤3 targets (≤15pp). A 5–11/22 spread is not certifiable.
- **600 s wall:** acceptable for Phase 1 only if `floor_preservation_ratio ≥0.95`, total median ≥ floor median, and <50% of assignments time out before verification; otherwise P0.
- **Floor determinism (accepted):** a 30 vs 33/59 swing is a determinism bug, not noise. Canonical sort endpoints/probe queues/harvested IDs/persona pairs; audit state-clobbering concurrent probes, breaker ordering, and early `maxDurationMs`. Repeat spread >1 target blocks the gate.
- **Verifier parity (accepted):** the five fixes must live in a shared `oracle-invariants.ts` used by **both** `replay-verifier.ts` and the Layer-1 `verify-rpc` transcript oracle; otherwise `guardian_verify` repeats the over-claims. Add Gap #6 (clean GET readback, never response echo) and Gap #7 (ambient cookie without SameSite=Strict for CSRF; owner-scoped non-public attribute for read-BOLA). Parity test required.
- **Coordinator wiring (accepted):** pages ≤25 compact rows (summary ≤160 chars, raw in artifacts); cross-origin primitives (`origin:'*'`) since `CrossHostSynthesizer` is deleted; audit `runDetail`/`writeReport`/`Store.recover` for `cold_digests`/`synthesizedSignature`/`plannerDoneRound`; measure decideNext edges, chain subset (≥3–4/6), one full 3-app dev run.
- **LOC gate (accepted):** interim **execution.ts <9,500** on coordinator-wire merge; <7,500 reserved for Phase 4 after realism gates. Count net LOC across extracted modules, not just file splitting.
- **Realism order (accepted):** #2 → #3 → #4 → #1, with explicit wiring-vs-capability metrics: #2 `pending_oob_registered ≥1`, `oob_drain_waited_ms ≥15000`, `late_promotions ≥1`; #3 `approval_blocks == 0`, `broker_denied_mutations == 0`, `leaked_entities == 0`, `h2_single_packet_bursts ≥1`; #4 `stored_endpoints ≥2500`, p99 <50 ms, all 4-hop sinks Tier A, `sibling_derivation_suppressed`; #1 route discovery ≥20/24 before judging agent output.

### 2026-11-23 — hourly architecture check-in #4 (floor starvation found)

- **Instrumented measurement:** acme agentic seed 1 → `deterministic_lane.metrics` = `floorConfirmed 5`, `floorRequests 896`, `laneWallMs 85 s`, `floorLeadsConsumed 0`; unified total 8/22 @88.9%. Standalone floor 10–12/22 ⇒ **`floor_preservation_ratio ≈ 0.5`**, and unified total is *below* the standalone floor on that cell.
- **Reviewer ruling (accepted):** delete the lite concurrent lane. Run the **exact same deep floor sequentially first** — dual configs guarantee drift and concurrency causes state clobber/rate/breaker interference. 600 s split: **Phase A floor 150–180 s / ~1,500–1,800 reqs**, Phase B agents 360–390 s with 90–120 s caps and K=4–6, **Phase C 30–60 s reserved** for `pending_oob` + report.
- **No fallback/suppression hack.** Enforce monotonicity by construction: floor findings immutable (`provenance:'floor'`), agents only add net-new or higher-impact chains, never overwrite/downgrade/dedupe-drop a floor finding. Gate remains `preservation ≥0.95`, unified ≥ floor on 100% of runs.
- **Leads P0:** `floorLeadsConsumed=0` with 5 emitted is a wiring bug; fix both sides (fact filter ↔ `buildAssignmentBrief`/`queryFindings`, Round 1 seeds top-M) and add the invariant `emitted > 0 ⇒ consumed > 0`.
- **Next deletion (accepted, after realism #2/#3 baseline):** `v6-retire-dsl` ≥1,800 net LOC — dead `prove_*` agent bindings/JSON compilers/legacy spec prompt guidance (~1,000–1,400) plus legacy Phase-3 DSL refinement queues/fallback/plannerDoneRound glue (~800–1,200), targeting `execution.ts <9,200` now and `<7,500` after probes leave the legacy VM.
- **Phase-1 certification matrix (accepted):** floor n=3 per app dev seed 1 (spread ≤1, target 0) + held-out baseline; unified agentic n=3 per app dev and n=2–3 per app held-out; **worst-run precision 100%**, preservation ≥0.95, leads invariant, median incremental lift ≥+10pp dev / ≥+8pp held-out, reason-bench agentic ≥25% with floor 0/28; plus the Phase-C window carve-out verified before realism #2.

### 2026-11-23 — v6-delete final + realism #3 wiring result

- **Deletions landed:** keyword escalation storms (ALWAYS_HIGH_RISK/AUTH_ADMIN scans) removed; K=6 global kill removed at both sites (dry streak is telemetry only); bounded `pending_oob` drain (45 s, promotes late callbacks, records `oobDrainMs/promotedLate/remaining`); per-worker composite session clones bound into every grant (logout isolates). New modules: `probe-plan.ts`, `oob-drain.ts`, `session-isolation.ts`, `tier3-approval.ts`, `graph-leads.ts`.
- **Graphwire consumption:** engine targets use `selectRankedProbeTargets` (ranked sample + risk fill to the 220/150 cap) with the store kept lossless; code-to-runtime hypotheses seed prioritized, idempotent `det_lead` facts.
- **LOC:** execution.ts 10,543 vs base 10,557 (−14); approval-judge 1,014 vs 1,051 (−37).
- **Realism #3 (wiring signal, not capability):** `staging-concurrency --no-llm` fails at investigation, but **0 leaked entities, 0 tagged orphans, 0 approval requests/leases/parked workers** — env mode + cleanup wiring is healthy; the zero confirms are a capability gap.
- **Floor variance caveat:** 29 vs 33/59 measured on the same base while ~31 concurrent benchmarks ran; treated as possibly **load-induced**, not automatically a code bug. Determinism stream now measures idle vs loaded spreads and replaces wall-clock early exit with request-count termination where load truncates the queue.
- **Follow-up merge:** `9a865b6` (preserve store ordering for the bounded probe set) is committed but not yet in main; merge after the worktree is clean.

### 2026-11-23 — hourly architecture check-in #5

- **Determinism breakthrough (checkpoint `0f9a974`):** idle floor counts `[10,10,10]/[10,10,10]/[9,9,9]` with identical site sets; with 8 CPU hogs loaded the counts are identical (`driftApps=0`). Sequential Phase A (168 s / 1,800 req) restored acme agentic floor to **10/10 preserved**, leads **5 emitted / 4 consumed**, total **11/22 @100%** (was floor 5, leads 0, total 8).
- **Checkpoint protocol (accepted, now in AGENTS.md):** 15-minute commit ceiling; commit code/typecheck/worker-gate before long evals; heartbeat every 15–20 min; reclaim any stream silent >25–30 min with a dirty tree.
- **Provenance (accepted):** keep monotonicity **and** surface `provenance: floor | agent_only | chain_from_floor` in product report and certificate; `agentic_incremental_lift` computed from agent-only/chain findings, not total−floor alone.
- **Phase-1 scope (accepted):** reason-bench **agentic ≥25% moves to Phase 3**; reason `--no-llm == 0/28` stays a Phase-1 gate, with one non-blocking agentic baseline recorded at Phase-1 close.
- **Grader contract (accepted):** `confirmed_findings` may contain only `verificationStatus === 'confirmed'`; `static_only`/`open_proof_gap` go to a separate advisories bucket (≤10/app, never recall/precision); a static item leaking into confirmed counts as an FP. Fix the product boundary, never the grader.
- **Universal default-deny (accepted):** every auth/access/bypass claim needs a transcript-verified denied/challenged control plus a boundary-crossing variant with state/data proof, regardless of label — closes label whack-a-mole (e.g. “2FA bypass” on an account without 2FA).
- **Order confirmed:** determinism → realism #2 → #3 → #4 → #1 → `v6-retire-dsl` (≥1,800 LOC). Do not run the full n=3 matrix until static/advisory separation and the default-deny control land.

### 2026-11-23 — xben restored; held-out-saas regression isolated

- **xben 25/25 restored** (`19a6fdd`): mutating authz specs now emit actor pre-read → low-priv mutation → separate post-read, with `requiredRole` and a function-level observe step; harness parity got the same rule plus a fresh self-service victim and `{id}` placeholder fix. Procedural acme 42 improved 15 → 16/22 at 100%.
- **Held-out-saas regression confirmed on main:** `benchmark-recall --suite held-out-saas` = **18/20 (90%), 0 FP, patches 16/20** vs baseline 9fe4c99 20/20 + 20/20. Funnel reaches 20 specs; failures are confirmation/inference, not discovery.
  - `hos-03`: function-state delta (feature flag) has no protected field for the readback gate.
  - `hos-05`: server action's observable read is a sibling `GET /api/v1/org` not inferred.
  - `hos-02`: patched app not reported fixed (spec/step mismatch after readback change).
  - `hos-09`: shared-endpoint attribution ambiguity → patch retest skipped.
- **Fix stream launched:** `hos-restore` (generic function-state delta evidence, sibling-read inference from the route map, patch/spec reconciliation, mutated-field disambiguation) with a hard gate: **20/20 + 20/20 patches at 100%** without weakening `oracle-invariants`/`replay-verifier`; stop and report if a target cannot be proven honestly.
- **Sequencing unchanged:** provenance merge → realism #2/#3/#4 → `v6-retire-dsl` → certification; held-out 20/20 is a hard regression gate before cert.

### 2026-11-23 — realism #2 (WAN/OOB) measured: capability gap, not wiring

- **Result:** FAIL at `investigation`: 0 TP / 0 FP, 0% recall; floor used 467 requests with 0 confirmed and 0 leads; chain `wan-oob-exfil` 0/3; async false-negative **100%**.
- **Diagnostic:** fixture callbacks `sqli=true, ssrf=false, xxe=false, webhook=false` — the product never triggered the async sinks, so `pending_oob` promotion was **not exercised**. This is not the "run closes early with a relay hit" wiring signature; it is route-shape/probe selection on this fixture (Layer-3 capability).
- **Not claimed:** OOB wiring is neither passed nor failed by this run; it remains covered by unit tests (`v6-verify-loop` fake-clock promotion) and needs an agentic #2 run once the floor/agent can reach the sinks.
- **Next:** realism #3 (staging safety) for the certifiable wiring properties (`approval_blocks=0`, `broker_denied_mutations=0`, `leaked_entities=0`, H2 burst), then #4 (scale/ranking).

### 2026-11-23 — realism #3/#4 measured: safety wiring passes, scale ingestion gap

- **#3 staging-concurrency:** FAIL at investigation (0 TP), but `leakedEntities=0`, no tagged orphans, cleanup 0/0 → staging safety wiring healthy. Capability (write-BOLA/race/checkout) absent. Harness did not emit `approvalBlocks`/`brokerDeniedMutations`/`h2SinglePacketBursts`, so a metrics stream was launched to separate wiring from capability and fail closed on missing metrics.
- **#4 monorepo-whitebox:** FAIL at investigation; **62 persisted / 62 retrieved / 2565 declared**, SAST suspects 0, 4-hop 0/3. This is a fixture↔product wiring gap: the declared catalog is not reaching the store and the 4-hop sinks are not AST-recognizable. Stream launched to fix briefing completeness and fixture AST patterns (no `src/` edits; report if a product bug is proven).
- **Held gates remain:** held-out-saas 20/20 + 20/20 patches, xben 25/25, procedural acme 16/22.

### 2026-11-23 — hourly check-in #7: honest zero lift + proof-conversion cliff

- **Corrected measurement (quiet host, serialized):** floor acme 11/22, unified 11/22 at 100% precision, **0 net agentic targets**, $0.129 of $2, preservation 1.00, leads 4/3, Phase A 145 s. The earlier 12/22 was an `open_proof_gap` advisory leaked by the harness; fixed to submit runtime-confirmed only.
- **Reviewer verdict:** not a model ceiling — a **proof-conversion cliff** (5 candidates → 5 `open_proof_gap`, 0 confirmed) plus **6% budget utilization**. Same model previously confirmed 7–11/22.
- **Structural fixes (accepted):**
  1. Five typed SDK helpers aligned to `oracle-invariants` (`prove_access_boundary`, `prove_persisted_mutation`, `prove_boolean_or_timing_diff`, `prove_oob_callback` auto-registering `pending_oob`, `prove_race_burst` using the HTTP/2 barrier) with machine-readable `rejectedBy`/`missingEvidence` feedback for one-turn repair.
  2. Phase-B utilization: keep K=4–6 saturated, warm workers across assignments, target 12–20 completed assignments and $0.50–1.20 at 600 s, <15% idle.
  3. Restore the post-harden floor regression spec-side: shopflow 11→7 and opsportal 9–10→8 (total 30–33→26) using the xben/hos readback + control_denied pattern.
- **Certification protocol:** do not run the full matrix. Tune acme to ≥14–15/22 (≥+3–4 net-new, ≥50% proof conversion, 100% precision), smoke shopflow/opsportal at ≥+2–3 net-new each (aggregate ≥+6 targets / +10pp), then certify.
- **Realism #2/#3:** real wiring bugs; `prove_oob_callback` and `prove_race_burst` should register `pending_oob` and execute the h2 barrier. Keep Phase-1 grey-box certification decoupled from Phase-3 realism gates, but fix both in this wiring sprint.
- **Streams launched:** sdk-helpers, floor-regress, phaseb-diag (read-only diagnosis).

### 2026-11-23 — hourly check-in #8: +9.1pp on acme, precision is the only gate

- **Correction adopted:** K=6 acme 13/22 is **+9.1pp** over floor 11/22 (not +2pp), with 18 assignments queued/paused and 75% of budget unspent. Keep the +10pp dev / +8pp held-out bar; do not lower it.
- **Precision first:** 3 unmatched FPs at K=6 (100% → 81.3%). Audit order: (1) repair-loop reward hacking (`control_denied` pairing / `expectControlDenied:false`), (2) concurrent cross-talk (`before!=after` caused by another worker — require this script's nonce in `after_get`), (3) SDK helper bypass of host transcript validation.
- **Throughput second:** drive `verified_tp_per_100s_phase_b`; cut median assignment wall ~150 s → 70–90 s (warm workers across assignments, cap single-step assignments, check provider-stream stalls) to drain 12 ready/6 paused in the same window.
- **Floor-regress before certification:** finish 26 → ≥31/59 so agentic lift is genuine, not picking up targets the floor lost to the hardening regression.
- **Realism #2:** decouple from Phase-1 cert, but Layer-2 `ssrf_canary`/`xxe_canary` must also register non-immediate canaries into `pending_oob` so the fixture passes end-to-end; do not certify #2 via SDK unit tests alone.
- **Structural red flags accepted:** per-assignment entity namespace + nonce-matched readbacks; host recomputation is the trust boundary (SDK is ergonomics only); check F3 still emits genuine leads on shopflow/opsportal/held-out; lock `v6-retire-dsl` (≥1,800 LOC) immediately after Phase 1.

### 2026-11-23 — floor restored to 31/59; certification run started

- **Floor (product --no-llm, serial, wordlist off, seed 1):** **31/59 (52.5%) at 100% precision**, 0 decoy/unmatched — acme 11, shopflow 11, opsportal 9. The 30→31 came from `xss-occurrence` (all-occurrence scan; opsportal search reflected XSS).
- **Floor-hardening false negatives fixed (no loosening):** pre-probe-only denial controls (post-mutation readbacks are persistence evidence); credential-shape `proofPatterns` for free-text disclosure; role-exclusive function-surface delta for vertical BFLA. `store/scope/acting/account/org/identity` are protected identity fields.
- **Regressions held:** held-out-saas 20/20 + 20/20 patches, xben 25/25, procedural acme 16/22.
- **Certification measurement started:** K=6 unified acme ×3 sequential runs on merged main; gate = worst-run precision 100%, preservation ≥0.95, positive lift over 11/22, leads investigated when emitted, provenance complete.

### 2026-11-23 — v7 planning + honest deterministic vs agentic numbers

- **Numbers at planning time:** product floor 3-app **31/59 (52.5%) @100%**; agentic K=6 acme ×3 = **11 / 12 / 11 of 22**, precision **100% / 92.3% / 100%**, median lift **0**, $0.48–0.51, p50 assignment 53 s; realism #2/#3/#4 wiring PASS but **0 capability confirms**; xben 25/25, held-out 20/20 + 20/20; salted held-out product floor last 23/58 (not re-run).
- **Certification verdict:** not certifiable — worst-run precision 92.3% (one unmatched cross-tenant mass-assign claim under triage) and median lift 0.
- **Root cause caught by review:** Phase A floor consumes ~1,500–1,800 of the shared ~2,000 request budget, leaving ~20 agent assignments ~10–25 requests each. Decoupling floor/agent budgets is an instant win.
- **v7 plan:** `plans/v7.md`. No fourth layer. Thesis = real-world conversion + white-box-first verification. M0 ProofReceipt + budget split + DSL retirement (3 cuts); M1 realism conversion #1–#4; M2 white-box dataflow + chains; M4 production ops. **Continuous scanning / persistent org graph deferred** (candidate v8).
- **Cut for now:** multi-tenant SaaS, plugin SDK, ML priors, heavy UX. M1/M2 blocked behind M0 gates.

### 2026-11-23 — budget decoupling: budget was never the constraint

- **Implemented:** separate floor/agent request allowances scaled to duration (600 s: 6,000/25,000/31,000 total, $5; 45 min: 12,000/100,000/112,000, $10), 50 RPS lab cap, `agent_budget_exhausted` termination, per-phase accounting (no borrowing), no stale 2,000 literal.
- **600 s generous run:** **13/22 (59.1%) at 100% precision**, +2 net, 25 investigations, 2,225 requests, $0.65.
- **45 min generous:** 15/22 (68.2%) @88.2% and kept-rerun 13/22 (59.1%) @92.9%, **+2..+4 net**, 83 investigations, **4,288 of 112,000 requests**, $2.99 of $10.
- **Conclusion:** caps are not binding; the limits are model/tool throughput and hypothesis/proof quality. Longer horizons raise recall but also the FP rate (1–2 unmatched), so **worst-run precision at horizon is now the gate**, not budget.
- **Follow-up:** triage the negative-invoice-amount claim (genuine invariant bug vs echo/clamp) and rerun 45 min; certification should use an ample-budget 600 s cell for the precision-clean number plus a long-horizon precision check.

### 2026-11-23 — consultation cadence hardening

- **Issue:** hourly Gemini check-ins lapsed after #8 because the background timer was not relaunched and long benchmark waits hid the gap.
- **Fix:** `consult.sh` stamps `~/.config/guardian/last-consult` on every successful reply; `parallel-pulse.sh` prints **GEMINI CHECK-IN OVERDUE** when the stamp is missing or older than 60 minutes. The pulse is the backstop, so the cadence cannot silently lapse again.

### 2026-11-23 — smoke-testing consult: fast + predictive is possible

- **Reviewer verdict:** yes, ~85–90% of changes can be covered by a **~6 min / ~$1** Tier-1 battery, if smoke is decoupled from "a smaller 45-min scan."
- **Tier 0 (<90 s, $0):** worker-gate + deterministic replay of past FP/over-claim archetypes through verifier/dedupe/scheduler.
- **Tier 1 (~6 min, ~$1, 4 parallel cells):** paired lift from post-floor snapshots (acme), rotating second app (shopflow/opsportal), **pre-exhausted precision trap must confirm 0**, realism conversion micro-slice (async OOB / staging race / 4-hop).
- **Tier 2 (30–45 min):** cold 3-app dev n=3 + salted held-out n=2 + one 45-min endurance + realism + xben/held-out. Blind spots: cold Phase-A→B integration and multi-hour DB drift stay here.
- **Technique ranking:** paired snapshot A/B 9.5/10; precision trap 9/10; transcript replay 8.5/10 ($0); stratified slices 7.5/10; bootstrap CIs 4/10 (reject). Frozen LLM-turn VCR is plumbing-only, never recall.
- **Gates:** 100% precision on lift cells + 0 on trap; paired net-new non-regression (allow −1 only with conversion gain + rerun); conversion drop ≤10pp; 0 crashes; p50 ≤75 s; ≥12 completions/300 s; ≤$0.80/cell; rotate the second app; fix general invariants, never trap-specific names.
- **Calibration study (accepted, ~$22–24):** 8 variants vs full reference; trust at Spearman ≥0.75, 100% directional agreement for Δ≥2 targets, trap catches every variant below 95% precision.
- **Stream launched:** `smoke-battery` (Tier 0 corpus, Tier 1 runner with snapshot resume + trap fixture, gates, calibration helper).

### 2026-11-23 — hourly check-in #10: don't certify yet; shopflow FP is P0

- **Tier-1 smoke paid for itself:** rotation shopflow 0/19 with **1 unmatched FP** and **p50 98 s**, trap 0, acme +1 @100%, floor preserved. Two gates failed on real defects.
- **Certification rule (accepted):** no cert while any FP is active or held-out is unmeasured. Held-out hard blockers: any FP, preservation <0.95, unified < floor, aggregate lift ≤+3.5pp, or 0 net-new on 2+ apps. Acceptable variance: 100% precision, preservation ≥0.95, aggregate +5–7pp.
- **Order:** triage shopflow FP first (hard P0), then p50/0-lift; **Cut 3 becomes P0 immediately after** (`execution.ts <8.5K`, `replay-verifier <1.5K`) because LOC drift reversed (9.5K → 11.5K / 3.4K → 3.8K).
- **Horizon finding:** 45 min yielded **0 marginal recall over 10 min** (13/22 both) at 3× cost, so remaining gaps are hypothesis/proof coverage (white-box slices, workflows, chains), not runtime.
- **Gate calibration accepted:** p50 hard fail ≤90 s (>75 s warns); monorepo micro-slice should use a cached post-recon snapshot.
- **M1 rank after cert:** (1) #4 4-hop via attached slices, (2) #2 no-SSRF-hypothesis gap (promotion path already merged), (3) #3 race/workflow capability.

### 2026-11-24 — hourly check-in #11: certify Floor+Realism milestone, hold "Agentic Lift"; fix 1/7 dispatch first

**Measured going in:** dev floor 33/59 (55.9%, 0-spread, 100%); held-out floor 24/58 (41.4%, 100%); dev unified 35/59 (+2: acme +1, shopflow +1, opsportal 0) @100%; held-out unified 24/58 (**0 lift**, 2 unmatched FPs, 19–23 investigations/app); Realism #2 **async SSRF + XXE confirmed** (2 TP/0 FP); Realism #3 capability PASS; #4 wiring PASS, 4-hop 0/3.

**Triage (accept/reject/defer):**

| # | Recommendation | Verdict | Owner |
|---|---|---|---|
| 1 | Refuse to certify "Agentic Lift" at dev +2 / held-out +0; record a **Floor + Realism-Wiring Milestone** (33/59 dev 0-spread, 24/58 held-out, xben 25/25, held-out-saas 20/20+20/20, Realism #3 PASS, #2 async SSRF+XXE) | **ACCEPT** | coordinator |
| 2 | Fair lift bar after the floor jump 26→33/59: **≥+6–8pp dev and ≥+6pp held-out** at 100% worst-run precision (~37–38/59 dev, ~28/58 held-out) | **ACCEPT** | certification stream |
| 3 | Don't guess the missing class — pull a structured funnel over the ~60 held-out investigations (`dispatched → target_route_hit → verify_called → oracle_rejected_by → open_proof_gap`) plus the 2 FPs' rejection gap | **ACCEPT** | `heldout-lift` |
| 4 | Audit order for 1/7 & 2/19: (a) dry-round stop/`decideNext()` after round 1 while ready steps are queued, or `alreadyConfirmed`/cap-2 filtering; (b) `dependsOn` gating leaving steps blocked; (c) dedupe collapsing routes onto `(origin,class)` | **ACCEPT** | `dispatch-funnel` (launched) |
| 5 | Cheap invariant: emit dispatch funnel (`planned/filtered*/dispatched/remainingReadyAtStop/stopReason`) and assert `stopReason ∈ {dry_rounds, coordinator_done} ⇒ remainingReadyAtStop === 0` unless budget/wall/request exhausted | **ACCEPT** | `dispatch-funnel` |
| 6 | Split Realism #2 gates: `oob_wiring_fnr ≤5%` (denominator = minted canaries, now 2/2 ⇒ 0%) separate from `fixture_capability_recall ≥75%` (all planted targets; blind-SQLi + chain stay there) | **ACCEPT** | `realism-gates` (launched) |
| 7 | Cut 3 **option (a) strict strangler**: wire the 6 recipe families, delete their VM branches, hard no-fallback assertion now; remaining kinds in a follow-up (3b) | **ACCEPT** | `cut3a` (launched) |
| 8 | Realism #4: read the 3-number funnel per Tier-A slice (`dispatched`, `target_route_hit`, `verify_called` vs `oracle_rejected_by`) before touching prompts; fix cold-recon starvation and the dispatch killer first | **ACCEPT** | `realism-gates` + `dispatch-funnel` |
| 9 | Dev +2 vs held-out +0 is **noise around near-zero agentic conversion**, not dev overfitting; the 14.5pp floor gap is residual Layer-2 structure on randomized surfaces — do **not** chase with deterministic regexes, that is Layer 3's job | **ACCEPT** (no floor-regex work commissioned) | — |
| 10 | Delete the 28h-stale `parity-diff` worktree | **ACCEPT** | coordinator (done; plan doc archived to /tmp/opencode/PARITY-DIFF-SEED1.archived.md) |

**Consequence:** certification claim is versioned as **M0-interim (Floor + Realism-Wiring)**, not "agentic lift". Lift certification stays blocked until the funnel shows the true blocker and the +6pp bar is met.

### 2026-11-24 — held-out autopsy: the loss is proof submission, not hypothesis coverage

Event-derived funnel over all 34 held-out floor misses (salted seed 1000042, 600 s, K=6, kept data dirs; full report `plans/HELDOUT-LIFT.md`):

| stage | acme | shop | ops | total | share |
|---|---:|---:|---:|---:|---:|
| floor misses | 13 | 11 | 10 | 34 | 100% |
| dispatched | 9 | 10 | 9 | 28 | 82.4% |
| target_route_hit | 7 | 8 | 8 | 23 | 67.6% |
| verify_called | 1 | 2 | 1 | **4** | **11.8%** |
| confirmed after floor | 1 | 0 | 0 | 1 | 2.9% |

Codes: `no_route_hit` 11, **`no_spec_submitted` 19**, `dismissed/true` 2, inconclusive 2, confirmed 1. **23/34 targets were requested on the mounted route+method and only 4 produced a persisted replay spec.** So the dominant loss is post-route **proof submission**, not randomized-surface coverage. This reframes the whole M1 priority.

Two concrete proof defects found: (a) shopflow `product-search-sqli` — true arm used a catalog term absent from the held-out data, both arms empty → dismissed; (b) opsportal `og.log-filter-sqli` — no persona bound, all three arms 401 → dismissed.

Held-out rerun after fixture hardening (shopflow settings/admin-reviews owner+admin gate, cart ownership): **25/58 at 100% precision, 0 FPs** (acme 10, shopflow 8, opsportal 7) — first held-out **+1** with precision intact. Acme's earlier FP row was unrecoverable (`dataDirKept:false`); two subsequent clean reruns, still unexplained and tracked.

**Streams launched:** `sqli-baseline` (ground boolean arms in the target's own baseline rows) and `spec-submission` (make spec-or-explicit-proof-gap mandatory at settlement; classify the 19 no-spec targets).

### 2026-11-24 — realism gates split (wiring vs capability) + #4 funnel

- **`oob_wiring_fnr` separated from `fixture_capability_recall`** (reviewer-accepted): #2 now reports wiring PASS with **0.0% OOB wiring FNR** (0 of 2 fired async-canary targets unconfirmed) and **50.0% capability recall FAIL** (2 of 4 planted: async SSRF + XXE confirmed; blind SQLi and the exfil chain missing). The old blended 33.3% is informational only, so an unrelated capability miss can never again look like an OOB wiring defect.
- **#4 per-slice funnel** now pins the loss stage per slice: `mono-admin-bfla` was **dispatched and hit the mounted route but never reached verification**; `mono-billing-bola` and `mono-report-sqli` were **never requested**. That is not a brief-truncation signature — it is the same post-route proof-submission loss seen on held-out (19/23 `no_spec_submitted`).
- Realism #3 re-verified PASS after the split (3 TP / 0 FP, 2 h2 single-packet bursts, 0 leaks), so the change is measurement-only.

### 2026-11-24 — hourly check-in #12: hold the lift bar red; serialize the engine lane; capture FP evidence

**Triage (accept/reject/defer):**

| # | Recommendation | Verdict | Owner |
|---|---|---|---|
| 1 | Treat settlement enforcement as instrumentation, not the cure; first extract a **19-row × 7-column** table (turns/wall vs caps, `endReason`, statuses seen, personas tried, last 3 tools, anomaly-noted, vuln class) and let the dominant bucket choose the fix | **ACCEPT** | `spec-submission` |
| 2 | Decision rule pre-committed: mostly turn/wall limit → 12→18 turns / 80→120 s + wrap-up verify; mostly 401/422 + concluded-clean → input/persona capability gap; mostly anomaly-noted-text-only → proof-submission friction | **ACCEPT** | `spec-submission` |
| 3 | Serialize the three hot core files (`execution.ts`, `deterministic-specs.ts`, `replay-verifier.ts`) into ONE FIFO **Engine Lane**; keep leaf modules (`probes/*`, `agent-session`, `assignment-brief`, realism, smoke) parallel | **ACCEPT** | coordinator |
| 4 | Engine-lane merge order: sqli-baseline → dispatch-funnel → spec-submission → cut3a | **ACCEPT** | coordinator |
| 5 | **Hold the +6pp lift bar red.** Do not re-baseline again; the +6pp (+4 targets) sits inside the 19/23 proof-submission bottleneck | **ACCEPT** (no gate change) | certification |
| 6 | Next capability target after the lane drains: **Realism #4**, smallest acceptable proof = 3/3 Tier-A slices dispatched **and** route-hit, `verify_called ≥ 2/3`, ≥2/3 4-hop sinks `runtime_confirmed` at 100% precision | **ACCEPT** | next stream |
| 7 | Fixture hardening is valid only for unintended non-planted behavior; log every fixture security fix in a changelog | **ACCEPT** (created `benchmarks/CHANGELOG.md`) | coordinator |
| 8 | **Real red flag:** unrecoverable acme FP because data dirs were cleaned. Embed a redacted proof summary for every unmatched finding into the `--out` JSON/meta **before** cleanup | **ACCEPT** | `spec-submission` (file added to lease) |
| 9 | After Cut 3a parity, go **straight to Cut 3b** on the Engine Lane — do not pause to certify between them | **ACCEPT** | coordinator |

**Solved with #12:** `benchmarks/CHANGELOG.md` records both shopflow hardening changes with the "unintended, non-planted, recall unchanged" rationale, so benchmark mutations stay auditable.

### 2026-11-24 — engine lane merge 1+2: dispatch funnel fixed, Cut 3a partial (measured, not assumed)

**`dispatch-funnel` (merged `5fdd8e0`).** Root causes, in the order the reviewer predicted:
1. **Multi-trial fanout collapsed the slot pool** (not dedupe): priority steps were expanded 2–3× *before* slot allocation, so 7 planned / 6 slots became 2 hypotheses × 3 trials. Trials are now capped by `multiTrialSurplusSlots = fleet − distinctQueued` (7 or 19 queued on 6 slots ⇒ zero fanout; the M4.8 1-queued-6-slots contract preserved).
2. Latent: a dry-round/coordinator-done stop could fire with an idle fleet. `evaluateDispatchStop` defers it; `planner.ready_steps_stranded` fires only when a guarded stop would abandon work with an idle fleet.
3. Latent: unfiltered planner `dependsOnFactIds` left steps `pending` forever. Unknown ids are dropped at enqueue; blocked steps reported as `filteredDep`.
4. **Opsportal's 1–2/7 had a fourth cause:** a route-scoped 5xx cooldown was treated as an origin `circuit_open`, pausing the whole run at ~161 s with 24 ready steps stranded. `circuitBreakAction` now keeps route cooldowns as evidence and only origin-wide trips pause.

| app | distinct steps dispatched | ready stranded | recall | precision |
|---|---|---|---|---|
| opsportal before | 6 (2 hyp × 3 trials) | 24, run **paused** at 161 s | 10/18 | 100% |
| opsportal after | **19 / 25** | 19 / 12 (wall-clock only) | 10–11/18 | 100% |
| acme before | 7 | 17 | 13/22 | 100% |
| acme after | **14** | 11 (wall-clock) | 13/22 | 100% |

Funnel attribution is exact (`planned = enqueued + filtered*`, gap 0 every round), and the ≤11-line `worker-gate.sh` invariant is live.

**`cut3a` (merged `3a8f4a5`) is a deliberate partial, with measured blockers.** What landed: recipe→broker adapter (real broker guards, probeClass, staging headers, host-recorded exchange ids), a planner/record/retest projection (`floor-recipe-engine.ts`), product wiring for `boolean_or_timing`, and a hard `assertNotRecipeWiredLegacyCall` guard.

- Dev floor **34/59** (acme 12, shopflow **12**, opsportal 10), 3 runs, 0 spread, identical site-set hash, 100% precision. The +1 is `product-search-sqli` **via the boolean receipt**, i.e. a genuine product gain from the new path — not a harness trick.
- Held-out 24/58 @100%, xben 25/25, held-out-saas 20/20 + 20/20 patches.
- **Authz families stay on legacy because wiring them lost 5 dev confirmations** (routes deny only on bogus ids; writes need the legacy baseline-write/self-state readback). **The strictest variant (deleting the sql branch too) dropped xben to 20/25** — the receipt boolean rule cannot yet express status-only differentials. Reported rather than papered over.
- `replay-verifier.ts` cannot reach <1.5K yet: 3,866 lines; `http_chain` alone carries 8/33 dev confirmations and patch retest.

Follow-ups created: (a) status-divergent boolean receipt rule in `oracle-invariants.ts`, then delete the sql branch; (b) the no-model fallback in `execution.ts` still proposes sql specs (second producer of the retired path); (c) `scripts/benchmark-live.ts` still calls the legacy verifier.

### 2026-11-24 — spec-submission: rule 1 fired (78.9% turn-capped); spec-on-route 12.5% → 50%

**19-row autopsy (structured, from kept held-out cells; `plans/SPEC-SUBMISSION.md`):** `endReason` = **turn_limit 14**, wall_limit 1, concluded_clean 3, claimed_in_text_only 1. **15/19 (78.9%) hit a turn/wall cap while actively probing**, 7 of them mid-`verify_replay_spec` repair. 14/19 had already seen a 2xx on the target route; 18/19 noted the anomaly in text. So the pre-agreed **Rule 1 fired** and Rule 2 did not.

**Fixes landed (merged `f6d5205`):**
- Single-step budget **12 → 18 turns, 80 s → 120 s** (applied by the coordinator on the freed `execution.ts` lease; `settlementTurn` follows `maxTurns-2`).
- Settlement cannot accept `complete_intent(proved|partial)` for a probed route without a spec or a coded `proofGapReason` (`no_spec_shape`, `no_authenticated_persona`, `baseline_empty`, `no_control_path`, `runtime_unavailable`, `tier_blocked`, `out_of_scope`, `no_reproducible_signal`); free-text gaps do not discharge it.
- Reserved wrap-up verify turn + a route-specific obligation naming `METHOD path param=…` and the exact spec shape.
- **FP evidence capture:** every unmatched/misclassified finding now embeds a redacted `falsePositiveEvidence` block (class, CWE, category, normalized route, `oracleRulePassed`, scrubbed delta summary, per-step status/`rejectedBy`) into the `--out` JSON and `.meta.json` **before** teardown. 0-FP artifacts are byte-identical.

**Measured after-cell (salted held-out shopflow, 600 s, K=6):** spec-on-route **2/16 (12.5%) → 5/10 (50%)**; confirmed 8/19 → **9/19** (`review-stored-xss` agent-confirmed); cost $0.5455. Precision was 90% in that cell with 1 unmatched FP (now captured), and an earlier sibling cell ran 72.7%.

**Two new P0 follow-ups opened:**
1. A finding was persisted `runtime_confirmed` while its persisted diff said `verdict: inconclusive` — precision-integrity hole → stream `confirm-consistency`.
2. The grounded-SQLi fix was built on a stale base and violated leases → parked; re-landed cleanly on main by `sqli-baseline2`.

**Tooling:** `worker-gate.sh` lease guard now has a documented coordinator override (`WORKER_GATE_ALLOW_DIRTY_MAIN=1`) so the coordinator can validate its own in-flight edits while subagents stay blocked. Stale `v5-agentic-lane` test replaced: it referenced the `submitProofSpec` internal retired in M0 Cut 1, and now pins the live `verifierRepairFeedback` contract.

### 2026-11-24 — grounded SQLi arms (probe-only) + the real held-out blocker: zero discovered params

**Probe-side fix validated (`agents/sqli-baseline` @ `e7ccd6d`, probe + test only after the lease revert):** the boolean probe now sends one benign empty-term request, harvests a literal operand from the returned rows, and uses it for the baseline and every shape, with the tautology pair as the only fallback. Measured arms on held-out shopflow `product-search-sqli`:

| | baseline | true arm | false arm | result |
|---|---|---|---|---|
| before | `Item` → 3 rows | 0 rows | 0 rows | no separation; dismissed |
| after | `Item 1` → 1 row | **1 row, 200** | **0 rows, 200** | 2/2 rounds pass; `provenStyle=single_quote` |

xben stayed 25/25 (the probe maps `tautology` → `or_branch` so legacy builders still replay correctly), dev floor 33/59 at 100%, held-out 24/58 at 100%.

**But two replay-side edits are still required for the +1, and a bigger blocker sits underneath.** With the grounded pair the replay dismisses on `simBaselineTrue = 0.8333 < 0.9` because the echoed `{"query":…}` contains the payload and `k` tokens; scrubbing the reflected request value yields `1.0` and confirms 3/3 (verified on a scratch copy). Those edits (`replay-verifier` scrub, `deterministic-specs` grounded pair) are being re-landed by `sqli-baseline2` **only where the live path still reaches them** after Cut 3a.

**The blocker that actually holds held-out at 24/58:** the floor never forms an sqli hypothesis for `/api/v1/search` because recon stores **zero `endpoint_params`** for that route (`bucket=hypothesis_miss`). No pair fix can help a route the floor cannot describe. New stream `param-discovery` derives candidate params from evidence the crawler already holds (link query keys, form fields, XHR/GraphQL args, bundle literals near the path, schema docs) with `observed` vs `inferred` provenance — inferred params may form a hypothesis but can never create a confirmation.

### 2026-11-24 — hourly check-in #13: accept p50 bump, claim-halt on the precision hole, don't abandon VM deletion

**Triage (accept/reject/defer):**

| # | Recommendation | Verdict | Owner |
|---|---|---|---|
| 1 | Accept a modest p50 bump for the 4× proof-submission gain: Tier-1 **p50 110 s hard / 85 s warn** (was 90/75); do **not** split probing and proof into two assignments (splitting drops live cookies/IDs/repair context and doubles overhead) | **ACCEPT** (gate updated) | coordinator |
| 2 | Pull p50 back down by **early-exit settlement on clearly clean/hardened routes** (stop at turn 5–6 instead of burning 7–18) plus warm-pool containers, without lowering the 18-turn/120 s ceiling | **ACCEPT** | queued (agent-session) |
| 3 | Inferred params: explicit provenance (`observed` / `inferred_bundle` / `inferred_html` / `inferred_ast`), never a static advisory, noise-filtered, **one-request sensitivity check or paired differential** before any confirmation path | **ACCEPT** | `param-discovery` |
| 4 | Do **not** exclude bundle/HTML/XHR params from the +6pp gate — that is universal recon, not overfitting; only hardcoded benchmark wordlists are forbidden | **ACCEPT** | certification |
| 5 | Precision-integrity hole: **halt certification claims**, ship a **store-level invariant** (`runtime_confirmed` requires `receipt.verdict === 'confirmed'`, typed `InvariantError`), triage recovered FP rows into Tier-0 archetypes, verify forward only (worker-gate + trap 0 + one clean held-out cell) — **no** hours spent re-auditing dead runs | **ACCEPT** | `confirm-consistency` |
| 6 | Wait for `confirm-consistency` + `param-discovery`, **then** run dev + salted held-out 3-app (600 s, K=6, n=1) before any capability pivot | **ACCEPT** | coordinator |
| 7 | Do **not** abandon deleting the VM: after the re-baseline, one `cut3b-parity` stream adds the two missing receipt primitives (~150–250 LOC): `status_differential` for xben's 5 SQL targets, and authz baseline/self-state readback for the 5 dev authz targets | **ACCEPT** | queued after re-baseline |
| 8 | +6pp is likely within reach without a new capability class: funnel math on 25 route hits × 50% spec × 35–50% confirm ⇒ +4–6 targets | **NOTED** | measurement pending |

**Claim status:** agentic-lift certification remains **halted** until the store invariant lands and a clean held-out cell exists.

### 2026-11-24 — grounded SQLi pair reaches the live (recipe) path

`sqli-baseline2` answered the "which edits are actually live after Cut 3a" question by reading the code instead of assuming:

| Edit | Verdict |
|---|---|
| `execution.ts` grounded spec | **not live** — `--no-llm` runs `deterministicOnly`, so the inline spec pass is never reached; reverted, lease released |
| `deterministic-specs.ts` grounded fields + `tautology` | **not live** — wired `sql_boolean_diff/sqli` confirms via the recipe and persists `recipeSpecRecord(recordGeneratedFromArgs)`, never the synthesized spec; reverted |
| `replay-verifier.ts` echo scrub | **kept** — `verifyReplaySpec` is still reached by verification workers and patch retest, so the legacy branch is live; receipt rule already scrubbed, this covers the legacy branch |
| `floor-recipe-engine.ts` + `floor-recipes.ts` | **new and required** — the planner was replaying `hyp.baselineValue` (a seed literal); it now carries the probe anomaly's grounded `baselineValue`/`valueTemplate`/`quoteStyle` into the recorded spec so patch retest replays the same pair |

Validation on the reduced tree: dev **34/59** (3 runs, 0 spread, 100%), xben 25/25, held-out-saas 20/20 + 20/20 patches, held-out **24/58** @100%. Dev shopflow confirms `/api/v1/search` sqli through `boolean_or_timing` (`deterministic_engine.recipe_confirmed`).

**Sharpened held-out diagnosis:** `/api/v1/search` *does* declare a param (`searchQuery`); the floor still never creates an `sqli_boolean` hypothesis for it (only `mass_assignment` probes the route). So the gap is **param anchoring for a class**, not necessarily param discovery — `param-discovery` has been asked to distinguish (A) missing param vs (B) present-but-not-anchored and to report the rejecting predicate if it lives outside its lease.

### 2026-11-24 — precision invariant merged (certification blocker #1 closed forward)

`confirm-consistency` (merged `72c9cc2`):
- **Store-level invariant**: a finding can no longer persist `runtime_confirmed` (or `status = confirmed`) unless the cited receipt/replay verdict is confirming. `replayVerdictConfirmsRuntime()` + `InvariantError('invariant.confirmation_evidence')` at the single chokepoint used by inline replay, floor confirmations and receipt promotion. Typed exception, not a silent skip.
- `execution.ts` demotes/removes a finding when a later downgrade arrives, and emits a loud `finding.confirmation_conflict` event that is counted.
- `scripts/audit-confirmation-consistency.ts` audits a run's DB for confirmed findings whose persisted diff is non-confirming — usable on any future kept cell.
- operator-visible invariant check added to `worker-gate.sh`.

This is the certification blocker the spec-submission stream surfaced (a `runtime_confirmed` finding whose own diff said `inconclusive`). Claims remain halted until a clean held-out cell verifies forward.
