# Guardian v5 — Living Verification (`VERIFICATION-v5.md`)

**Status:** IN PROGRESS — v5 is not released. This page is the rolling evidence record for the M0–M6 line; it is updated as streams merge.

**Snapshot:** 2026-11-22, base `main` @ `edcc7f1` (includes `5b4b625`, M2 complete, and the paired realism runs), docs branch `agents/docs-v5`.
**Plan:** [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) · [plans/v5.md](plans/v5.md)
**Prior release:** [VERIFICATION-v4.md](VERIFICATION-v4.md) (v4/M7 closed at 25/25 XBEN, 20/20 held-out, 20/20 patches)
**Handover:** [HANDOVER-v5.md](HANDOVER-v5.md)

> Every v5 number below is either re-derived from a preserved structured artifact or explicitly marked **copied** from a stream report / roadmap. Provenance and discrepancies are in [§9](#9-provenance-and-discrepancies). No raw benchmark logs or probe payloads are reproduced here.

---

## 1. What v5 is measuring

v5 is the integration line that turns already-built v4 primitives into active production paths and measures the result end-to-end on `realistic-bench`. The v5 goal is not a new scanner architecture; it is:

1. close the broken production wires (broker/browser args, coverage/param/dependency plumbing, routing, dedupe, canary surfaces);
2. raise real-application recall while holding decoy false positives at zero;
3. prove generalization on salted held-out seeds, not just the dev suite;
4. publish before/after evidence per milestone.

The surfaces below are reported separately and are **not comparable to each other**.

| Surface | Purpose | Size |
| :--- | :--- | :--- |
| `benchmarks/xben-25` | Fixed dev suite used for recall hill-climbing | 25 targets, 0 decoys |
| `local-lab/held-out-saas` | Anti-overfitting + patch retest | 20 vulns + 6 hard decoys |
| `benchmarks/realistic-bench` | Multi-tenant realism, paired dev + salted held-out seeds | 3 apps, 172/171 dev/held-out targets, 6–8 decoys per seed |
| Agentic `Execution` baseline | Real LLM worker loop on realistic apps | 1 app/seed per run, wall-clock capped |

“Confirmed” means a Zero-LLM `ReplayVerifier` reached `confirmed` / `runtime_confirmed`. LLM output is a hypothesis only.

---

## 2. Release gates (v5 target vs current)

Targets are copied from the roadmap header; current values are re-derived in §4 unless marked. **Held-out/dev parity uses the absolute percentage-point definition: within 10 percentage points.**

| # | Gate | v5 target | Current v5 evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| G1 | XBEN-25 recall | ≥ 23/25 | **24/25 (96%)**, 0 FP | **MET** |
| G2 | Held-out SaaS recall | ≥ 18/20 | **20/20 (100%)**, 6/6 decoys clean | **MET** |
| G3 | Held-out patch retest | ≥ 14/20 fixed | **20/20 fixed** (18 clean dismissals, 2 inconclusive counted fixed) | **MET, with caveat** |
| G4 | Realistic H/C recall — grey-box | ≥ 65% | **16/117 = 13.7%** (all severities: **24/172 = 14.0%**) | **NOT MET** |
| G5 | Realistic H/C recall — white-box | ≥ 80% | not measured | **NOT MEASURED** |
| G6 | Precision | ≥ 95% | dev **100%** (24/24), held-out **100%** (26/26) | **MET** (small denominators) |
| G7 | Decoy FP rate | ≤ 5% | **0/62** dev, **0/63** held-out | **MET** |
| G8 | Chain completion | ≥ 50% | **0/6** dev, **0/6** held-out; XBEN `browser_chain` missed | **NOT MET** |
| G9 | Held-out within 10 pp of dev | ≤ 10 pp absolute | dev **13.95%** vs held-out **15.20%** = **+1.25 pp (≈ +1.2 pp)** | **MET** |
| G10 | Gate suites | 100% pass, 0 skips | v5 suites **149/149**; harness **142/142**; Board **14/14** + tools **15/15** + Playwright **1/1** | **MET** for the run set |
| G11 | Orphan containers/networks | 0 / 0 | **51 leaked `Created` containers found; 50 stale removed**; re-check 0 `Created`, 2 running, 0 networks | **FIX IN PROGRESS** |

**Scorecard:** 6 met, 1 met-with-caveat, 2 not met (G4, G8), 1 not measured (G5), 1 fix in progress (G11). The principal release blockers are G4, G5 and G8; container-lifecycle remediation is owned by the gate stream.

---

## 3. Milestone status (M0–M6)

| # | Scope | Status at snapshot | Owner / worktree | Primary commits | What remains |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **M0** | True E2E `realistic-bench` harness, baseline, CLI | **DONE** (deterministic baseline; agentic run requires a model profile) | `m5-m0` / `agents/m0` | `ac5cebd` harness, `795f7c6` per-cell isolation, `36998da` inert-run preflight | Re-baseline after M3/M6; keep baseline artifacts out of `/tmp` |
| **M1** | P0 wiring: broker/browser args, canaries, dedupe, routing, verify feedback, guard/sanitizer, CVE semver | **DONE** (merged) | `m5-m1-core`, `m5-m1-static` | merge `5dae946`; static `0fd8a9d`; recon halt fix `4ad4078` | Restore the one XBEN regression vs v4 parity (`xben-16`) |
| **M2** | State graph, recon, auth/session, coverage | **DONE** (merged; M2.1 acceptance 10/10) | `m7-spa`, `m5-m2-auth`, `agents/m2-state` | merge `198cdad`; `e111d29` endpoint graph/coverage/ID harvest; `476e03c` auth | Keep parity as recall rises; no open M2.1 item |
| **M3** | Real-world probes/verifiers: CSRF, webhook forgery, open redirect, write-BOLA, race, noise | **IN PROGRESS** (probes + spec contracts merged) | `m5-m3-probes`, `specs2` | merge `5aa897c`; probes `db9b822`; contracts `769311c` | Finish race/setup and business-logic invariants; dedicated decoy-negative acceptance |
| **M4** | Templates, multi-framework AST, SAST→DAST, Patch Gate 6 | **DONE** (merged; live wiring landed) | `m5-m4` / `agents/m4` | merge `c19e98a`; corpus `05f2e39`; wiring `e3202d7`, `0797d70` | More modern CVE coverage; keep appliance templates off modern-stack targets |
| **M5** | Swarm Message Board, Board UI, board tools | **PHASE 1 + TOOLS DONE**; posters/wakeups in progress | `m5-board` / `agents/board-ui` | `4b41388`, `344d9b1`; workspace `ca197a2`; tools `b0b3cce`, merge `c019295` | Deterministic posters, warm wakeups/handoffs, chain planning, compaction |
| **M6** | Hill-climb, anti-overfitting, v5 gate | **IN PROGRESS** (this document; agentic matrix added) | `m5-docs2` / `agents/docs-v5` | `73b11c2` goal/gates; `d54b463` agentic matrix | Reach G4/G5/G8; hold G9 parity; close G11; publish final gate |

---

## 4. Measured evidence

### 4.1 Build and suite gate

Run on this worktree at `edcc7f1` unless noted. `node_modules` was symlinked from the base checkout; host worker deps were linked for AST suites.

| Check | Command | Result | Notes |
| :--- | :--- | :--- | :--- |
| Typecheck | `npm run check` | **PASS (0 errors)** | re-run 2026-11-22 |
| Production build | `npm run build` | **PASS** | client + SSR |
| v5 M0–M5 suites | `node --test --test-concurrency=1 tests/v5-*.test.ts` under the Docker group | **149 / 149 PASS, 0 skip** | 124 → 149 with M2-state + board-tools |
| Board unit/boundary | `node --test tests/v5-board-store.test.ts tests/v5-board-boundaries.test.ts` | **14 / 14 PASS** | 8 store + 6 boundary |
| Board tools | `node --test tests/v5-m5-board-tools.test.ts` | **15 / 15 PASS** | board_post/read, deltas, warm lifecycle |
| Board UI (Playwright) | `npx playwright test tests/guardian-v5-board.spec.ts --workers=1` | **1 / 1 PASS** | requires `npm run build` first |
| realistic-bench harness | `node --test --test-concurrency=1 benchmarks/realistic-bench/tests/` | **142 / 142 PASS, 0 skip** | re-run |
| realistic-bench typecheck | `tsc -p benchmarks/realistic-bench/tsconfig.json --noEmit` | **PASS** | re-run |
| Docker orphans | `docker ps -a --filter label=dev.guardian.assignment` | **51 leaked `Created` found; 50 removed; 0 `Created` now** | re-check saw 2 running, 0 run containers, 0 networks |

**Caveats:** the full v4 519-case matrix and Playwright v2/v4 specs were **not** re-run by this docs stream. The 51 leaked containers were found by the docs pass; the gate stream removed 50 stale objects. Two running assignment containers were present at re-check and may belong to active work; lifecycle enforcement is still in progress.

### 4.2 XBEN-25 — 24/25 (G1 met)

Source: `/tmp/opencode/xben-board.json` (suite `xben-25`, `v4-full`, `local-jq`, commit `198cdad`, not simulated).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 25 / 0 |
| Confirmed | **24** |
| False positives | 0 |
| Recall / precision | 96% / 100% |
| Duration / cost | 101.1 s / $0.00 |
| Funnel | 25 → 25 surface → 24 hypothesis → 24 signal → 24 spec → 24 confirmed |
| Only miss | `xben-16` (`browser_chain`), outcome `hypothesis_miss`, no probe class |

This is above the v5 ≥23 gate but **one below v4 parity** (25/25 at `9793d2d`). The missing challenge is the browser chain, not a parser/verifier failure.

### 4.3 Held-out SaaS — 20/20, patches 20/20 (G2/G3 met)

Source: `/tmp/guardian-m7-bench/m2-state-held.json` (`held-out-saas`, `local-jq`, M2-state line).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 20 / 6 |
| Confirmed / decoys clean | **20 / 6** |
| False positives | 0 |
| Recall / precision | 100% / 100% |
| Funnel | 20 → 20 → 20 → 20 → 20 → 20 |
| Scan / patch retest duration | 140.9 s / 16.8 s |
| Cost | $0.00 |

Patch retest:

| Metric | Value |
| :--- | ---: |
| Attempted / reproduced before | 20 / 20 |
| Fixed | **20** |
| Clean dismissals | 18 |
| Inconclusive-after counted fixed | 2 (`hos-04`, `hos-17`) |
| Isolation preserved | 20 × 4/4 checks, 0 lost |
| Decoy FP before / after | 0 / 0 |
| All-patches verdict | `fixed`; 20 replayed, 20 dismissed |

**Attribution caveat:** the all-patches verdict replays baseline-attributed specs (the artifact’s own note says a fresh pipeline pass is not used as patch evidence). `hos-04` / `hos-17` were `inconclusive` after patching and counted fixed under patch-retest semantics, not clean dismissals.

### 4.4 realistic-bench dev matrix — 24/172 (G4/G6/G7)

Source: `/tmp/rb-m2-state/*.json` (9 scorecards; deterministic replay, `$0`, not agentic). Run report: **9 cells, ~100 s wall at concurrency 9**.

| App | Seed | Confirmed / targets | Recall | Precision | Decoy FP | Unmatched FP | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1 | 3 / 22 | 13.6% | 100% | 0 | 0 | 0/0 |
| acme-saas | 2 | 3 / 20 | 15.0% | 100% | 0 | 0 | 0/0 |
| acme-saas | 42 | 5 / 22 | 22.7% | 100% | 0 | 0 | 0/1 |
| opsportal | 1 | 3 / 18 | 16.7% | 100% | 0 | 0 | 0/1 |
| opsportal | 2 | 2 / 17 | 11.8% | 100% | 0 | 0 | 0/1 |
| opsportal | 42 | 2 / 16 | 12.5% | 100% | 0 | 0 | 0/1 |
| shopflow | 1 | 2 / 19 | 10.5% | 100% | 0 | 0 | 0/1 |
| shopflow | 2 | 2 / 20 | 10.0% | 100% | 0 | 0 | 0/1 |
| shopflow | 42 | 2 / 18 | 11.1% | 100% | 0 | 0 | 0/0 |
| **Total** | | **24 / 172** | **13.95%** | **100%** | **0 / 62** | **0** | **0 / 6** |

Severity split: Critical **4/26 (15.4%)**, High **12/91 (13.2%)**, Medium 8/52, Low 0/3 → **H/C 16/117 = 13.7%** (G4 target 65%).

Aggregate funnel and loss buckets:

| Stage / bucket | Count |
| :--- | ---: |
| Target vulns | 172 |
| Surface discovered | 139 (80.8%) |
| Hypothesis formed | 132 |
| Signal observed | **57 (33.1%)** |
| Spec submitted / confirmed | 24 / **24** |
| `replay_spec_miss` | 90 |
| `budget_exhausted` | 23 |
| `surface_miss` | 16 |
| `form_encoding_missing` | 8 |
| `hypothesis_miss` | 8 |
| `csrf_blocked` | 3 |

Confirmed by class (top): BOLA 8/19, IDOR 6/8, BFLA 3/9, CSRF 2/7, webhook forgery 2/6, SSTI 1/5, OAuth 1/1, open redirect 1/6. **16 classes have zero confirmations**, including SQLi (0/7), SSRF (0/12), stored/reflected XSS (0/11), XXE (0/7), mass assignment (0/11), race (0/5), command injection (0/5), and GraphQL BOLA (0/3).

**Precision definition:** `TP / (TP + decoyFP + unmatchedFP)`. The 100% value is over 24 emitted findings with zero decoy and zero unmatched FPs. It does not yet demonstrate precision at a high-recall operating point.

### 4.5 realistic-bench held-out matrix — 26/171 (G9)

Source: `/tmp/rb-heldout-final/*.json` (9 salted scorecards, seeds `1000042/1/2`, salt from environment only). Paired with §4.4 on the same M2 line.

| App | Seed | Confirmed / targets | Recall | Precision | Decoy FP | Unmatched FP | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1000001 | 4 / 22 | 18.2% | 100% | 0 | 0 | 0/0 |
| acme-saas | 1000002 | 4 / 21 | 19.0% | 100% | 0 | 0 | 0/1 |
| acme-saas | 1000042 | 5 / 22 | 22.7% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000001 | 1 / 16 | 6.3% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000002 | 2 / 16 | 12.5% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000042 | 3 / 17 | 17.6% | 100% | 0 | 0 | 0/1 |
| shopflow | 1000001 | 3 / 18 | 16.7% | 100% | 0 | 0 | 0/0 |
| shopflow | 1000002 | 2 / 20 | 10.0% | 100% | 0 | 0 | 0/1 |
| shopflow | 1000042 | 2 / 19 | 10.5% | 100% | 0 | 0 | 0/0 |
| **Total** | | **26 / 171** | **15.20%** | **100%** | **0 / 63** | **0** | **0 / 6** |

Severity: Critical 4/26, High 10/98, Medium 11/44, Low 1/3 → **H/C 14/124 = 11.3%**. Funnel: 171 → 144 surface → 136 hypothesis → **60 signal** → 26 spec → 26 confirmed. Top buckets: `replay_spec_miss` 91, `budget_exhausted` 20, `surface_miss` 14, `hypothesis_miss` 11, `form_encoding_missing` 6, `csrf_blocked` 3.

Confirmed by class (top): BOLA 8/18, IDOR 4/7, BFLA 3/9, open redirect 4/8, webhook forgery 3/8, CSRF 2/5, SSTI 1/5, OAuth 1/2. **16 classes have zero confirmations**, including SQLi (0/10), SSRF (0/12), XSS (0/8), XXE (0/5), race (0/6), command injection (0/5), and GraphQL BOLA (0/3).

**Gap:** dev **13.95%** vs held-out **15.20%** = **+1.25 pp absolute**. Under the roadmap’s 10-percentage-point definition, G9 is met. The all-severity gap is favorable; the H/C split is not (13.7% dev vs 11.3% held-out), so parity is not uniform across severities.

### 4.6 Agentic `Execution` baseline — 2/22 and 1/19

Sources: `/tmp/m5-m0/agentic-long/` and `/tmp/m5-m0/agentic-shopflow/` (`*.json`, `*.meta.json`). Model profile: DeepSeek V4.1 Flash via the OpenRouter profile; verifier `docker`; grey-box; $5 budget; 20-minute wall cap. Both runs hit the wall-clock cap, not the dollar budget.

| Run | Wall | Spend | Confirmed | Precision | Decoy FP | Unmatched | Chain |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas seed 1 | 1,200.4 s (timed out) | $0.4746 | **2/22 (9.1%)** | 66.7% | 0/6 | 1 | 0/0 |
| shopflow seed 1 | 1,200.1 s (timed out) | $0.3400 | **1/19 (5.3%)** | 50.0% | 0/7 | 1 | 0/1 |

| Run | Endpoints | Params | Requests | Oracle events | Findings persisted / submitted | Funnel |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| acme-saas | 59 | 27 | 663 | 43 | 7 / 3 | 22 → 14 → 6 → 6 → 2 → 2 |
| shopflow | 36 | 0 | 426 | 26 | 6 / 2 | 19 → 7 → 4 → 4 → 1 → 1 |

Failure buckets: acme `hypothesis_miss` 8, `budget_exhausted` 8, `context_reset` 3, `form_encoding_missing` 1; shopflow `budget_exhausted` 12, `hypothesis_miss` 5, `context_reset` 1.

**Novel finding note (copied from roadmap):** the acme run’s unmatched finding is a novel admin-activity BFLA with oracle evidence, not a planted site. Under the benchmark’s matching rule it still counts as an unmatched FP; the JSON corroborates 2 matched + 1 unmatched finding. Roadmap reports 3 worker bootstrap failures (3–4 assignments, 0 turns) on the acme run; that count is not in the structured JSON.

Deterministic M0 baseline (copied from roadmap, not re-run here): 11 s, $0, 0/22, 100% precision, 43 endpoints discovered. Agentic reality: wall-clock is the limiter, and worker reliability — not budget — is the first blocker. The M6 agentic matrix (`d54b463`) adds parallel isolated cells and fail-closed metrics; its scorecards are not part of this snapshot’s gate.

### 4.7 M4 corpus and Gate 6

Corpus counts re-derived from `src/templates/compiled/` on this tree:

| Metric | Value | Method |
| :--- | ---: | :--- |
| Compiled YAML templates | **1,724** | count of `src/templates/compiled/**/*.yaml` |
| CVE-named templates, all years | 915 | `cve-*.yaml` |
| CVE-named modern templates (2021–2026) | **492** | filename year filter |
| Unique CVE IDs across templates | 916 | unique `cve:` fields |
| Unique modern CVE IDs (year ≥ 2021) | **493** | year filter on `cve:` field |

The extra modern ID is a non-`cve-`-named template that references a 2021 CVE. Use **492** for “CVE-named modern templates” and **493** for “unique modern CVE IDs”; state which definition is meant.

Gate 6 / AST evidence: `tests/v5-m4-sast-templates-patch.test.ts` passes **10/10** under the Docker worker image, including “Gate 6 never passes when skipped” and trivy-fs advisories for Python/Go/Java/Ruby manifests. Compile identity checks (`npm run templates:transpile`) were not re-run; counts are from the committed corpus.

### 4.8 M5 Board Phase 1 + board tools

| Item | Evidence |
| :--- | :--- |
| Schema/store/SSE + migration | `4b41388`; board tests 8/8 |
| Boundary behavior (redaction, taint, injection delimiters, mention rules) | 6/6 boundary tests |
| Mandatory `Board` tab replaces `Coordinator` | Playwright 1/1; roster state pills, unread badge, evidence chips, inline Tier-3 approval cards, mention autocomplete |
| Composer routing | plain messages route to `@coordinator`; `board_post` honours explicit mentions |
| Board tools / warm specialists | `b0b3cce`, merge `c019295`; 15/15 board-tools tests |
| Workspace redesign port | `ca197a2` (Board in right pane) |

**Board count:** 14 node tests (store + boundaries) + **15 board-tools tests** + 1 Playwright check. Use those totals; the earlier 19/19 figure was a stale pre-merge count.

### 4.9 Notable engine fixes

| Fix | Commit | Effect / evidence |
| :--- | :--- | :--- |
| **Recon halt bug** — off-origin redirect denial is no longer treated as global scope revocation; the nav overflow lane is reserved | `4ad4078` | Phase-0 no longer aborts discovery on a denied off-origin redirect; XBEN recovered **20 → 24** |
| M2.1 endpoint graph, coverage updates, cross-persona ID harvest, BOLA consumer queue | `e111d29`, merge `198cdad` | M2-state tests **10/10**; cumulative dev realism 20 → 24/172 |
| M3 contract encodings, collection state, webhook acceptance, list reads | `3e8e418`, merge `769311c` | Dev CSRF 2/7 and webhook 2/6; held-out open redirect 4/8 and webhook 3/8 |
| Board tools + warm specialist lifecycle | `b0b3cce`, merge `c019295` | Board-tools suite **15/15** |

The realism gains are cumulative across M2/M3; they are not attributed to a single stream.

---

## 5. Before / after

These are **cumulative main-line deltas**, not isolated per-stream causal claims: M1–M4 merged in close succession and the scorecards were produced at different points.

| Metric | v4 baseline | Current v5 | Delta | Source |
| :--- | ---: | ---: | ---: | :--- |
| XBEN-25 | 25/25 (`9793d2d`) | **24/25** | **−1** | `iter3-merged.json` → `xben-board.json` |
| Held-out SaaS | 20/20 | **20/20** | 0 | `heldout-merged.json` → `m2-state-held.json` |
| Held-out patches fixed | 20/20 | **20/20** | 0 | same |
| realistic dev confirmed | 0/172 | **24/172** | **+24** | `rb-score` → `rb-m2-state` |
| realistic dev recall | 0.0% | **13.95%** | +13.95 pp | recomputed |
| realistic dev precision | 0.00 | **1.00** | +1.00 | recomputed |
| realistic dev unmatched FP | 12 | **0** | **−12** | recomputed |
| realistic held-out confirmed | 3/171 | **26/171** | **+23** | `rb-score-heldout` → `rb-heldout-final` |
| realistic held-out recall | 1.75% | **15.20%** | +13.45 pp | recomputed |
| realistic held-out precision | 0.20 | **1.00** | +0.80 | recomputed |
| realistic held-out unmatched FP | 12 | **0** | **−12** | recomputed |
| dev → held-out gap | not comparable (0 vs 1.75) | **+1.25 pp** | within 10 pp | paired M2 runs |
| realistic dev surface discovered | 131/172 | **139/172** | +8 | funnel totals |
| realistic dev signal observed | 10 | **57** | **+47** | funnel totals |
| realistic held-out surface discovered | 130/171 | **144/171** | +14 | funnel totals |
| realistic held-out signal observed | 14 | **60** | **+46** | funnel totals |
| realistic chains | 0/1 per run | **0/6** | none completed | scorecards |
| Templates / modern CVE templates | 1,600 (legacy-capped) / — | **1,724 / 492** | +124 / +492 | corpus counts |
| Board UI | Coordinator tab | **Board + Worker Inspector + board tools** | — | `4b41388`, `b0b3cce`, Playwright |

Per-milestone headline (same caveat):

| Milestone | Headline delta |
| :--- | :--- |
| M0 | no E2E realistic harness → `benchmark:realistic` drives real `Execution`, per-cell data-dir isolation, inert-run fail-fast |
| M1 | recon halt fix (`4ad4078`) stops a denied off-origin redirect from aborting discovery; XBEN **20 → 24**; unmatched realistic FPs 12 → **0** |
| M2 | M2.1 endpoint graph/coverage/ID harvest merged (`198cdad`, 10/10); dev surface 131 → **139**; dev confirmed 20 → **24** |
| M3 | held-out realistic 3/171 → **26/171**, precision 1.00, 0 decoys; CSRF/webhook/open-redirect confirmations appear |
| M4 | 1,600 legacy-capped templates → **1,724** with **492** modern CVE templates; AST/bridge/Gate 6 merged |
| M5 | Coordinator UI → **Board** plus 15/15 board tools; posters/wakeups still pending |
| M6 | paired dev/held-out gap **+1.25 pp** (G9 met); realism H/C recall, white-box, chains remain open |

---

## 6. Honest gap list

| Gap | Measured state | Why it matters | Next action |
| :--- | :--- | :--- | :--- |
| Realistic H/C recall | **13.7%** grey-box vs 65% target; held-out H/C **11.3%**; white-box unmeasured | Core v5 promise | Attack `replay_spec_miss` (90 dev / 91 held-out), `budget_exhausted` 23/20, `surface_miss` 16/14, `form_encoding_missing` 8/6 |
| Signal-stage collapse | 57/132 dev, 60/136 held-out hypotheses produce a signal | Discovery is no longer the only limiter | Per-class trigger coverage; prioritize classes with 0 confirmations (SQLi, SSRF, XSS, XXE, race, command injection, GraphQL BOLA) |
| Chain completion | **0/6 dev, 0/6 held-out**; XBEN `browser_chain` missed | Gate G8 | Wire M5 chain planning and browser-chain verification; add chain fixtures |
| Parity at low recall | dev 13.95% vs held-out 15.20% (+1.25 pp) | G9 is met, but both are far below target | Re-check the gap after each recall lift; do not treat parity at 14% as generalization at 65% |
| White-box mode | not run | Gate G5 | Run the 9-cell matrix with `--mode white-box`; record recall and decoy FPs |
| Agentic worker reliability | 2/22 and 1/19; wall-clock capped; 51 leaked containers found | Production path cannot scale | Finish the gate-stream lifecycle fix; keep `--isolate-data-dir`; treat wall-clock as a first-class SLO |
| Precision at scale | 100% on 24 dev + 26 held-out findings | Denominator is small; high recall may add FPs | Track precision per class as recall rises; keep decoy audit |
| Patch attribution | 20/20 fixed, but 2 inconclusive; all-patches is a replay | Avoid overstating clean fixes | Report clean dismissals (18/20) separately; run a fresh all-patches pass; resolve shared-`/graphql` attribution |
| XBEN regression | 25/25 v4 → 24/25 v5 | v4 parity lost on `browser_chain` | Restore `xben-16` without hardcoding; keep ≥23 gate |
| Container hygiene | 51 leaked `Created` found; 50 removed; 0 `Created` at re-check | Lifecycle enforcement not closed | Gate stream owns the fix; re-run the orphan check and document the final state |
| Full regression gate | v5 149 + harness 142 re-run; v4 519-case matrix not re-run | Release gate is not one pass | Run `docs/reverify-v4.sh` on a Docker host after v5 merges |
| Artifact durability | evidence under `/tmp` | `/tmp` is ephemeral | Copy structured JSON into release storage before cleanup |
| Corpus definitions | 1,724 total; 492 modern CVE-named; 493 unique modern IDs | Prevents unverifiable counts | State the definition in release notes |

---

## 7. Known limitations

- **Docs snapshot, not final gate.** Scores were produced by different streams at different times; only the values in §4 are re-derived here. Dev and held-out realism are now paired on the M2 line.
- **Deterministic vs agentic are separate populations.** The 24/172 and 26/171 matrices are deterministic replay; the 2/22 and 1/19 runs are LLM-driven with wall-clock caps. Do not combine them.
- **Held-out parity is all-severity.** The +1.25 pp gap compares overall recall. H/C recall is 13.7% dev vs 11.3% held-out, so parity is not uniform across severities.
- **“Within 10%” means 10 percentage points absolute.** This is the roadmap definition used for G9. It is not a relative-recall tolerance.
- **Patch “fixed” includes inconclusive retests.** Two held-out patches were counted fixed without a clean dismissal.
- **All-patches is replay-based.** It is evidence for the replayed specs, not for a fresh end-to-end patch pass.
- **Docker checks require `newgrp docker`** on this host; a plain `docker info` from the agent shell gets `permission denied` despite group membership.
- **No external targets.** Every benchmark is loopback-only; no internet host was contacted.
- **No credentials or salts in this document.** Paths only.

---

## 8. Reproduction

All commands are loopback-only. Never print, copy, or commit the model key or the held-out salt.

### 8.1 Setup

```bash
cd /path/to/guardian
npm ci
npm run worker:install          # host deps for AST suites (@swc/core, acorn)
npm run worker:build            # Docker required
```

For a fresh worktree, symlink the base checkout’s `node_modules` (and `worker/node_modules`) instead of reinstalling.

### 8.2 Typecheck, build, suites

```bash
NODE_OPTIONS=--max-old-space-size=1536 npm run check
NODE_OPTIONS=--max-old-space-size=1536 npm run build

# v5 suites (149 tests). Use the Docker group so M4-T9 is not skipped.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=1536 &&
  node --test --test-concurrency=1 tests/v5-*.test.ts
'

# Board UI and tools (after build)
npx playwright test tests/guardian-v5-board.spec.ts --workers=1
node --test tests/v5-m5-board-tools.test.ts

# Harness self-tests
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 benchmarks/realistic-bench/tests/
npx tsc -p benchmarks/realistic-bench/tsconfig.json --noEmit
```

### 8.3 XBEN-25

```bash
mkdir -p /tmp/guardian-v5-bench
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:recall -- \
  --suite xben-25 --profile-mode v4-full --verifier-backend local-jq \
  --git-sha v5-xben --out-json /tmp/guardian-v5-bench/xben.json \
  --out-md /tmp/guardian-v5-bench/xben.md
```

Add `--baseline-sha <label> --diff` for the delta table.

### 8.4 Held-out SaaS + patch retest

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:recall -- \
  --suite held-out-saas --profile-mode v4-full --verifier-backend local-jq \
  --verify-patches --git-sha v5-heldout \
  --out-json /tmp/guardian-v5-bench/heldout.json \
  --out-md /tmp/guardian-v5-bench/heldout.md
```

### 8.5 realistic-bench dev matrix

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- \
  --app all --seeds 1,2,42 --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/rb-v5-dev
```

### 8.6 realistic-bench held-out matrix (paired)

```bash
# The salt lives at ~/.config/guardian-bench/heldout.salt (mode 600).
# Read it into the environment; never echo it.
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"

npm run benchmark:realistic -- \
  --app all --seeds 1000001,1000002,1000042 --held-out --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/rb-v5-heldout

unset GUARDIAN_RB_HELDOUT_SALT
```

White-box: repeat §8.5/§8.6 with `--mode white-box` and a separate `--out-dir`.

### 8.7 Agentic matrix (model profile + Docker workers)

The model profile and credential live in the Guardian data dir; do not print the credential file. `--isolate-data-dir` copies only enabled model profiles and symlinks `credentials/`, giving each cell its own store (avoids the single-process data-dir lock).

```bash
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
         NODE_OPTIONS=--max-old-space-size=1536 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 2 \
    --budget-usd 5 --max-duration-ms 1200000 \
    --out-dir /tmp/rb-v5-agentic
'
```

Fail-fast rules: a model profile plus `--verifier local-jq` exits 2 (inert workers) unless `--no-llm`; Docker worker sessions require socket access via `newgrp docker`.

### 8.8 Hygiene

```bash
docker ps -aq --filter label=dev.guardian.assignment   # expect empty
docker ps -aq --filter label=dev.guardian.run          # expect empty
docker network ls -q --filter name=guardian            # expect empty
```

The 51-container leak is under remediation; 50 stale `Created` objects were removed. Do not delete containers with a live owner; verify age/status and coordination before cleanup.

---

## 9. Provenance and discrepancies

### 9.1 Number provenance

| Claim | Value used | Provenance | Status |
| :--- | :--- | :--- | :--- |
| XBEN confirmed | 24/25 | `/tmp/opencode/xben-board.json` | re-derived |
| Held-out confirmed | 20/20 | `/tmp/guardian-m7-bench/m2-state-held.json` | re-derived |
| Held-out patches | 20/20, 18 clean | same `patchVerification.perPatch` | re-derived |
| Realistic dev | 24/172, 0/62 decoys, 0 unmatched | sum of 9 `/tmp/rb-m2-state` scorecards | re-derived |
| Realistic held-out | 26/171, 0/63 decoys, 0 unmatched | sum of 9 `/tmp/rb-heldout-final` scorecards | re-derived |
| Dev run wall time | ~100 s at concurrency 9 | stream report | **copied** |
| Agentic acme / shopflow | 2/22, 1/19; costs/times | `agentic-long` + `agentic-shopflow` JSON/meta | re-derived |
| Templates / modern CVEs | 1,724 / 492 / 493 | filesystem counts | re-derived |
| Board tests / Playwright | 14/14 + 15/15 + 1/1 | test runs | re-derived |
| v5 suites | 149/149, 0 skip | run under Docker group | re-derived |
| Harness tests | 142/142 | test run | re-derived |
| Orphans | 51 found, 50 removed, 0 `Created` at re-check | docs check + gate report | re-derived / **partly copied** |
| Worker bootstrap failures (acme) | 3 | roadmap §5 | **copied** |
| Novel admin BFLA | oracle-evidenced, unmatched | roadmap §5 + JSON unmatched ID | **partly copied** |
| Deterministic M0 baseline | 11 s, $0, 0/22 | roadmap §5 | **copied** |
| v4 gate 25/25 | 25/25 | `iter3-merged.json`; `9793d2d` attribution from roadmap | re-derived artifact / **copied** commit |

### 9.2 Discrepancies found / retired

1. **Modern CVE count retired:** earlier drafts said “521 CVEs”. The verifiable counts are **492 CVE-named modern templates (2021–2026)** and **493 unique modern CVE IDs** across 1,724 compiled templates. Use one of those definitions, not 521.
2. **Board test count retired:** earlier drafts said “19/19”. Current totals are **14 node board tests + 15 board-tools tests + 1 Playwright check**.
3. **XBEN still below v4 parity:** v4 closed at 25/25 (`9793d2d`); current main is 24/25, missing `xben-16` (`browser_chain`). The v5 ≥23 gate passes, but v4 parity does not.
4. **Container leak is real but improved:** 51 leaked `Created` assignment containers were found; 50 stale ones were removed. Re-check: 0 `Created`, 2 running, 0 run containers, 0 networks. The lifecycle fix is in progress, so G11 is not yet “closed”.
5. **Held-out snapshot retired:** the stale 15/171 held-out matrix was replaced by a paired run (`rb-m2-state` dev, `rb-heldout-final` held-out). Dev/held-out gap is now +1.25 pp.
6. **“Within 10%” resolved:** the definition is **10 percentage points absolute**, not relative recall. Under that definition G9 is met.
7. **Suite scope:** “100% suites, 0 skips” here means the 149 v5 tests + 142 harness tests + Board UI/tools, not the full v4 519-case matrix. The v5 run is 0-skip only under `newgrp docker`; without Docker, `M4-T9` skips.
8. **Agentic failure counts are partly narrative:** the 3–4 worker-bootstrap failures and the novel-BFLA classification come from the roadmap, not the JSON; the JSON only exposes one unmatched finding ID.
9. **Severity split differs by split:** held-out all-severity recall (15.2%) is above dev (14.0%), but held-out H/C recall (11.3%) is below dev (13.7%). Do not present the all-severity gap as H/C parity.
10. **Patch artifact choice:** `heldout-board.json` (newest held-out run) has no patch verification; patch evidence is from `m2-state-held.json` on the same M2 line.

### 9.3 Next review trigger

Refresh this page when any of the following lands: M3 completion, M5 posters/wakeups, a white-box matrix, an M6 paired recall lift, the container-lifecycle fix, or a full v4 519-case regression run. The gate table in §2 is the single source of truth for release readiness.
