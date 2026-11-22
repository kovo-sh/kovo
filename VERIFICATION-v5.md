# Guardian v5 — Living Verification (`VERIFICATION-v5.md`)

**Status:** IN PROGRESS — v5 is not released. This page is the rolling evidence record for the M0–M6 line; it is updated as streams merge.

**Snapshot:** 2026-11-22, base `main` @ `175a0a1` (merge recon2 tech-tags wiring), docs branch `agents/docs-v5`.
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
| `benchmarks/realistic-bench` | Multi-tenant realism, dev + salted held-out seeds | 3 apps, 172/171 dev/held-out targets, 6–8 decoys per seed |
| Agentic `Execution` baseline | Real LLM worker loop on realistic apps | 1 app/seed per run, wall-clock capped |

“Confirmed” means a Zero-LLM `ReplayVerifier` reached `confirmed` / `runtime_confirmed`. LLM output is a hypothesis only.

---

## 2. Release gates (v5 target vs current)

Targets are copied from the roadmap header; current values are re-derived in §4 unless marked.

| # | Gate | v5 target | Current v5 evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| G1 | XBEN-25 recall | ≥ 23/25 | **24/25 (96%)**, 0 FP | **MET** |
| G2 | Held-out SaaS recall | ≥ 18/20 | **20/20 (100%)**, 6/6 decoys clean | **MET** |
| G3 | Held-out patch retest | ≥ 14/20 fixed | **20/20 fixed** (18 clean dismissals, 2 inconclusive counted fixed) | **MET, with caveat** |
| G4 | Realistic H/C recall — grey-box | ≥ 65% | **16/117 = 13.7%** (all severities: 20/172 = 11.6%) | **NOT MET** |
| G5 | Realistic H/C recall — white-box | ≥ 80% | not measured | **NOT MEASURED** |
| G6 | Precision | ≥ 95% | dev **100%** (20/20), held-out **100%** (15/15) | **MET** (small denominators) |
| G7 | Decoy FP rate | ≤ 5% | **0/62** dev, **0/63** held-out | **MET** |
| G8 | Chain completion | ≥ 50% | **0/6** dev, **0/6** held-out; XBEN `browser_chain` missed | **NOT MET** |
| G9 | Held-out within 10% of dev | ≤ 10% | 11.63% dev vs 8.77% held-out: **−2.86 pp / −24.6% relative** | **NOT MET** (strict relative reading; see §6) |
| G10 | Gate suites | 100% pass, 0 skips | v5 suites **124/124**; realistic harness **142/142**; Board **14/14** + Playwright **1/1** | **MET** for the run set |
| G11 | Orphan containers/networks | 0 / 0 | **51 created assignment containers, 0 running, 0 run containers, 0 networks** | **NOT MET** |

**Scorecard:** 5 met, 1 met-with-caveat, 4 not met (G4, G8, G9, G11), 1 not measured (G5). The release is blocked by G4, G5, G8, G9 and container hygiene; G1 is above target but below v4 parity (see §5).

---

## 3. Milestone status (M0–M6)

| # | Scope | Status at snapshot | Owner / worktree | Primary commits | What remains |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **M0** | True E2E `realistic-bench` harness, baseline, CLI | **DONE** (deterministic baseline; agentic run requires a model profile) | `m5-m0` / `agents/m0` | `ac5cebd` harness, `795f7c6` per-cell isolation, `36998da` inert-run preflight | Re-baseline after M1–M3; keep baseline artifacts out of `/tmp` |
| **M1** | P0 wiring: broker/browser args, canaries, dedupe, routing, verify feedback, guard/sanitizer, CVE semver | **DONE** (merged) | `m5-m1-core`, `m5-m1-static` | merge `5dae946`; static `0fd8a9d`; XBEN recovery `4ad4078` | Restore the one XBEN regression vs v4 parity (`xben-16`) |
| **M2** | State graph, recon, auth/session | **PARTIAL** — 2.2/2.3/2.4 done; **2.1 in flight** | `m7-spa`, `m5-m2-auth`, `m5-m2-state` | merge `51d3b5a`; auth `476e03c`; XHR routes `a747d6e` | 2.1 acceptance: endpoint-param/dependency consumers, coverage updates, cross-persona ID harvest, per-resource budget |
| **M3** | Real-world probes & verifiers: CSRF state change, webhook forgery, open redirect, write-BOLA, race, noise | **RUNNING** | `m5-m3-probes` | merge `5aa897c`; probes `db9b822` | Finish race/setup and business-logic invariants; dedicated acceptance suite; verify on decoys |
| **M4** | Templates, multi-framework AST, SAST→DAST, Patch Gate 6 | **DONE** (merged; live execution/recon wiring partly landed) | `m5-m4` / `agents/m4` | merge `c19e98a`; corpus `05f2e39`; wiring `e3202d7`, `0797d70` | More modern CVE coverage; keep appliance templates off modern-stack targets |
| **M5** | Swarm Message Board + Board UI | **PHASE 1 DONE**; Phase 1b/2/3 pending | `m5-board` / `agents/board-ui` | `4b41388`; merge `344d9b1`; workspace port `ca197a2` | Deterministic posters, warm specialists/handoffs, chain planning, compaction |
| **M6** | Hill-climb, anti-overfitting, v5 gate | **IN PROGRESS** (this document) | `m5-docs2` / `agents/docs-v5` | `73b11c2` goal/gates | Reach G4/G5/G8/G9; re-run held-out after M1–M3; clean orphans; publish final gate |

---

## 4. Measured evidence

### 4.1 Build and suite gate

Run on this worktree unless noted. `node_modules` was symlinked from the base checkout; host worker deps were linked for AST suites.

| Check | Command | Result | Notes |
| :--- | :--- | :--- | :--- |
| Typecheck | `npm run check` | **PASS (0 errors)** | re-run 2026-11-22 |
| Production build | `npm run build` | **PASS** | client + SSR, `server.js` 1,742.80 kB |
| v5 M0–M5 suites | `node --test --test-concurrency=1 tests/v5-*.test.ts` under the Docker group | **124 / 124 PASS, 0 skip** | without Docker: 123 pass + 1 skip (`M4-T9`, image unavailable) |
| Board unit/boundary | `node --test tests/v5-board-store.test.ts tests/v5-board-boundaries.test.ts` | **14 / 14 PASS** | 8 store + 6 boundary |
| Board UI (Playwright) | `npx playwright test tests/guardian-v5-board.spec.ts --workers=1` | **1 / 1 PASS** (1.3 s) | requires `npm run build` first |
| realistic-bench harness | `node --test --test-concurrency=1 benchmarks/realistic-bench/tests/` | **142 / 142 PASS, 0 skip** | re-run |
| realistic-bench typecheck | `tsc -p benchmarks/realistic-bench/tsconfig.json --noEmit` | **PASS** | re-run |
| Docker orphans | `docker ps -aq --filter label=dev.guardian.assignment` | **51 created, 0 running** | run containers 0; networks 0; `guardian-worker:v4` present |

**Caveats:** the full v4 519-case matrix and Playwright v2/v4 specs were **not** re-run by this docs stream. The 51 created containers are stale objects from earlier worker/agentic runs; this snapshot did not remove them (docs stream is read-only outside `docs/`).

### 4.2 XBEN-25 — 24/25 (G1 met)

Source: `/tmp/guardian-m7-bench/post-m1.json` (suite `xben-25`, `v4-full`, `local-jq`, not simulated).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 25 / 0 |
| Confirmed | **24** |
| False positives | 0 |
| Recall / precision | 96% / 100% |
| Duration / cost | 86.4 s / $0.00 |
| Funnel | 25 → 25 surface → 24 hypothesis → 24 signal → 24 spec → 24 confirmed |
| Only miss | `xben-16` (`browser_chain`), outcome `hypothesis_miss`, no probe class |

This is above the v5 ≥23 gate but **one below v4 parity** (25/25 at `9793d2d`). The missing challenge is the browser chain, not a parser/verifier failure.

### 4.3 Held-out SaaS — 20/20, patches 20/20 (G2/G3 met)

Source: `/tmp/guardian-m7-bench/post-m1-heldout.json` (`held-out-saas`, `local-jq`).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 20 / 6 |
| Confirmed / decoys clean | **20 / 6** |
| False positives | 0 |
| Recall / precision | 100% / 100% |
| Funnel | 20 → 20 → 20 → 20 → 20 → 20 |
| Scan / patch retest duration | 140.6 s / 16.6 s |
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

### 4.4 realistic-bench dev matrix — 20/172 (G4/G6/G7)

Source: `/tmp/rb-post-m1/*.json` (9 scorecards; deterministic replay, `$0`, not agentic).

| App | Seed | Confirmed / targets | Recall | Precision | Decoy FP | Unmatched FP | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1 | 2 / 22 | 9.1% | 100% | 0 | 0 | 0/0 |
| acme-saas | 2 | 2 / 20 | 10.0% | 100% | 0 | 0 | 0/0 |
| acme-saas | 42 | 3 / 22 | 13.6% | 100% | 0 | 0 | 0/1 |
| opsportal | 1 | 3 / 18 | 16.7% | 100% | 0 | 0 | 0/1 |
| opsportal | 2 | 2 / 17 | 11.8% | 100% | 0 | 0 | 0/1 |
| opsportal | 42 | 2 / 16 | 12.5% | 100% | 0 | 0 | 0/1 |
| shopflow | 1 | 2 / 19 | 10.5% | 100% | 0 | 0 | 0/1 |
| shopflow | 2 | 2 / 20 | 10.0% | 100% | 0 | 0 | 0/1 |
| shopflow | 42 | 2 / 18 | 11.1% | 100% | 0 | 0 | 0/0 |
| **Total** | | **20 / 172** | **11.63%** | **100%** | **0 / 62** | **0** | **0 / 6** |

Severity split: Critical **4/26 (15.4%)**, High **12/91 (13.2%)**, Medium 4/52, Low 0/3 → **H/C 16/117 = 13.7%** (G4 target 65%).

Aggregate funnel and loss buckets:

| Stage / bucket | Count |
| :--- | ---: |
| Target vulns | 172 |
| Surface discovered | 139 (80.8%) |
| Hypothesis formed | 132 |
| Signal observed | **57 (33.1%)** |
| Spec submitted / confirmed | 20 / **20** |
| `replay_spec_miss` | 92 |
| `budget_exhausted` | 23 |
| `surface_miss` | 16 |
| `form_encoding_missing` | 10 |
| `hypothesis_miss` | 8 |
| `csrf_blocked` | 3 |

Confirmed by class (top): BOLA 8/19, IDOR 6/8, BFLA 3/9, SSTI 1/5, OAuth 1/1, open redirect 1/6. **18 classes have zero confirmations**, including SQLi (0/7), SSRF (0/12), stored/reflected XSS (0/11), XXE (0/7), CSRF (0/7), webhook forgery (0/6), race (0/5), and command injection (0/5).

**Precision definition:** `TP / (TP + decoyFP + unmatchedFP)`. The 100% value is over 20 emitted findings with zero decoy and zero unmatched FPs. It does not yet demonstrate precision at a high-recall operating point.

### 4.5 realistic-bench held-out matrix — 15/171 (G9)

Source: `/tmp/m7-specs2/rb-held/*.json` (9 salted scorecards, seeds `1000001/2/42`). This artifact predates the post-M1 dev run; it is the latest preserved held-out matrix, not a same-minute A/B.

| App | Seed | Confirmed / targets | Precision | Decoy FP | Unmatched FP | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1000001 | 2 / 22 | 100% | 0 | 0 | 0/0 |
| acme-saas | 1000002 | 2 / 21 | 100% | 0 | 0 | 0/1 |
| acme-saas | 1000042 | 2 / 22 | 100% | 0 | 0 | 0/1 |
| opsportal | 1000001 | 1 / 16 | 100% | 0 | 0 | 0/1 |
| opsportal | 1000002 | 1 / 16 | 100% | 0 | 0 | 0/1 |
| opsportal | 1000042 | 2 / 17 | 100% | 0 | 0 | 0/1 |
| shopflow | 1000001 | 2 / 18 | 100% | 0 | 0 | 0/0 |
| shopflow | 1000002 | 2 / 20 | 100% | 0 | 0 | 0/1 |
| shopflow | 1000042 | 1 / 19 | 100% | 0 | 0 | 0/0 |
| **Total** | | **15 / 171** | **100%** | **0 / 63** | **0** | **0 / 6** |

Severity: Critical 3/26, High 9/98 → **H/C 12/124 = 9.7%**. Funnel: 171 → 117 surface → 115 hypothesis → **44 signal** → 15 spec → 15 confirmed. Top buckets: `replay_spec_miss` 81, `surface_miss` 64, `hypothesis_miss` 5, `form_encoding_missing` 3, `csrf_blocked` 3, `budget_exhausted` 0.

**Gap:** dev 11.63% vs held-out 8.77% is **−24.6% relative** (2.86 pp absolute). Under a relative “within 10%” reading, G9 fails. The held-out run also predates post-M1 dev changes, so the comparison is directional, not a clean paired test.

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

**Novel finding note (copied from roadmap):** the acme run’s unmatched finding is a novel admin-activity BFLA with oracle evidence, not a planted site. Under the benchmark’s matching rule it still counts as an unmatched FP; the JSON corroborates 2 matched + 1 unmatched finding. Roadmap reports 3 worker bootstrap failures (3–4 assignments, 0 turns) on the acme run; that count is not in the structured JSON. This host snapshot corroborates the bootstrap/cleanup symptom: **51 created, never-started assignment containers**.

Deterministic M0 baseline (copied from roadmap, not re-run here): 11 s, $0, 0/22, 100% precision, 43 endpoints discovered. Agentic reality: wall-clock is the limiter, and worker reliability — not budget — is the first blocker.

### 4.7 M4 corpus and Gate 6

Corpus counts re-derived from `src/templates/compiled/` on this tree:

| Metric | Value | Method |
| :--- | ---: | :--- |
| Compiled YAML templates | **1,724** | count of `src/templates/compiled/**/*.yaml` |
| CVE-named templates, all years | 915 | `cve-*.yaml` |
| CVE-named templates, 2021–2026 | **492** | filename year filter |
| Unique CVE IDs across templates | 916 | unique `cve:` fields |
| Unique CVE IDs with year ≥ 2021 | 493 | year filter on `cve:` field |

The extra modern ID is a non-`cve-`-named template that references a 2021 CVE. The roadmap’s “492 CVEs ≥2021” matches the filename definition. **The brief’s “521 CVEs” is not reproducible from this tree or preserved artifacts** (see §9).

Gate 6 / AST evidence: `tests/v5-m4-sast-templates-patch.test.ts` passes **10/10** under the Docker worker image, including “Gate 6 never passes when skipped” and trivy-fs advisories for Python/Go/Java/Ruby manifests. Compile identity checks (`npm run templates:transpile`) were not re-run; counts are from the committed corpus.

### 4.8 M5 Board Phase 1 UI

| Item | Evidence |
| :--- | :--- |
| Schema/store/SSE + migration | `4b41388`; board tests 8/8 |
| Boundary behavior (redaction, taint, injection delimiters, mention rules) | 6/6 boundary tests |
| Mandatory `Board` tab replaces `Coordinator` | Playwright 1/1; roster state pills, unread badge, evidence chips, inline Tier-3 approval cards, mention autocomplete |
| Composer routing | plain messages route to `@coordinator`; `board_post` honours explicit mentions |
| Workspace redesign port | `ca197a2` (Board in right pane) |

**Count discrepancy:** the brief cites **19/19** board tests. On this tree the measurable total is **14 node tests + 1 Playwright test (15 checks)**; no 19-test suite or preserved log exists. See §9.

---

## 5. Before / after

These are **cumulative main-line deltas**, not isolated per-stream causal claims: M1–M4 merged in close succession and the scorecards were produced at different points.

| Metric | v4 baseline | Current v5 | Delta | Source |
| :--- | ---: | ---: | ---: | :--- |
| XBEN-25 | 25/25 (`9793d2d`) | **24/25** | **−1** | `iter3-merged.json` → `post-m1.json` |
| Held-out SaaS | 20/20 | **20/20** | 0 | `heldout-merged.json` → `post-m1-heldout.json` |
| Held-out patches fixed | 20/20 | **20/20** | 0 | same |
| realistic dev confirmed | 0/172 | **20/172** | **+20** | `rb-score` → `rb-post-m1` |
| realistic dev recall | 0.0% | **11.63%** | +11.63 pp | recomputed |
| realistic dev precision | 0.00 | **1.00** | +1.00 | recomputed |
| realistic dev unmatched FP | 12 | **0** | **−12** | recomputed |
| realistic held-out confirmed | 3/171 | **15/171** | **+12** | `rb-score-heldout` → `m7-specs2/rb-held` |
| realistic held-out precision | 0.20 | **1.00** | +0.80 | recomputed |
| realistic held-out unmatched FP | 12 | **0** | **−12** | recomputed |
| realistic dev surface discovered | 131/172 | **139/172** | +8 | funnel totals |
| realistic dev signal observed | 10 | **57** | **+47** | funnel totals |
| realistic held-out signal observed | 14 | **44** | **+30** | funnel totals |
| realistic chains | 0/1 per run | **0/6** | none completed | scorecards |
| Templates / modern CVE templates | 1,600 (legacy-capped) / — | **1,724 / 492** | +124 / +492 | corpus counts |
| Board UI | Coordinator tab | **Board + Worker Inspector** | — | `4b41388`, Playwright |

Per-milestone headline (same caveat):

| Milestone | Headline delta |
| :--- | :--- |
| M0 | no E2E realistic harness → `benchmark:realistic` drives real `Execution`, per-cell data-dir isolation, inert-run fail-fast |
| M1 | XBEN was at 20/25 before the recovery commit and **24/25** after (`4ad4078`); v4 closed at 25/25. Unmatched realistic FPs 12→**0** |
| M2 | dev surface discovery 131→**139**; authenticated/XHR route maps and session/CSRF hardening merged |
| M3 | held-out realistic 3/171→**15/171** with precision 1.00 and 0 decoys; probes merged (`5aa897c`) |
| M4 | 1,600 legacy-capped templates → **1,724** with **492** modern CVE templates; AST/bridge/Gate 6 merged |
| M5 | Coordinator UI → **Board** with roster, approvals, SSE, redaction/taint boundaries |
| M6 | gate not closed; realism recall, white-box, chains, held-out gap, orphans remain open |

---

## 6. Honest gap list

| Gap | Measured state | Why it matters | Next action |
| :--- | :--- | :--- | :--- |
| Realistic H/C recall | **13.7%** grey-box vs 65% target; white-box unmeasured | Core v5 promise | Attack `replay_spec_miss` (92 dev / 81 held-out), `budget_exhausted` 23, `surface_miss` 16/64, `form_encoding_missing` 10 |
| Signal-stage collapse | 57/132 dev, 44/115 held-out hypotheses produce a signal | Discovery is no longer the only limiter | Per-class trigger coverage; prioritize classes with 0 confirmations (SQLi, SSRF, XSS, XXE, CSRF, webhook, race) |
| Chain completion | **0/6 dev, 0/6 held-out**; XBEN `browser_chain` missed | Gate G8 | Wire M5 chain planning and browser-chain verification; add chain fixtures |
| Held-out generalization | 8.77% vs 11.63% dev (−24.6% relative) | Gate G9 / anti-overfitting | Re-run held-out on the post-M1 tree; tighten overfit-prone rules; report paired deltas |
| White-box mode | not run | Gate G5 | Run the 9-cell matrix with `--mode white-box`; record recall and decoy FPs |
| Agentic worker reliability | 2/22 and 1/19; wall-clock capped; 51 created/never-started containers | Production path cannot scale | Fix worker bootstrap and teardown; keep `--isolate-data-dir`; add an orphan sweep; treat wall-clock as a first-class SLO |
| Precision at scale | 100% on 20 dev + 15 held-out findings | Denominator is small; high recall may add FPs | Track precision per class as recall rises; keep decoy audit |
| Patch attribution | 20/20 fixed, but 2 inconclusive; all-patches is a replay | Avoid overstating clean fixes | Report clean dismissals (18/20) separately; run a fresh all-patches pass; resolve shared-`/graphql` attribution |
| XBEN regression | 25/25 v4 → 24/25 v5 | v4 parity lost on `browser_chain` | Restore `xben-16` without hardcoding; keep ≥23 gate |
| Container hygiene | 51 orphan assignment containers | Violates v4/v5 0-orphan invariant | Drain stale objects; verify no live owner before cleanup; add gate check |
| Full regression gate | v5 suites + harness re-run; v4 519-case matrix not re-run | Release gate is not one pass | Run `docs/reverify-v4.sh` on a Docker host after v5 merges |
| Artifact durability | evidence under `/tmp` | `/tmp` is ephemeral | Copy structured JSON into release storage before cleanup |
| Corpus count claims | 1,724/492 verified; brief’s 521 not found | Prevent unverifiable numbers in release notes | Define CVE count (filename vs field vs curated) in the roadmap |

---

## 7. Known limitations

- **Docs snapshot, not final gate.** Scores were produced by different streams at different times; only the values in §4 are re-derived here.
- **Deterministic vs agentic are separate populations.** The 20/172 matrix is deterministic replay; the 2/22 and 1/19 runs are LLM-driven with wall-clock caps. Do not combine them.
- **Held-out artifact predates post-M1 dev.** `/tmp/m7-specs2/rb-held` is the latest preserved held-out matrix, not a same-commit pair.
- **“Within 10%” is undefined.** The roadmap does not say whether 10% means relative recall drop or absolute percentage points. This document reports both.
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

# v5 suites (124 tests). Use the Docker group so M4-T9 is not skipped.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=1536 &&
  node --test --test-concurrency=1 tests/v5-*.test.ts
'

# Board UI (after build)
npx playwright test tests/guardian-v5-board.spec.ts --workers=1

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

### 8.6 realistic-bench held-out matrix

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

Do not delete containers with a live owner; verify age/status and coordination before cleanup.

---

## 9. Provenance and discrepancies

### 9.1 Number provenance

| Claim | Value used | Provenance | Status |
| :--- | :--- | :--- | :--- |
| XBEN confirmed | 24/25 | `post-m1.json` `confirmedCount` / `targetsTotal` | re-derived |
| Held-out confirmed | 20/20 | `post-m1-heldout.json` | re-derived |
| Held-out patches | 20/20, 18 clean | `patchVerification.perPatch` | re-derived |
| Realistic dev | 20/172, 0/62 decoys, 0 unmatched | sum of 9 `rb-post-m1` scorecards | re-derived |
| Realistic held-out | 15/171, 0/63 decoys | sum of 9 `m7-specs2/rb-held` scorecards | re-derived |
| Agentic acme / shopflow | 2/22, 1/19; costs/times | `agentic-long` + `agentic-shopflow` JSON/meta | re-derived |
| Templates / modern CVEs | 1,724 / 492 | filesystem counts | re-derived |
| Board tests / Playwright | 14/14 + 1/1 | test run | re-derived |
| v5 suites | 124/124, 0 skip | run under Docker group | re-derived |
| Harness tests | 142/142 | test run | re-derived |
| Orphans | 51 created, 0 running | `docker ps -a` | re-derived |
| Worker bootstrap failures (acme) | 3 | roadmap §5 | **copied** |
| Novel admin BFLA | oracle-evidenced, unmatched | roadmap §5 + JSON unmatched ID | **partly copied** |
| Deterministic M0 baseline | 11 s, $0, 0/22 | roadmap §5 | **copied** |
| v4 gate 25/25 | 25/25 | `iter3-merged.json`; `9793d2d` attribution from roadmap | re-derived artifact / **copied** commit |

### 9.2 Discrepancies found during this pass

1. **“521 CVEs” is not reproducible.** The tree contains 1,724 templates, 915 CVE-named files, 916 unique CVE IDs, 492 CVE-named 2021–2026 templates, and 493 unique modern CVE IDs. No 521 count exists in the tree or preserved artifacts. Use 492 (filename definition) or 493 (unique IDs), and state which.
2. **“19/19 Board tests” is not reproducible.** Current total is 14 node tests + 1 Playwright test. The 19 figure is likely a stale pre-merge stream report.
3. **XBEN regressed vs v4.** v4 closed at 25/25 (`9793d2d`); current main is 24/25, missing `xben-16` (`browser_chain`). The v5 ≥23 gate still passes, but “v4 parity” does not.
4. **Orphan gate fails.** 51 created/never-started assignment containers exist. The v4 verification reported 0/0; this snapshot does not. All are `Created`, not running.
5. **Held-out snapshot mismatch.** The latest preserved held-out realistic matrix (`m7-specs2/rb-held`, 15/171) predates the post-M1 dev matrix (20/172). The dev/held-out gap is therefore not a paired measurement.
6. **“Within 10%” ambiguity.** 8.77% vs 11.63% is 2.86 pp absolute (passes a 10-pp reading) but −24.6% relative (fails a relative reading). The roadmap must define the unit before G9 can be scored.
7. **Suite scope.** “100% suites, 0 skips” here means the 124 v5 tests + 142 harness tests + Board UI, not the full v4 519-case matrix. The v5 run is 0-skip only under `newgrp docker`; without Docker, `M4-T9` skips.
8. **Agentic failure counts are partly narrative.** The 3–4 worker-bootstrap failures and the novel-BFLA classification come from the roadmap, not the JSON; the JSON only exposes one unmatched finding ID.

### 9.3 Next review trigger

Refresh this page when any of the following lands: M2.1 acceptance, M3 completion, M5 Phase 1b, a post-M1 held-out realistic run, a white-box matrix, or a clean orphan sweep. The gate table in §2 is the single source of truth for release readiness.
