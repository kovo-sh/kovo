# Guardian v5 — Freeze Handover (`HANDOVER-v5.md`)

**Status:** **v5.0 FREEZE CANDIDATE** — deterministic engine meets G4/G9; shipped `Execution` has no deterministic floor; final gate pending.
**Snapshot:** 2026-11-22, `main` @ `d26cd01` (engine-port revert `a73f07e`)
**Read first:** [VERIFICATION-v5.md](VERIFICATION-v5.md) · [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md)
**Previous line:** [HANDOVER-v4.md](HANDOVER-v4.md) · [VERIFICATION-v4.md](VERIFICATION-v4.md) (historical)

---

## 1. Two scorecards

### A — Shipped production runtime (`Execution`), actual v5.0

Scope: 3 apps, grey-box, dev seed 1, $2/600 s per cell, Tier-3 local-lab, Docker verifier.

| Mode | Confirmed | Recall | Precision | Decoy/unmatched | Worker failures | Cost |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--no-llm` | **0 / 59** | **0%** | 0 confirmed; 2 unmatched FPs | 0 / 2 | 0 | $0.00 |
| agentic (post race-fix) | **7 / 59** | **11.9%** | **100%** (7/7) | 0 / 0 | 0 | **$0.4844** total; $0.069/finding |

Agentic per-cell: acme 2/22, opsportal 4/18, shopflow 1/19; all three hit the 600 s wall. No shipped deterministic floor.

### B — Deterministic engine harness (procedural)

| Suite | Confirmed | Recall | Precision | Gap |
| :--- | ---: | ---: | ---: | ---: |
| realistic dev | **115 / 172** | **66.9%** | 100% | — |
| salted held-out | **111 / 171** | **64.9%** | 100% | **−2.0 pp** |
| XBEN-25 | **25 / 25** | 100% | 100% | — |
| held-out-saas | **20 / 20** + **20/20 patches** | 100% | 100% | `allPatches=fixed` |

H/C: **70.9% dev**, **67.7% held-out**. Chains: **1/6** both splits. Final deterministic rerun completed: **115/172 dev, 111/171 held-out**.

### v5.1 candidate — NOT shipped

`agents/engine-port`: `--no-llm` 25/59, agentic 28/59, 100% precision, 0 decoy/unmatched, 0 worker failures, $0.140 / $0.005 per finding. Deferred because the merge regressed 25 existing Execution/E2E tests (planner budgets, specialist tools, multi-trial, fallback). Do not cite as v5.0.

---

## 1b. v5.1 integration (in progress)

**Status:** **v5.0 stays frozen.** The engine-port was reverted (`a73f07e`) after 25 Execution/E2E regressions, and integration restarted as **five slices behind a default-off flag**. Slices **1–2 are in progress**; slices 3–5 are gated on their results. No v5.1 number is shipped until the flag flips.

| # | Slice | Status |
| :--- | :--- | :--- |
| 1 | Standalone engine modules + structural dedupe `(origin, endpoint, method, param/resolver, cwe)` | **IN PROGRESS** |
| 2 | `deterministicOnly` path outside M1 fallback; verified-only persistence + `det_lead` facts | **IN PROGRESS** |
| 3 | Non-blocking concurrent agentic lane, default-off flag, seeded-step guard, 30% / 180 s cap, K=6/budget isolation, no step cancellation | **NOT STARTED** |
| 4 | Replace specialist scope guard with `ReplayVerifier` proof-strength + endpoint binding | **NOT STARTED** |
| 5 | Flip the default + parity port | **NOT STARTED** |

**Pre-flip gates (all with the flag ON):**

1. Full suite green, 0 failures / 0 skips / 0 orphans.
2. `dynamicStepBudget` / K=6 / M1 fallback invariants hold.
3. `Execution --no-llm` **≥ 25/59 at 100% precision**.
4. Agentic **strictly additive**: ≥ 95% precision, ≤ 10 pp held-out gap, no lost confirmations.
5. Legacy floors: XBEN 25/25, held-out-saas 20/20 + 20/20 patches, deterministic dev 115/172, held-out 111/171, 0 orphans.

**Chain-safety rules (release-blocking):** never cancel a specialist step or hide a confirmed route (chains break); give specialists read-only “Already Confirmed” context; preserve white-box `static_verified` findings; persist unconfirmed candidates as `det_lead` facts; dedupe per endpoint, never origin+CWE only.

Full detail: [VERIFICATION-v5.md §0](VERIFICATION-v5.md#0-v51-integration-in-progress).

---

## 2. Convergence gap

**v5.0: the product has no deterministic floor.** Shipped runtime is 7/59 agentic (11.9%) and 0/59 no-LLM; procedural is 115/172 (66.9%) — a **55 pp** gap. The ported engine exists on `agents/engine-port` but is deferred; its gap to procedural is ~19 pp.

| Cause | v5.1 action |
| :--- | :--- |
| Engine-port reverted (`a73f07e`); 25 existing tests regressed | Rebuild without planner/tool/multi-trial/fallback regressions |
| Latest JWT/mass converters not ported into `src/server/deterministic-engine.ts` | Port remaining converters (candidate branch) |
| `Execution` surface ingestion incomplete (v5.0 25 endpoints / 59 targets; candidate 45 / 59) | Full surface ingestion + evidence-derived discovery |
| 600 s wall consumed by deterministic pass (candidate) | Reallocate budgets; document opsportal early stop |
| Specialist deterministic-pair scope guard (candidate) | Replace with ReplayVerifier proof-strength + endpoint binding |

---

## 3. Tier-3 safety (shipped)

Five invariants: environment isolation, origin binding, strict precedence, broker guards (destructive/webshell/metadata-SSRF/RPS), audited `auto-review:local-lab` attribution.

Containment fix (`343bf16`, `0fd6127`): external redirect hops denied in local-lab; project environment defaults to **public** and fails closed; relative/loopback/container-alias redirects still work; metadata/link-local SSRF stays blocked.

Tests: **8/8** Tier-3 safety; **15/15** with `approval-judge`.

---

## 4. Gates

| Gate | Status |
| :--- | :--- |
| G1 XBEN ≥23 | **MET** (25/25) |
| G2 held-out ≥18 | **MET** (20/20) |
| G3 patches ≥14 | **MET** (20/20, caveat) |
| G4 H/C ≥65% | **MET on deterministic harness** (70.9%); runtime 11.9% |
| G5 white-box ≥80% | **NOT MEASURED** |
| G6 precision ≥95% | **PARTIAL** — deterministic 100%, agentic 7/7; `--no-llm` 0 confirmed + 2 unmatched FPs |
| G7 decoy FP ≤5% | **MET** (0) |
| G8 chains ≥50% | **NOT MET** (1/6) |
| G9 held-out within 10 pp | **MET** (−2.0 pp all-severity; −3.2 pp H/C) |
| G10 release gate | **PENDING** — freeze run not clean; last clean 980/980 pre-revert |
| G11 orphan hygiene | **PASS** direct check (0 stale, 0 networks); gate pending |

**Do not quote Scorecard B as the runtime result.** The final v5.0 gate recorded in [VERIFICATION-v5.md §6](VERIFICATION-v5.md#6-release-gates) is **PASS 992/992**; the table above preserves the earlier pre-final snapshot.

---

## 5. Milestones

M0–M5 **DONE**; M6 **PARTIAL** — deterministic matrix measured, runtime has no floor, final gate/white-box/salted Execution/chains/engine-port rebuild remain.

---

## 6. v5.1 priorities

These are now executed as the five slices in §1b, in order; slices 3–5 stay gated on 1–2.

1. Land slices 1–2 (standalone engine modules + structural dedupe; `deterministicOnly` path + `det_lead` facts).
2. Land slice 3 behind the default-off flag without step cancellation or confirmed-route hiding.
3. Replace the specialist scope guard with proof-strength + endpoint-binding guards (slice 4).
4. Run the flag-ON pre-flip gate: floor ≥25/59, agentic additive ≥95% precision / ≤10 pp gap, 0 orphans, legacy floors.
5. Flip the default only after parity (slice 5), then run salted held-out and white-box `Execution` matrices.
6. Raise chains from 1/6 to ≥50%.
7. Preserve artifacts and update the v5.1 verification record.

---

## 7. Reproduction

Use [VERIFICATION-v5.md §10](VERIFICATION-v5.md#10-reproduction).

```bash
# Shipped runtime scorecard A
newgrp docker -c 'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data && node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --verifier docker --isolate-data-dir --concurrency 3 --budget-usd 2 --max-duration-ms 600000 --out-dir /tmp/v5-runtime-agentic'

# No-LLM baseline (0/59 on v5.0)
newgrp docker -c 'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 && node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm --verifier docker --isolate-data-dir --concurrency 3 --budget-usd 2 --max-duration-ms 600000 --out-dir /tmp/v5-runtime-no-llm'

# Freeze gate (v5.0: PASS 992/992)
newgrp docker -c 'bash docs/reverify-v5.sh --full'

# v5.1 integration loop (smoke; use --full once per batch)
newgrp docker -c 'bash scripts/hillclimb-loop.sh'

# Tier-3 safety
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v5-tier3-safety.test.ts tests/approval-judge.test.ts
```

OOB listeners are loopback-only; pin with `GUARDIAN_CANARY_PORT` / `GUARDIAN_CANARY_DNS_PORT`. Salt stays in `GUARDIAN_RB_HELDOUT_SALT`, never printed.

---

## 8. Commit anchors

| Area | Commit |
| :--- | :--- |
| Engine-port candidate | `abcbd29` (branch `agents/engine-port`) |
| Revert from main | `a73f07e` |
| Workflow-synthesis restore | `d26cd01` |
| Tier-3 safety | `76a4903` |
| Tier-3 containment | `343bf16` / `0fd6127` |
| Final replay specs | `4a37c2c` / `2d1d8f4` |

---

## 9. Honest limitations

**v5.0 (shipped record):** the deterministic engine harness is 66.9% dev / 64.9% held-out (G4/G9 met), but the real `Execution` path is 11.9% agentic / 0% no-LLM because the port was reverted. Chains are 1/6, white-box is unmeasured, salted/white-box runtime matrices are v5.1, and patch evidence includes two inconclusive-after retests plus a replay-based all-patches pass.

**v5.1 (in progress):** the integration flag is default-off, so `main` still behaves as v5.0. Slices 1–2 are in progress and 3–5 have not started. Candidate 25/59 / 28/59 is reference only; no v5.1 number is shipped. The scope guard still blinds novel/workflow/chain/white-box recall until slice 4, chain-safety is not yet proven end-to-end, and wall-clock/held-out parity are unmeasured design targets. Only a flag-ON, 0-skip run that passes the §1b gates qualifies as a v5.1 release gate.
