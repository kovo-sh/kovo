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

**Do not quote Scorecard B as the runtime result.**

---

## 5. Milestones

M0–M5 **DONE**; M6 **PARTIAL** — deterministic matrix measured, runtime has no floor, final gate/white-box/salted Execution/chains/engine-port rebuild remain.

---

## 6. v5.1 priorities

1. Rebuild the engine-port without the 25 Execution/E2E regressions.
2. Port remaining JWT/mass converters and close surface ingestion.
3. Replace the specialist scope guard with proof-strength + endpoint-binding guards.
4. Fix wall-clock allocation and opsportal early stop.
5. Run salted held-out and white-box `Execution` matrices.
6. Raise chains from 1/6 to ≥50%.
7. Finalize the release gate and preserve artifacts.

---

## 7. Reproduction

Use [VERIFICATION-v5.md §10](VERIFICATION-v5.md#10-reproduction).

```bash
# Shipped runtime scorecard A
newgrp docker -c 'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data && node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --verifier docker --isolate-data-dir --concurrency 3 --budget-usd 2 --max-duration-ms 600000 --out-dir /tmp/v5-runtime-agentic'

# No-LLM baseline (0/59 on v5.0)
newgrp docker -c 'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 && node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm --verifier docker --isolate-data-dir --concurrency 3 --budget-usd 2 --max-duration-ms 600000 --out-dir /tmp/v5-runtime-no-llm'

# Freeze gate (PENDING at this snapshot)
newgrp docker -c 'bash docs/reverify-v5.sh --full'

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

v5.0 ships the deterministic engine harness at 66.9% dev / 64.9% held-out (G4/G9 met), but the real `Execution` path is 11.9% agentic / 0% no-LLM because the port was reverted. Chains are 1/6, white-box is unmeasured, salted/white-box runtime matrices are v5.1, the final gate is pending, and patch evidence includes two inconclusive-after retests plus a replay-based all-patches pass.
