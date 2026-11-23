# Guardian v5 — Freeze Verification (`VERIFICATION-v5.md`)

**Status:** **v5.0 FREEZE CANDIDATE.** The deterministic engine harness meets G4/G9; the shipped production runtime has **no deterministic floor** in v5.0. The ported engine exists on `agents/engine-port` but was reverted from `main` because it regressed 25 existing Execution/E2E tests. Final release gate is **PENDING**.

**Snapshot:** 2026-11-22, `main` @ `d26cd01` (engine-port revert `a73f07e` + workflow-synthesis restore `d26cd01`), docs branch `agents/docs-v5`.
**Plan:** [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) · [plans/v5.md](plans/v5.md)
**Prior release:** [VERIFICATION-v4.md](VERIFICATION-v4.md)
**Handover:** [HANDOVER-v5.md](HANDOVER-v5.md)

> The two scorecards are not interchangeable. Scorecard B is the deterministic engine harness. Scorecard A is the shipped `Execution` runtime. The 25/59 and 28/59 runtime numbers are a **v5.1 candidate**, not v5.0.

---

## 1. Two surfaces, two scorecards

| Surface | What it measures | v5.0 result | Role |
| :--- | :--- | :--- | :--- |
| **A — Production runtime (`Execution`)** | Real orchestrator, Docker verifier, Tier-3 local-lab | agentic **7/59 (11.9%)**; `--no-llm` **0/59** | Primary product surface; no deterministic floor in v5.0 |
| **B — Deterministic engine harness (procedural)** | `scripts/benchmark-*` hypothesis → probe → spec → `ReplayVerifier` | dev **115/172 (66.9%)**; held-out **111/171 (64.9%)** | Capability engine + hill-climb harness; G4 met here |
| **v5.1 candidate (not shipped)** | Ported deterministic engine inside `Execution` on `agents/engine-port` | `--no-llm` 25/59; agentic 28/59 | Deferred: regressed 25 existing Execution/E2E tests |

The shipped runtime and the procedural harness are ~55 pp apart in v5.0. The candidate port narrows that to ~19 pp but is not in `main`.

---

## 2. Scorecard A — Production Runtime (`Execution`), actual v5.0

Scope: 3 apps, grey-box, dev seed 1, $2/600 s per cell, Tier-3 local-lab, Docker verifier, concurrency 3.

| Mode | Confirmed | Recall | Precision | Decoy / unmatched | Worker failures | Cost | Wall |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--no-llm` | **0 / 59** | **0%** | 0 confirmed; 2 unmatched FPs | 0 / 2 | 0 | $0.00 | 81.5 s total |
| agentic (post race-fix) | **7 / 59** | **11.9%** | **100%** (7/7) | 0 / 0 | 0 | $0.4844 total; $0.069/finding | 1,800 s total |

Per-cell agentic:

| App | Confirmed | Wall | Notes |
| :--- | ---: | ---: | :--- |
| acme-saas | 2 / 22 | 600.1 s | hit wall |
| opsportal | 4 / 18 | 600.1 s | hit wall |
| shopflow | 1 / 19 | 600.1 s | hit wall |
| **Total** | **7 / 59** | 1,800 s | 7 assignments completed, 0 failed |

Agentic funnel: 59 → **25 surface** → 13 hypothesis → 13 signal → 7 spec → **7 confirmed**. Buckets: `budget_exhausted` 34, `hypothesis_miss` 16, `replay_spec_miss` 1, `form_encoding_missing` 1.

`--no-llm` funnel: 59 → 21 surface → 10 hypothesis → 2 signal → 1 spec → **0 confirmed**. Buckets: `surface_miss` 38, `hypothesis_miss` 12, `replay_spec_miss` 6, `trigger_miss` 2, `form_encoding_missing` 1.

**v5.1 candidate (branch `agents/engine-port`, NOT shipped):** `--no-llm` 25/59 (42.4%), agentic 28/59 (47.5%), 100% precision, 0 decoy/unmatched, 0 worker failures, $0.140 total / $0.005 per finding. Two of three cells hit 600 s after the deterministic pass; opsportal exited at 137 s. This candidate is preserved on the branch and deferred because it regressed 25 existing tests (planner budgets, specialist tools, multi-trial, fallback); it must not be cited as v5.0.

---

## 3. Scorecard B — Deterministic Engine Harness (procedural)

Final completed matrix on the freeze tree. Values below are the freeze floors.

| Suite | Confirmed | Recall | Precision | Decoy / unmatched | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: |
| realistic dev | **115 / 172** | **66.9%** | **100%** | 0 / 0 | 1 / 6 |
| salted held-out | **111 / 171** | **64.9%** | **100%** | 0 / 0 | 1 / 6 |
| XBEN-25 | **25 / 25** | 100% | 100% | 0 / 0 | — |
| held-out-saas | **20 / 20** | 100% | 100% | 0/6 decoys | — |
| held-out-saas patches | **20 / 20 fixed** | — | — | `allPatches=fixed` | — |

- Dev → held-out gap: **−2.0 pp** (64.9% vs 66.9%), within 10 pp.
- **G4 MET** on this surface: all-severity 66.9%; H/C **83/117 = 70.9%**.
- **G8 still open:** chains **1/6 dev, 1/6 held-out**.

Dev funnel: 172 → 162 surface → 162 hypothesis → 131 signal → 117 spec → **115 confirmed**. Buckets: `replay_spec_miss` 41, `budget_exhausted` 10, `form_encoding_missing` 3, `csrf_blocked` 3.

Held-out funnel: 171 → 162 surface → 162 hypothesis → 132 signal → 112 spec → **111 confirmed**. Buckets: `replay_spec_miss` 46, `budget_exhausted` 7, `form_encoding_missing` 2, `csrf_blocked` 3, `surface_miss` 2.

Class highlights (dev / held-out): BOLA 17/19 / 17/18; SQLi 4/7 / 3/10; stored XSS 6/6 / 4/6; path traversal 6/6 / 9/9; XXE 7/7 / 5/5; SSRF 11/12 / 11/12; CSRF 7/7 / 4/5; command injection 5/5 / 5/5; info disclosure 7/9 / 11/13; mass assignment 6/11 / 5/9; JWT 1/6 / 2/4; business logic 5/12 / 5/11; workflow 5/10 / 3/5.

---

## 4. Convergence gap: B → A

**v5.0 framing: the product has no deterministic floor.** Real `Execution` is 7/59 agentic and 0/59 `--no-llm`; the procedural harness is 115/172. The ported engine that closed this loop was reverted because it broke 25 existing tests.

| Cause | Evidence | Impact | v5.1 action |
| :--- | :--- | :--- | :--- |
| Engine-port was reverted | `a73f07e`; 25 existing Execution/E2E tests regressed (planner budgets, specialist tools, multi-trial, fallback) | Shipped runtime has no deterministic closed loop | Rebuild the port without regressing planner/tool/trial behavior |
| Latest JWT/mass converters not ported into `src/server/deterministic-engine.ts` | Candidate still used an older converter set | Missing runtime class coverage | Port remaining converters |
| `Execution` surface ingestion is incomplete | v5.0 agentic surface 25 endpoints / 59 targets; candidate 45 / 59 | Targets never reach the runtime loop | Full surface ingestion + evidence-derived discovery |
| 600 s wall consumed by deterministic pass (candidate) | Candidate: 2/3 cells at 600 s, opsportal 137 s | Specialists get little wall clock | Reallocate deterministic vs specialist budgets; document early stop |
| Specialist deterministic-pair scope guard (candidate) | Only engine-triaged `(endpoint, class family)` pairs accepted | Fail-safe precision, but blinds novel logic/workflow/chain/white-box recall | Replace with ReplayVerifier proof-strength + endpoint binding |

**Gap size:** v5.0 **66.9% − 11.9% = 55.0 pp**. The v5.1 candidate narrows it to **19.4 pp** (66.9% − 47.5%), but is not shipped.

### 4.1 v5.1 candidate guardrail (not in v5.0)

The candidate carries a specialist deterministic-pair scope guard: local-lab LLM specs are accepted only when the normalized `(endpoint, class family)` pair was triaged by the deterministic engine, or the family is already confirmed. It is fail-safe and precision-preserving, but deliberately blinds novel logic, workflow, chain, and white-box recall. It is scheduled for replacement in v5.1 by `ReplayVerifier` proof-strength and endpoint-binding guards. This guard is on `agents/engine-port`, not in the v5.0 runtime.

---

## 5. Tier-3 safety and containment (shipped)

Five invariants, covered by `tests/v5-tier3-safety.test.ts` (**8/8**) and together with `tests/approval-judge.test.ts` (**15/15**):

| # | Invariant | Enforcement |
| :--- | :--- | :--- |
| 1 | Environment isolation | Tier-3 auto-approval only for `environment === 'local-lab'`; public/unspecified always escalates; `GUARDIAN_ALLOW_LOCAL_LAB=1` alone never relaxes public rules |
| 2 | Origin binding | Only loopback, RFC1918 lab/container subnets, and single-label Docker/LabRunner aliases auto-approve; external/mislabeled origins fall back to public hard escalation |
| 3 | Strict precedence | Explicit `strict` always escalates before any auto-approval |
| 4 | Broker guards survive | Destructive/webshell denylists, metadata/link-local SSRF denial (`169.254/16`, `fe80::/10`), RPS caps remain fail-closed |
| 5 | Audit attribution | Auto-approvals attributed `auto-review:local-lab` and persisted before the state change leaves the broker |

**Containment fix** (`343bf16`, confirmation `0fd6127`): auto-approved local-lab writes no longer follow redirects to external hosts. Redirect hops are checked against lab containment, not just `canRead`; external hops are denied and audited, while relative/same-loopback/container-alias redirects still work. The project schema default `environment` is **public** and fails closed; a loopback seed does not become local-lab implicitly.

---

## 6. Release gates

**Release gate status: PENDING.** The freeze `reverify-v5.sh --full` run in `/tmp/guardian-reverify-v5.GtumGa` completed while the tree was still changing and reported failures (2 v4, 6 v5, 17 tiered E2E); it is **not** a clean certification. Last clean full gate was **980/980** before the engine-port revert; the final freeze rerun count is pending.

| # | Gate | Target | Current evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| G1 | XBEN-25 | ≥ 23/25 | **25/25**, 0 FP | **MET** |
| G2 | Held-out SaaS | ≥ 18/20 | **20/20**, 6/6 decoys clean | **MET** |
| G3 | Held-out patches | ≥ 14/20 | **20/20 fixed**; `allPatches=fixed` | **MET, with caveat** |
| G4 | Realistic H/C recall — grey-box | ≥ 65% | deterministic H/C **70.9%**; all-severity **66.9%** | **MET** (deterministic surface) |
| G5 | Realistic H/C recall — white-box | ≥ 80% | not measured | **NOT MEASURED** |
| G6 | Precision | ≥ 95% | deterministic **100%** (115/115, 111/111); agentic **100%** (7/7); `--no-llm` 0 confirmed + 2 unmatched FPs | **PARTIAL** |
| G7 | Decoy FP | ≤ 5% | 0/62 dev, 0/63 held-out; runtime 0/19 | **MET** |
| G8 | Chain completion | ≥ 50% | **1/6 dev, 1/6 held-out** | **NOT MET** |
| G9 | Held-out within 10 pp | ≤ 10 pp absolute | **−2.0 pp** all-severity; H/C −3.2 pp | **MET** |
| G10 | Full release gate | 100% pass, 0 skips | freeze gate **PENDING**; last clean **980/980** pre-revert | **PENDING** |
| G11 | Orphan containers/networks | 0 / 0 | direct check **0** stale `Created`, **0** networks | **PASS** (gate pending) |

**Scorecard:** 6 met, 1 met-with-caveat, 1 partial (G6), 1 not met (G8), 1 not measured (G5), 1 pending (G10). **G4 is met on the deterministic surface, not on production `Execution`.**

---

## 7. Milestones

| # | Status | Notes |
| :--- | :--- | :--- |
| M0 | **DONE** | E2E realistic harness, per-cell isolation, inert-run preflight |
| M1 | **DONE** | Wiring, canaries, dedupe, routing, guard/sanitizer, CVE semver, recon halt fix |
| M2 | **DONE** | State graph, recon, auth/session, coverage, ID harvest, BOLA queue |
| M3 | **DONE** | Probes/verifiers, SSRF/XXE realism, probes3/contracts |
| M4 | **DONE** | Templates/AST/bridge/Gate 6; 1,724 templates, 492 modern CVE-named (493 unique IDs) |
| M5 | **DONE** | Board UI, board tools, deterministic posters, warm specialists/handoffs |
| M6 | **PARTIAL** | Deterministic matrix measured; runtime has no floor; final gate, white-box/salted Execution matrices, chains, engine-port rebuild remain |

Commits: Tier-3 safety `76a4903`, containment `343bf16`, engine-port candidate `abcbd29` (branch), revert `a73f07e`, workflow restore `d26cd01`.

---

## 8. Before / after

| Metric | Pre-freeze v5 | Freeze v5.0 | Delta |
| :--- | ---: | ---: | ---: |
| Deterministic dev | 86/172 (50.0%) | **115/172 (66.9%)** | **+16.9 pp** |
| Deterministic held-out | 87/171 (50.9%) | **111/171 (64.9%)** | **+14.0 pp** |
| Deterministic H/C dev | 54.7% | **70.9%** | +16.2 pp |
| Deterministic chains | 0/6 | **1/6** | +1 |
| XBEN | 25/25 | **25/25** | 0 |
| Held-out SaaS / patches | 20/20 / 20/20 | **20/20 / 20/20** | 0 |
| Runtime `--no-llm` | 0/59 | **0/59** | 0 (engine-port reverted) |
| Runtime agentic | 12/117 stale | **7/59 (11.9%)** | new scope |
| Runtime precision | 66.7% stale | **100%** (7/7) | +33.3 pp |
| Runtime worker failures | 39.3% stale | **0** | fixed |

The 25/59 and 28/59 numbers are **not** in this table because they are not shipped. They are the v5.1 candidate.

---

## 9. Known limitations / v5.1 priorities

1. **No deterministic floor in shipped `Execution`.** The port exists on `agents/engine-port`; rebuild it without the 25 regressions.
2. **Port regressions to fix:** planner budgets, specialist tools, multi-trial, fallback.
3. **Surface ingestion:** v5.0 runtime sees 25/59; full ingestion is required.
4. **Specialist scope guard:** candidate-only; blinds novel logic/workflow/chain/white-box recall; replace with proof-strength + endpoint binding.
5. **Wall-clock:** candidate behavior (2/3 at 600 s, opsportal 137 s) needs budget allocation.
6. **White-box and salted Execution matrices** are v5.1.
7. **Chains remain 1/6 (16.7%)**, below 50%.
8. **Release gate pending;** do not quote the pre-revert 980/980 as the freeze result.
9. **Patch evidence** includes 2 inconclusive-after retests and a replay-based all-patches pass.
10. **No external targets, secrets, or salts.**

---

## 10. Reproduction

### 10.1 Shipped runtime (Scorecard A)

```bash
# Agentic, 3 apps, seed 1, Tier-3 local-lab, $2 / 600 s cells.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
         NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v5-runtime-agentic
'

# No-LLM baseline (0/59 expected on v5.0 main).
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box --no-llm \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v5-runtime-no-llm
'
```

### 10.2 Deterministic harness (Scorecard B)

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- \
  --app all --seeds 1,2,42 --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/v5-dev

# Salt lives at ~/.config/guardian-bench/heldout.salt (mode 600); never echo it.
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
npm run benchmark:realistic -- \
  --app all --seeds 1000001,1000002,1000042 --held-out --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/v5-held
unset GUARDIAN_RB_HELDOUT_SALT
```

### 10.3 v5.1 candidate (branch only)

```bash
git switch agents/engine-port
# Same Scorecard A commands; the candidate reports 25/59 no-LLM and 28/59 agentic.
# Do not merge until the 25 Execution/E2E regressions are fixed.
```

### 10.4 Freeze gate, Tier-3 safety, OOB, secrets

```bash
newgrp docker -c 'bash docs/reverify-v5.sh --full'          # PENDING

GUARDIAN_ALLOW_LOCAL_LAB=1 \
  node --test tests/v5-tier3-safety.test.ts tests/approval-judge.test.ts   # 15/15
```

OOB callbacks bind one **loopback** canary listener; the harness passes that exact port to the app allowlist. Pin with loopback-only `GUARDIAN_CANARY_PORT` / `GUARDIAN_CANARY_DNS_PORT`; never bind off-loopback. `secretMatches` is `{kind, sha256Prefix, fieldPath?, count}` only; correlate against a locally held secret, never log the raw value.

---

## 11. Provenance and remaining discrepancies

| Claim | Source | Status |
| :--- | :--- | :--- |
| Runtime agentic 7/59, $0.4844 | `/tmp/m6-postrace/matrix.json` | re-derived |
| Runtime no-LLM 0/59, 2 unmatched | `/tmp/engine-port-baseline/matrix.json` | re-derived |
| v5.1 candidate 25/59, 28/59, $0.140 | `/tmp/engine-port-final-no-llm`, `/tmp/tier3-agentic` | re-derived, **not shipped** |
| Deterministic dev 115/172, held-out 111/171 | `/tmp/v5-final2/dev`, `/tmp/v5-final2/held` | re-derived, final rerun |
| XBEN 25/25, held-out 20/20 + patches | `/tmp/guardian-m7-bench/final-dev.json`, `final-held.json` | re-derived |
| Tier-3 safety 8/8 and 15/15 | test runs | re-derived |
| Freeze gate | in-flight `GtumGa` log; last clean 980/980 | **PENDING** |

**Discrepancies:**

1. **Engine-port is not shipped.** `a73f07e` reverted the merge; 25 existing Execution/E2E tests regressed. The 25/59 and 28/59 results are v5.1 candidate only.
2. **Shipped runtime has no deterministic floor:** agentic 7/59 (11.9%), no-LLM 0/59.
3. **Scorecard B is deterministic-only:** 66.9% dev / 64.9% held-out; do not present it as the product runtime.
4. **G4 is met on the deterministic surface only.**
5. **G9 is all-severity (−2.0 pp); H/C is −3.2 pp** (70.9% dev vs 67.7% held-out). Both are within 10 pp.
6. **Chains are 1/6**, below 50%; G8 open.
7. **Freeze gate PENDING:** latest run was not clean; pre-revert 980/980 is not the freeze result.
8. **Final deterministic rerun:** dev holds at 115/172; held-out is 111/171, one below the earlier 112. The document uses the final rerun values.
