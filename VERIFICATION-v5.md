# Guardian v5 — Freeze Verification (`VERIFICATION-v5.md`)

**Status:** **v5.0 FREEZE CANDIDATE.** The deterministic engine harness meets G4/G9; the shipped production runtime has **no deterministic floor** in v5.0. The ported engine exists on `agents/engine-port` but was reverted from `main` because it regressed 25 existing Execution/E2E tests. Final release gate: **992/992 PASS** (0 failures, 0 skips, 0 orphans; `/tmp/guardian-reverify-v5.5in05x`).

**Snapshot:** 2026-11-22, `main` @ `d26cd01` (engine-port revert `a73f07e` + workflow-synthesis restore `d26cd01`), docs branch `agents/docs-v5`.
**Plan:** [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) · [plans/v5.md](plans/v5.md)
**Prior release:** [VERIFICATION-v4.md](VERIFICATION-v4.md)
**Handover:** [HANDOVER-v5.md](HANDOVER-v5.md)
**v5.1 integration:** in progress behind a default-off flag — see [§0](#0-v51-integration-in-progress). The v5.0 scorecards in §2–§3 are unchanged and remain the shipped numbers.
**v7 planning snapshot:** current measured state and the smoke battery — see [§V7](#v7-planning-snapshot-2026-11-23--not-a-release-claim). It is a **planning record**, not a release claim.

> The two scorecards are not interchangeable. Scorecard B is the deterministic engine harness. Scorecard A is the shipped `Execution` runtime. The 25/59 and 28/59 runtime numbers are a **v5.1 candidate**, not v5.0.
>
> Everything in §0–§11 is **historical** (v5.0 freeze + v5.1 integration record). The current line is v7 planning; its numbers live only in §V7 and are labelled with their measurement scope.

---

## v7 planning snapshot (2026-11-23) — not a release claim

> **This section is new and supersedes nothing.** The v5.0 freeze record (§2–§3, §6) and the v5.1 integration record (§0) stay intact and historical. Nothing below is a release gate result, a certification, or a shipped number. It records what the v6 line measured, what it did not, and the battery/protocol v7 will use to turn a measurement into a claim.

**Status:** v7 **M0/M2/M4 landed; Queue #14 Unified Agentic Matrix & Tier-1 Warm Smoke complete** (2026-11-24, `main` @ `fb93a8a`, Queue #14 measured on `4010d05`). Recorded: **100.0% worst-run precision across BOTH full Unified Agentic Matrices** (Dev **36/59** + Salted Held-Out **29/58**, `shopflow` back to `100.0%`, `0` decoy/unmatched FPs, `0` stalls, `0` conflicts), **21/21 live `agent_script` `ProofReceipt` confirmations** across all 3 Queue #14 legs (including net-new `acme.invoice-bola` `CWE-639` on both Dev & Held-Out), Tier-1 warm `throughput` **12 completed (PASS)** + `trap-zero` **0 (PASS)**, **all 3 Realism suites CAPABILITY PASS @ 100%**, **`held-out-saas` 20/20 + 20/20 patches @ 100%** restored (`fb93a8a`), `xben-25` **25/25 @ 100%**, `execution.ts` **5,388 LOC** (−61.4%), `replay-verifier.ts` **2,657 LOC** (Cut 3e `f9dc5d4` retired `browser_chain` + 4 legacy VMs & fixed the `4375eb8` `-2` XSS regression), M2 white-box/4-hop chains (`4f09411`), M4 production ops (`53ca9f2`), and `plans/v8.md` (`1a3cebc`). Aggregate M1 recall target (`>= 40/59` dev / `>= 32/58` held-out) is **not yet certified** — Queue #15 on post-`fb93a8a` `main` will measure recovered XSS floor + M2/M1 lift.

### V7.1 Current measured numbers (`main` through `fb93a8a`)

All product rows are real `Execution` on the 3-app realistic cells (`acme-saas`, `shopflow`, `opsportal`), grey-box, Tier-3 local-lab, Docker verifier (`--verifier docker --isolate-data-dir --concurrency 1`), wordlists off (`--no-conventional-wordlist`), serial unless noted.

| Measure | Result | Commit / Scope / Caveat |
| :--- | :--- | :--- |
| Product floor (`Execution --no-llm`, dev seed 1) | **37 / 59 (62.7%)**, **100%** precision, 0 decoy/unmatched FPs | `aca8262`: acme **14/22**, shopflow **13/19** (`api-jwt-alg-none` confirmed), opsportal **10/17**; 0 spread on prior 36/59 repeat |
| Salted held-out product floor (`Execution --no-llm`, seed `1000042`) | **29 / 58 (50.0%)**, **100%** precision, 0 decoy/unmatched FPs | `aca8262`: acme **11/22**, shopflow **11/19** (`api-jwt-alg-none` confirmed), opsportal **7/17**; 0 `broker.persona_scope_mismatch` events |
| Live `guardian_verify` (`proof_kind='agent_script'`) on Docker | **21/21** live `agent_script` confirmations carried verified `ProofReceipt` (`0` stalls, `0` crashes, `0` conflicts) | Queue #14 (`4010d05`): 7/7 Dev (`79` calls, `0` val errors) + 7/7 Held-Out (`89` calls, `0` val errors) + 7/7 Tier-1 Smoke (`4` lift, `1` rotation, `1` monorepo, `1` staging) |
| Unified agentic — Dev seed 1 (`600s/cell`, `K=6`, `$1.716`) | **36 / 59 (61.0%)** (14/13/9), **100.0%** precision, 0 decoy/unmatched FPs, 0 stalls, `41 confirmed / 0 conflicts` | Queue #14 (`4010d05`): net-new **`acme.invoice-bola` (`CWE-639`)**; caught `-2` reflected-XSS floor regression (`4375eb8`: `acme.reflected-search-xss`, `og.account-search-xss`), fixed in Cut 3e (`f9dc5d4`) |
| Unified agentic — Salted held-out `1000042` (`600s/cell`, `K=6`, `$1.536`) | **29 / 58 (50.0%)** (11/11/7), **100.0%** precision, 0 decoy/unmatched FPs, 0 stalls, `35 confirmed / 0 conflicts` | Queue #14 (`4010d05`): **`shopflow` back to 100.0%**, net-new **`acme.invoice-bola` (`CWE-639`)**; same `-1` `acme.reflected-search-xss` regression fixed in `f9dc5d4` (30/58 without it) |
| Tier-1 Smoke (`--tier 1`, warm agentic post-floor snapshots, `$1.199`) | **Tier 0 PASS; 5/8 Tier-1 PASS** (`trap-zero` 0, `paired-net-new` `+1`/`+1`, `crashes` 0, **`throughput` 12 completed**, `cost` `$0.494/$0.413/$0.113/$0.179`) | Queue #14 (`4010d05`): 3 failed gates — `conversion` (`--resume-snapshot` accounting bug fixed on `swarm/v7-smoke-fix`), `precision-lift` (`1 unmatchedFP` in `lift`; `rotation` `100.0%`), `p50-assignment` (`lift 98.6s` PASS, `rotation/opsportal 268.2s`) |
| XBEN-25 (`--verifier-backend docker`) | **25 / 25 (100%)**, 100% precision, 0 FP | `51819a8` (after Cut 3c-1/3c-2 SQL + Cut 3d `race_burst` VM retirement) |
| `held-out-saas --verify-patches` (`--verifier-backend local-jq`) | **20 / 20 (100%)** + **20 / 20 patches fixed** + all-patches **20 / 20 dismissed**, 100.0% precision, 0 FP | `fb93a8a` (`5b77b1c`): `BENCH_MAX_REQUESTS_DEFAULT 3800 -> 6000` (`4,228/6,000`, `0` budgetSkipped) + GraphQL object-scoped arg/var precision check (`hos-02`) |
| Realism #2 (`wan-oob --no-llm`, Docker) | **CAPABILITY PASS — 4 / 4 (100%)**, 100% precision (3 TP / 0 FP) | `aca8262`: blind SQLi timing (`CWE-89`), async SSRF ✅, async XXE ✅, `wan-oob-exfil` **3/3**, `oob_wiring_fnr: 0.0%` |
| Realism #3 (`staging-concurrency`, Docker) | **CAPABILITY PASS — 3 / 3 (100%)**, 100% precision | Write-BOLA, h2 single-packet race (2 ms spread, 4 acks / 1 debit), checkout tampering; 0 leaks |
| Realism #4 (`monorepo-whitebox`, Docker) | **CAPABILITY PASS — 3 / 3 (100%)**, chain `2/2`, 100% precision | Canonical spec synthesis (`fe578db`, fallbacks deleted) |
| `src/server/execution.ts` size | **5,388 LOC** (down from `13,960 LOC`, **−61.4%**) | `2e1b2ed`: −468 net `src/` LOC, 4/4 parity PASS @ 100% |
| `src/server/replay-verifier.ts` size | **2,657 LOC** (down from `4,268 LOC`, **−37.7% / −1,611 LOC**) | Cut 3c-1 + Cut 3c-2 + Cut 3d + Cut 3e (`f9dc5d4`: retired `browser_chain` & 4 legacy VMs, −806 LOC) |
| M2 (White-box / 4-hop Chains) & M4 (Production Ops) & v8 Plan | Merged on `main` (`fb93a8a`) | M2 `4f09411` (white-box-first AST/RBAC diff, typed `ChainHops`, `reason-bench` readiness); M4 `53ca9f2` (signed scope, `<2s` kill switch, ZDR/TTL/audit, tenant isolation, coverage gaps, `ProofReceipt` export); v8 plan `1a3cebc` (`plans/v8.md`) |
| Product UX & Kovo brand kit | Shipped on `main` (`fb93a8a`) | Option 3 unified `.rw` workbench (`e7f526d`, `ecd953a`, `03e9cdf`), Kovo SVG/favicon kit (`cce25e3`), vault GitHub PAT + repo auto-discovery (`4d70351`, `370b9c2`), Phase-0 CT-log subdomain discovery + `*.domain` opt-in & unchecked third-party CNAMEs (`266c478`), multi-device pairing (`3e075f0`), Prototype A `New run` dialog (`107cc31`), `Test Accounts` UI rename (`a985be9`) |

**Scope rule carried forward:** product capability is always reported as `Execution --no-llm` (deterministic floor) **and** agentic (increment over that floor), on dev **and** salted held-out. Harness/procedural numbers are secondary evidence, never the product score.

### V7.2 Certification status

**CERTIFICATE M0/M2/M4-landed, M1-precision-verified — updated 2026-11-24 (`main` @ `fb93a8a`, Queue #14 on `4010d05`).**

> **Deterministic floors (37/59 dev, 29/58 held-out), ALL 3 Realism suites (#2/#3/#4), `xben-25` (25/25), `held-out-saas` (20/20 + 20/20 patches), Queue #14 100.0% worst-run agentic precision across BOTH matrices + 21/21 verified `ProofReceipt` confirmations, Tier-1 warm `throughput` (12 completed) + `trap-zero` (0), M2 chains (`4f09411`), and M4 ops (`53ca9f2`) are PASS/LANDED. M1 aggregate recall (`>= 40/59` dev / `>= 32/58` held-out) and Tier-1 8/8 clean pass await Queue #15 post-`fb93a8a`.**

| Gate | Target | Measured | Status |
| :--- | :--- | :--- | :--- |
| **Floor** dev (`--no-llm`) | 0 spread, 100% precision | **37/59 (62.7%)** (14/13/10) on `aca8262`, **100%** precision, 0 decoy/unmatched FPs (`4375eb8` `-2` XSS regression fixed in `f9dc5d4`) | **PASS** |
| **Floor** salted held-out (`--no-llm`) | 100% precision, no regression | **29/58 (50.0%)** (11/11/7) on `aca8262`, **100%** precision, 0 decoy/unmatched FPs, 0 `broker.persona_scope_mismatch` | **PASS** |
| Confirmation integrity | no confirmed finding without verified receipt/evidence | Strict fail-closed `ProofReceipt` gate (`eec6419`) + collection-GET BOLA guard (`4010d05`); Queue #14 **21/21** live `agent_script` `ProofReceipt`, `0` conflicts | **PASS** |
| Legacy regression (`xben-25`) | `>= 23/25` @ 100% | **25/25 (100%)**, 0 FP on `51819a8` (post-Cut 3c-2 + 3d VM retirements) | **PASS** |
| Legacy regression (`held-out-saas`) | `20/20` + `20/20` patches | **20/20 + 20/20 patches** + all-patches **20/20 dismissed** @ **100.0%** precision (`0 FP`, `0 budgetSkipped`) on `fb93a8a` | **PASS** |
| Realism capability (#2, #3, #4) | #2–#4 capability PASS @ 100% | #2 **PASS (4/4, 0% OOB FNR)**, #3 **PASS (3/3)**, #4 **PASS (3/3, chain 2/2)** on `aca8262` | **PASS (3/3 suites)** |
| `execution.ts` decomposition | `< 8.5K LOC`, parity preserved | **5,388 LOC** (−61.4% from 13,960), −468 net `src/` LOC, 4/4 parity PASS (`2e1b2ed`) | **PASS** |
| `replay-verifier.ts` VM retirement | `< 1K LOC` (M0 Cut 3) | **2,657 LOC** (−1,611 LOC / −37.7% from 4,268 through Cut 3e `f9dc5d4`); Cut 3f `<1K LOC` queued | **IN PROGRESS (Cut 3e PASS)** |
| M2 White-box & Multi-hop Chains | white-box AST/RBAC + 4-hop `ChainHops` | Merged `4f09411` (`78f6240`); `reason-bench` readiness landed | **LANDED** |
| M4 Production Operations | signed scope, `<2s` kill switch, ZDR/TTL, export | Merged `53ca9f2` (`d53e237`): signed scope, `<2s` kill switch, ZDR/TTL/audit, tenant isolation, coverage gaps, receipt export | **LANDED** |
| **Total Product Recall (Unified Agentic)** | `>= 40/59` dev and `>= 32/58` held-out @ 100% | Queue #14 (`4010d05`): **36/59** dev & **29/58** held-out @ **100.0%** precision (`0` stalls, `0` FP; `-2`/`-1` XSS regression fixed in `f9dc5d4`); see §V7.7 | **PRECISION PASS / RECALL OPEN** |
| **Anti-inert agentic guard (`proof_kind='agent_script'`)** | `>= +4` net-new over frozen floor @ 100% | Queue #14 (`4010d05`): **21/21** live `agent_script` `ProofReceipt` (`acme.invoice-bola` net-new on Dev & Held-Out; `+1` `acme-saas` & `+1` `opsportal` in Tier-1 warm); needs `>= +4` aggregate lift | **LIVE / LIFT OPEN** |
| **Tier-1 Smoke (warm agentic snapshots)** | 8/8 gates PASS, `trap-zero = 0`, 0 stalls | Queue #14 (`4010d05`): **5/8 PASS** (`trap-zero`, `paired-net-new`, `crashes`, `throughput=12`, `cost`); `conversion` bug fixed on `swarm/v7-smoke-fix`; `lift` 1 unmatchedFP & `opsportal` p50 open | **5/8 PASS (3 OPEN)** |

**What must not be claimed yet:**
1. **"M1 aggregate recall certified (`>= 40/59` dev, `>= 32/58` held-out)"** — Queue #14 (`4010d05`) achieved **100.0% precision** across both full matrices (`36/59` dev, `29/58` held-out) with live verified `agent_script` `ProofReceipt` lift (`acme.invoice-bola`), but fell short of `40/59` / `32/58` (partly due to the `4375eb8` `-2`/`-1` XSS regression now fixed in `f9dc5d4`).
2. **"Tier-1 Smoke 8/8 green"** — Queue #14 passed 5/8 (`throughput=12`, `trap-zero=0`, `paired-net-new`, `crashes=0`, `cost`); `conversion` accounting is fixed on `swarm/v7-smoke-fix`, while `lift` `1 unmatchedFP` and `rotation/opsportal` `p50=268.2s` remain open for Queue #15.
3. **"Full DSL retirement (`<1K LOC`) complete"** — Cut 3e (`f9dc5d4`) brought `replay-verifier.ts` down to **2,657 LOC** (−1,611 LOC from 4,268); Cut 3f (`<1K LOC`) is queued next.

### V7.3 Smoke battery (adopted design)

The fast battery answers one question: **did this change break the funnel, the precision boundary, or the floor?** It does not attempt to certify. Decoupled deliberately from "a smaller 45-minute scan".

| Tier | Budget | Contents | Catches |
| :--- | :--- | :--- | :--- |
| **Tier 0** | < 90 s, $0 | `scripts/worker-gate.sh` (typecheck + fast contract invariants + targeted slice) and deterministic replay of past FP/over-claim archetypes through verifier → dedupe → scheduler | Type/contract breakage and regressions in previously-fixed over-claims, with no LLM and no Docker-heavy run |
| **Tier 1** | ~6 min, ~$1, 4 parallel cells | Paired lift from post-floor snapshots (acme); one rotating second app (shopflow or opsportal); the **pre-exhausted precision trap**; one realism conversion micro-slice (async OOB / staging race / 4-hop) | Floor preservation, net-new lift shape, precision boundary, one live realism path |
| **Tier 2** | 30–45 min | Cold 3-app dev n=3, salted held-out n=2, one 45-min endurance cell, realism suite, xben + held-out-saas | Cold Phase-A→B integration and multi-hour DB drift — the two known Tier-0/1 blind spots |

**The precision trap.** A pre-exhausted cell whose correct answer is *zero* findings (all budget spent before the target is reachable). It must confirm **0**. Any confirmation from the trap is a precision failure regardless of recall. This is the cheapest guard against the reward-hacking and cross-talk failure modes already seen (control-denial pairing, `before != after` cross-worker reads, SDK helper bypass of host transcripts).

**Tier-1 pass gates (all must hold):**

1. **100% precision** on every lift cell, and **0** on the trap.
2. **Paired net-new non-regression** versus the post-floor snapshot: no lost confirmed targets (a −1 is allowed only with a conversion gain and a clean rerun).
3. **Conversion drop ≤ 10 pp** on the realism micro-slice.
4. **0 crashes / 0 worker failures / 0 orphan containers or networks.**
5. **Throughput floor:** p50 assignment ≤ 75 s and ≥ 12 completions per 300 s of Phase B.
6. **Cost ceiling:** ≤ $0.80 per cell.

**Anti-gaming rules:** rotate the second app every batch; fix general invariants, never trap-specific names or fixtures; a green smoke is *not* evidence of capability — only of non-regression.

**Calibration (accepted, ~$22–24, deferred until M0 lands):** 8 deliberately-varied builds measured against a full reference run. Trust the battery only if Spearman ≥ 0.75 against the reference, 100% directional agreement for Δ ≥ 2 targets, and the trap catches every variant below 95% precision. Until that study is run, Tier 1 is a **regression tripwire**, not a predictive estimate.

**Rejected techniques:** bootstrap confidence intervals on 22-target cells (4/10 — too noisy to gate on); frozen LLM-turn VCR replay (plumbing-only; never a recall signal).

### V7.4 Known regressions fixed this cycle

| Regression | Fix | Result |
| :--- | :--- | :--- |
| XBEN-25 fell to **24/25** after the verifier required pre/post readback (`xben-12` became `replay_spec_miss`) | Spec-side readback for `synthAuthz`; no gate weakening | **25/25** restored |
| held-out-saas BFLA lost during floor hardening | Role-exclusive function-surface delta counts as vertical impact (restored held-out BFLA) | **20/20** + **20/20 patches** |
| Floor fell **26/59** after hardening took it off its pre-hardening level (shopflow 7, opsportal 8) | All-occurrence XSS canary scan picking the strongest executable context (opsportal reflected XSS +1) | **31/59 (52.5%)** at 100% |
| Floor repeat spread **29 / 30 / 33** | Canonical endpoint/probe/ID/persona ordering, state-clobber isolation, request-first termination with wall margin | **0 spread**, 3 identical repeats and site sets (26/59 tree), idle *and* loaded |
| 3 unmatched FPs in the K=6 cell: a planted mass-assignment target labelled BOLA; two fixture XSS escape defects | Evidence-first impact classification (CWE-915) and fixture escaping | **100%** precision on K=6 |
| Stored 2FA over-claim and `/api/admin/activity` false charge | Universal default-deny boundary + real MFA gate; `misclassifiedFindingIds` grader bucket (neither TP nor FP) | Over-claim dismissed; acme samples 100% precision |
| Salted held-out floor dropped **28/58 → 26/58** (shopflow 10 → 8; 26-vs-28 certificate erratum) | `persona-binding` (`222bc90`): per-request `(run, assignment, role, persona, session)` broker jars + fail-closed `broker.persona_scope_mismatch` + `floor-recipes.ts` post-observation `state_restore` | **28/58 (48.3%, 11/10/7) @ 100%** precision, 0 decoy/unmatched FPs, 0 `broker.persona_scope_mismatch` events; erratum resolved |
| `xben-25` dropped **25/25 → 17/25** (−8 SQL targets) after Cut 3c-2 retired legacy `sql_boolean_diff`/`sql_time_diff` | `boolean_or_timing` carriers (`form`/`path`/`header`/`xml`/`graphql_var`), tautology-vs-contradiction arms, timing `blind_sqli` receipt class, CSRF form binding, and non-JSON body signature keys (`0004070`, `4945f93`, `fabbb89`, `51819a8`) | **25/25 (100%)** restored on Docker with Cut 3c-2 & 3d VM deletions intact |
| `held-out-saas` dropped **20/20 → 18/20** (`hos-07`, `hos-08`) after Cut 3c-2 | Nested object construction for dotted JSON parameters (`c3da71f`, `hos-08`) + `BENCH_MAX_REQUESTS_DEFAULT 3800 -> 6000` & GraphQL object-scoped arg/variable recognition in `isObjectScopedRequest()` (`fb93a8a`, `hos-07`/`hos-02`) | **20/20 + 20/20 patches + 20/20 all-patches dismissed @ 100.0% precision** (`0` FP, `0` budgetSkipped, `4,228/6,000` units) |
| Live Docker `guardian_verify` had **0 confirmations** (`12/12 claims_missing` → `51/51 EACCES` → 22x missing-script loop + 1 receiptless `CWE-200` FP) | Idempotent TS/Python script wrapper (`d1e0192`), container-UID-readable `umask`-safe RPC staging (`b0767c5`), final-settlement allowance + SDK arg normalization (`b608e69`), strict fail-closed `ProofReceipt` gate + `code`/`source` alias + 3-error loop stop (`eec6419`), and bare collection GET BOLA guard (`4010d05`) | Queue #14 (`4010d05`): **21/21 live `agent_script` `ProofReceipt` confirmations** across all 3 legs, **100.0% precision** on both Dev & Held-Out matrices (`shopflow` back to 100%), `0` stalls, `0` conflicts |
| Reflected-XSS floor dropped **−2 dev / −1 held-out** (`acme.reflected-search-xss`, `og.account-search-xss`) in `4375eb8` (caught by Queue #14 on `4010d05`) | Fixed auth reflected-XSS `browser_sink` path in Cut 3e (`f9dc5d4` / `e939298`) while retiring `browser_chain` & 4 legacy VMs (−806 LOC; `replay-verifier.ts` now **2,657 LOC**) | Fixed on `main` @ `f9dc5d4` (re-verified in Queue #15) |
| Tier-1 Smoke `--resume-snapshot` reported `conversion: 4.5% (1/22)` vs `63.6%` despite 13 preserved floor + 4 post-resume findings (`17 confirmed / 0 conflicts`) | `computeCellAccounting` attributes preserved floor sites strictly via baseline `vulns` or `<snapshot>/guardian.sqlite` `runtime_confirmed` finding IDs matched in `card.vulns` (`swarm/v7-smoke-fix`) | Preserved floor + post-resume confirmed union measured accurately without weakening `conversion drop <= 10pp` |
| **Open:** 45-min "invoice amount accepts negative values" claim | Triage in flight (genuine invariant bug vs echo/clamp) | **Unresolved** — reason the 45-min worst-run precision is not 100% |
| **Open:** Tier-1 Smoke warm `lift` `1 unmatchedFP` & `rotation/opsportal` `p50=268.2s` (>110s) | Caught in Queue #14 Step 3 (`4010d05`) | Open for Queue #15 |

### V7.5 Honest limitations

1. **M1 aggregate recall target (`>= 40/59` dev, `>= 32/58` held-out) is not yet certified.** Queue #14 (`4010d05`) proved **100.0% worst-run precision** on both full matrices (`36/59` dev, `29/58` salted held-out) with **21/21** live verified `ProofReceipt` confirmations (`0` stalls, `0` conflicts) and net-new `acme.invoice-bola`, but was held back by the `4375eb8` `-2`/`-1` XSS regression (now fixed in `f9dc5d4`) and needs broader Phase-B lift across additional classes.
2. **Longer horizon trades precision for recall.** Worst-run precision at the horizon (100% with 0 decoy/unmatched FPs) remains a hard release gate.
3. **Held-out floor still lags dev by 12.7 pp** (62.7% vs 50.0% on `aca8262`: 37/59 dev vs 29/58 salted held-out). Closing the remainder on randomized routes belongs to Layer 3 (`guardian_verify` + white-box), not more deterministic regexes.
4. **Tier-1 smoke is not yet calibrated** via the 8-variant study; Queue #14 passed 5/8 warm gates (`throughput=12`, `trap-zero=0`, `paired-net-new`, `crashes=0`, `cost`), `conversion` accounting is fixed on `swarm/v7-smoke-fix`, and `lift` `1 unmatchedFP` + `rotation/opsportal` `p50=268.2s` remain open.
5. **DSL retirement is substantially advanced, not finished:** `execution.ts` is down to **5,388 LOC** (−61.4% from 13,960) and `replay-verifier.ts` is down to **2,657 LOC** (−1,611 LOC / −37.7% from 4,268 across Cut 3c-1/3c-2/3d/3e), with Cut 3f (`<1K LOC`) queued next.

### V7.6 Reporting rule

- §2–§3 and §6 are the **v5.0 freeze record**. §0 is the **v5.1 integration record**. Both are historical; do not update their numbers to match the current line.
- Nothing in §V7 is a release claim until the corresponding M0/M1 gates in [plans/v7.md](plans/v7.md#certification-protocol-adopted) pass on `main`.
- Never cite a harness/procedural number as the product score; never cite a wiring pass as a capability result; never cite a per-app lift as an aggregate.

### V7.7 Queue #14 Unified Agentic Matrix & Tier-1 Warm Smoke (`main` @ `4010d05`) + Post-Queue #14 Batch Merge (`fb93a8a`)

**Queue #14 provenance:** run by `@bench-verifier` on `main` @ `4010d053bb2e`, `--verifier docker`, model `deepseek/deepseek-v4.1-flash-1017`, `GUARDIAN_DATA_DIR="$HOME/guardian-data"`. Achieved **100.0% worst-run precision across BOTH full Unified Agentic Matrices**, **21/21 live `agent_script` `ProofReceipt` confirmations** across all 3 legs (`0` stalls, `0` crashes, `0` conflicts), and **Tier-1 warm `throughput` PASS (`12 completed`)** + **`trap-zero` PASS (`0 confirmed`)**.

| Leg | Command / Parameters | Target Gate | Measured (`4010d053bb2e`) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Dev Unified Agentic Matrix** | `--app all --seeds 1 --mode grey-box --verifier docker --isolate-data-dir --keep-data-dirs --concurrency 1 --worker-concurrency 6 --budget-usd 5.0 --max-duration-ms 600000` | `>= 40/59` total, `100.0%` precision, `0` conflicts, `proof_kind='agent_script'` + `with_receipt` > 0 | **36/59 (14/13/9) @ 100.0% precision**, `0` decoy FP, `0` unmatched FP, `0` stalls, `$1.716`, `audit-confirmation-consistency`: `41 confirmed / 0 conflicts`; **7/7** `agent_script` `ProofReceipt` (`79` `guardian_verify` calls, `0` validation errors); net-new **`acme.invoice-bola` (`CWE-639`)**; caught `4375eb8` `-2` reflected-XSS floor regression (`acme.reflected-search-xss`, `og.account-search-xss`) fixed in `f9dc5d4` | **PRECISION PASS / RECALL 36/59** |
| **2. Salted Held-Out Unified Agentic Matrix** | `--app all --seeds 1000042 --held-out --mode grey-box --verifier docker --isolate-data-dir --keep-data-dirs --concurrency 1 --worker-concurrency 6 --budget-usd 5.0 --max-duration-ms 600000` (with `GUARDIAN_RB_HELDOUT_SALT`) | `>= 32/58` total, `100.0%` precision, `0` conflicts, `proof_kind='agent_script'` + `with_receipt` > 0 | **29/58 (11/11/7) @ 100.0% precision**, `0` decoy FP, `0` unmatched FP (**`shopflow` back to 100.0%**), `0` stalls, `$1.536`, `audit-confirmation-consistency`: `35 confirmed / 0 conflicts`; **7/7** `agent_script` `ProofReceipt` (`89` `guardian_verify` calls, `0` validation errors); net-new **`acme.invoice-bola` (`CWE-639`)** (same `4375eb8` `-1` `acme.reflected-search-xss` regression fixed in `f9dc5d4`; 30/58 without it) | **PRECISION PASS / RECALL 29/58** |
| **3. Tier-1 Smoke (warm agentic post-floor snapshots)** | `scripts/smoke-agentic.ts --tier 1 --snapshot-root /tmp/v7-q14-snaps --budget-usd-per-cell 0.80` (`$1.199` total) | `8/8` gates PASS, `trap-zero = 0`, `100%` precision, `0` stalls, `throughput >= 12` | **Tier 0 PASS** (`worker-gate` pass, corpus all dismissed). **5/8 Tier-1 PASS:** `trap-zero` **PASS** (`0 confirmed`, `$0.113`, `p50=69.5s`, `10 completed`), `paired-net-new` **PASS** (`+1` `acme-saas`, `+1` `opsportal`), `crashes` **PASS** (`0`), **`throughput` PASS (`12 completed` in 300s warm `lift`, `lift p50=98.6s <= 110s`)**, `cost` **PASS** (`$0.494/$0.413/$0.113/$0.179 <= $0.80/cell`). **7/7** live `agent_script` `ProofReceipt` (`0` stalls): `lift` 4 (`13 floor + 4 agent_only = 17 confirmed / 0 conflicts`), `rotation`/`opsportal` 1 (`9 floor + 1 agent_only = 10 confirmed / 0 conflicts`, `100%` precision), `micro/monorepo-whitebox` 1, `micro/staging-concurrency` 1. **3 Failed:** `conversion` (`4.5% vs 63.6%` `--resume-snapshot` accounting bug — fixed on `swarm/v7-smoke-fix`), `precision-lift` (`1 unmatchedFP` in `lift`; `0` decoy FP), `p50-assignment` (`lift 98.6s` PASS; `rotation/opsportal 268.2s`) | **5/8 PASS (3 OPEN)** |

**Post-Queue #14 batch merges landed on `main` @ `fb93a8a`:**

| Stream | Merge SHA (Tip) | Provenance & Verified Impact |
| :--- | :--- | :--- |
| **M0 Cut 3e + XSS fix** | `f9dc5d4` (`e939298`) | Retired `browser_chain` & 4 legacy VMs from `src/server/replay-verifier.ts` (**−806 LOC**, now **2,657 LOC** down from `4,268`) + fixed `4375eb8` auth reflected-XSS `browser_sink` regression (`acme.reflected-search-xss`, `og.account-search-xss`) |
| **M2 Chains & White-box** | `4f09411` (`78f6240`) | White-box-first AST/RBAC analysis, typed multi-round 4-hop `ChainHops`, and `reason-bench` readiness |
| **M4 Production Ops** | `53ca9f2` (`d53e237`) | Signed scope, `<2s` kill switch, ZDR/TTL/audit, tenant isolation, coverage gaps, and `ProofReceipt` export |
| **`hos-07` + Legacy Tests** | `fb93a8a` (`5b77b1c`) | Bumped `BENCH_MAX_REQUESTS_DEFAULT 3800 -> 6000` (`4,228/6,000`, `0` budgetSkipped) + GraphQL object-scoped arg/variable recognition in `isObjectScopedRequest()` (`hos-02`, keeping bare collection GET fail-closed) → `held-out-saas --verify-patches` restored to **20/20 + 20/20 patches + 20/20 all-patches dismissed @ 100.0% precision** (`0` FP); fixed stale assertions & teardown in `tests/v5-engine-coverage.test.ts` + `tests/v4-m4-surface-orchestration.test.ts` (`36/36 PASS`) |
| **v8 Architecture Plan** | `1a3cebc` (`4d4971d`) | Added `plans/v8.md` multi-hop realistic SaaS architecture & benchmark plan |

---

## 0. v5.1 integration (in progress)

> This section is **new in v5.1**. It does not revise the v5.0 freeze record. v5.0 is frozen at the scorecards in §2–§3 (deterministic dev **115/172**, held-out **111/171**, runtime agentic **7/59**, `--no-llm` **0/59**). Nothing below changes those numbers until the integration flag is flipped on `main` and the pre-flip gates in §0.3 pass.

### 0.1 Status

- **v5.0 is frozen.** Release gate **992/992 PASS**, 0 failures, 0 skips, 0 orphans; deterministic floors and Scorecards A/B stand as recorded in §2–§3.
- **The engine-port was reverted** from `main` (`a73f07e`). It delivered 25/59 `--no-llm` and 28/59 agentic at 100% precision, but regressed **25 existing Execution/E2E tests**: planner budgets, specialist tools, multi-trial, and M1 fallback. It remains preserved on `agents/engine-port` for reference only.
- **Integration restarted in five slices** rather than re-merging the branch. The integration lands behind a **default-off** flag so `main` stays at v5.0 behavior until parity is proven. Slices **1–2 are in progress**; slices 3–5 are gated on their results.

### 0.2 The five slices

| # | Slice | Scope | Status |
| :--- | :--- | :--- | :--- |
| 1 | Standalone engine modules + structural dedupe | Extract the engine out of the request path into testable modules; structural dedupe key `(origin, endpoint, method, param/resolver, cwe)` so distinct same-class endpoints are not collapsed | **IN PROGRESS** |
| 2 | Deterministic-only path | Explicit `deterministicOnly` path outside the M1 fallback; persist verified findings only; emit `det_lead` facts for unconfirmed leads | **IN PROGRESS** |
| 3 | Non-blocking agentic lane | Concurrent lane behind a **default-off** flag; seeded-step guard, 30% / 180 s cap, K=6 and per-lane budget isolation, **no step cancellation** | **NOT STARTED** (gated on 1–2) |
| 4 | Verifier proof strength | Replace the specialist deterministic-pair scope guard with `ReplayVerifier` proof-strength + endpoint binding | **NOT STARTED** |
| 5 | Flip default + parity | Port remaining parity gaps, run the pre-flip gate, then flip the default on `main` | **NOT STARTED** |

### 0.3 Pre-flip gates

All of these must pass **with the integration flag forced ON** before slice 5 flips the default:

1. **Full suite green** with the flag ON — 0 failures, 0 skips, 0 orphans (`docs/reverify-v5.sh --full`).
2. **Budget invariants:** `dynamicStepBudget` / **K=6** / M1 fallback behavior unchanged; per-lane budget isolation holds.
3. **Deterministic floor:** `Execution --no-llm` **≥ 25/59 at 100% precision** on the 3-app grey-box dev cells.
4. **Agentic is strictly additive:** **≥ 95% precision** and **≤ 10 pp held-out gap**, with no loss of already-confirmed findings versus the flag-off control.
5. **Legacy floors hold:** XBEN **25/25**, held-out-saas **20/20** + **20/20 patches**, deterministic dev **115/172**, deterministic held-out **111/171**, and **0 orphans**.

A slice result that misses a gate is recorded as a failed candidate, not a shipped number. v5.1 figures are **not shipped until the flag flips**.

### 0.4 Chain-safety rules

The integration must preserve chained and white-box findings. These rules are release-blocking:

- **No step cancellation.** The deterministic pass never cancels a specialist step, and never hides a confirmed route from the agentic lane — either would break multi-step chains.
- **Read-only “Already Confirmed” context.** Specialists receive confirmed findings as read-only context for chaining, not as a signal to skip work.
- **Preserve white-box findings.** `static_verified` findings survive the integration; the deterministic lane must not overwrite or suppress them.
- **Persist unconfirmed leads.** Unconfirmed deterministic candidates are stored as `det_lead` facts rather than silently dropped, so later steps can promote them.
- **Per-endpoint structural dedupe.** Dedupe on `(origin, endpoint, method, param/resolver, cwe)`; origin+CWE-only dedupe is rejected because it discards distinct endpoints.

### 0.5 Reporting rule

Scorecards in §2 (runtime) and §3 (deterministic harness) are **v5.0 history and stay unchanged**. The 25/59 and 28/59 candidate results and any slice measurements are **reference only**; they are not v5.1 shipped numbers until the flag is on by default and §0.3 is green.

### 0.6 Security hardening (v5.1, merged)

An independent audit produced 2 high, 3 medium and 6 medium/low findings against Guardian itself. All were fixed on `main` with regression tests; nothing here changes the v5.0 scorecards, and the deterministic capability harness was re-measured after the merge (**39/56, 100% precision, 0 decoys/unmatched** on seed 42).

| # | Severity | Finding | Fix | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| 1 | High | One automatic approval authorized every later state change on the origin (path-prefix match; query/persona/body/flags ignored; 15-minute reuse) | Exact single-use approval ledger bound to run, origin, method, exact path+query, persona, body/parts hash, multipart/race/rce flags and scope revision (60 s TTL, consumed on first use). Persisted DB rows are audit-only. Broker passes real context; operator patterns are segment-aware only (`/api/*` matches `/api/x`, not `/apix`) | `tests/v5-security-approvals.test.ts` 11/11 |
| 2 | High | `--repo` copied symlinks; recon read through them and patches could write outside the repo | Link-free copy with `lstat` filtering, `O_NOFOLLOW` manifest reads, link-free patch work tree, `safeResolveUnderRoot` realpaths the deepest existing parent and rejects symlinked components | `tests/v5-security-repo.test.ts` 10/10 |
| 3 | Medium | Any local process received the owner session cookie on a plain HTML GET | Bootstrap-only issuance: printed one-time `?bootstrap=` URL plus owner-only `<data>/bootstrap` (0600); secret consumed on use; `HttpOnly; SameSite=Strict`; unauthenticated requests get `401` and never reach the app handler | `tests/v5-security-authbrowser.test.ts` 12/12 |
| 4 | Medium | Clerk/provider host taken from target HTML with a last-two-labels fallback (`co.uk` bug) and no allowlist check | PSL-aware registrable-domain check, provider discovery ignores redirects, publishable-key hosts must be in the allowlisted registrable domain | same suite |
| 5 | Medium | Credential POSTs followed redirects, replaying passwords to arbitrary/internal hosts outside the broker's IP checks | `redirect: 'manual'` everywhere; 3xx on credential/CSRF flows fails closed; `assertCredentialTarget` enforces scheme, allowlist and public-IP DNS classification | same suite |
| 6 | Medium | Scoped browser intercepted only HTTP; WebSocket/WebRTC egress reached loopback/LAN/metadata | `routeWebSocket` scope guard, non-proxied UDP disabled, `RTCPeerConnection` removed, host-resolver rules pin DNS | same suite |
| 7 | Medium | Form-login browser allowed self-resolved DNS (rebinding) and cross-origin subresources to any host | Cross-origin subresources limited to target/allowlisted eTLD+1; every request re-checks DNS before `route.continue()`; documents limited to exact allowed origins | same suite |
| 8 | Medium | Chromium ran with `--no-sandbox` while rendering target pages | Sandbox on by default; `--no-sandbox` only behind `GUARDIAN_INSECURE_NO_SANDBOX=1` with a warning | same suite |
| 9 | Medium | IAST telemetry directory was `0777` and mounted read-write into a root-capable container | `0700` directory, explicit non-root `--user` (root rejected), read-only `/app` | `tests/v5-security-repo.test.ts` |
| 10 | Medium | Approval fast paths were spoofable (`"query"` substring, hand-written multipart, 4 KiB scan, agent-controlled rationale) | Exact JSON `query` envelope, multipart derived from `Content-Type`/boundary, full-body scan capped at 64 KiB, rationale removed from the judge prompt | `tests/v5-security-approvals.test.ts` |
| 11 | Medium | Worker output read without line limits; LLM-written scripts shared the bridge uid | `BoundedLineDecoder` (64 KiB/line, 4 MiB/session) terminates the session on overrun | `tests/v5-security-repo.test.ts` |

**Intentional behavior changes**

- Public-target `rce_proof` / `upload_probe` / `sql_time_diff` replay gates now fail closed unless the request is local-lab auto-approved or operator-pattern authorized; they no longer ride the context-free fast path.
- Headless UI is opened through the bootstrap URL; `tests/app.ts` exposes `app.open(page)` and the README documents the handshake.
- Lab containers default to the invoking uid:gid (non-root) and reject `GUARDIAN_LAB_USER=0:*`.

**Gate wiring:** the three security suites run in the fast release gate (`docs/reverify-v5.sh`) and in the `v5-*` group of the full gate.

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

**Release gate status: PASS — 992/992, 0 failed, 0 skipped, 0 orphans.** Freeze run: `/tmp/guardian-reverify-v5.5in05x`. This includes 234 v5 tests (full glob), 322 tiered E2E, 198 v4 M1–M7, 46+32 boundaries, 142 realistic-harness, 9 Playwright, and orphan hygiene.

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
| G10 | Full release gate | 100% pass, 0 skips | **992/992 PASS**, 0 skips, 0 orphans | **MET** |
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

### 9.1 v5.0 limitations (frozen record)

1. **No deterministic floor in shipped `Execution`.** The port exists on `agents/engine-port`; rebuild it without the 25 regressions.
2. **Port regressions to fix:** planner budgets, specialist tools, multi-trial, fallback.
3. **Surface ingestion:** v5.0 runtime sees 25/59; full ingestion is required.
4. **Specialist scope guard:** candidate-only; blinds novel logic/workflow/chain/white-box recall; replace with proof-strength + endpoint binding.
5. **Wall-clock:** candidate behavior (2/3 at 600 s, opsportal 137 s) needs budget allocation.
6. **White-box and salted Execution matrices** are v5.1.
7. **Chains remain 1/6 (16.7%)**, below 50%.
8. Release gate is **PASS (992/992)** on the freeze tree.
9. **Patch evidence** includes 2 inconclusive-after retests and a replay-based all-patches pass.
10. **No external targets, secrets, or salts.**

### 9.2 v5.1 integration limitations (current, in progress)

1. **Flag is default-off.** `main` still behaves as v5.0; the deterministic floor only exists on integration branches until slice 5.
2. **Slices 1–2 are in progress.** Modules/dedupe and the `deterministicOnly` path are not yet merged; slices 3–5 have not started.
3. **No v5.1 numbers are shipped.** Candidate 25/59 / 28/59 remain reference results; slice measurements are not release claims.
4. **Scope guard is still in the candidate.** Until slice 4 lands, deterministic-pair scoping can blind novel logic, workflow, chain, and white-box recall.
5. **Chain safety is unverified end-to-end.** The no-cancellation, read-only confirmed context, `static_verified` preservation, and `det_lead` rules must be proven by the flag-ON suite.
6. **Wall-clock split is unresolved.** Slice 3's 30% / 180 s lane cap and K=6 isolation are design targets, not measured behavior.
7. **Held-out parity is unmeasured for the integration.** The ≤ 10 pp gap gate is a pre-flip requirement, not a result.
8. **Release gate still applies to v5.0.** Any integration run that is not flag-ON and 0-skip is not a release gate.

---

## 10. Reproduction

### 10.1 Shipped runtime (Scorecard A)

```bash
# Agentic, 3 apps, seed 1, Tier-3 local-lab, $2 / 600 s cells.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR="$HOME/guardian-data" \
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

Entrypoint map — the two files are *not* interchangeable:

- `scripts/benchmark-realistic.ts` = **product runtime** harness (drives real `Execution`; Scorecard A).
- `benchmarks/realistic-bench/benchmark-realistic.ts` = **deterministic capability** harness
  (procedural probes/spec synthesis; Scorecard B). `scripts/benchmark-realistic-matrix.ts`
  parallelizes this one across app × seed cells.

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-realistic-matrix.ts \
  --apps acme-saas,shopflow,opsportal --seeds 1,2,42 --split dev \
  --mode grey-box --concurrency 9 --out-dir /tmp/v5-dev

# Salt lives at ~/.config/guardian-bench/heldout.salt (mode 600); never echo it.
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
node scripts/benchmark-realistic-matrix.ts \
  --apps acme-saas,shopflow,opsportal --seeds 1000001,1000002,1000042 --split heldout \
  --mode grey-box --concurrency 9 --out-dir /tmp/v5-held
unset GUARDIAN_RB_HELDOUT_SALT
```

### 10.3 v5.1 candidate (branch only, historical)

```bash
git switch agents/engine-port
# Same Scorecard A commands; the candidate reports 25/59 no-LLM and 28/59 agentic.
# Do not merge: this branch regressed 25 Execution/E2E tests. Integration now proceeds
# in slices behind a default-off flag — see §10.5.
```

### 10.4 Freeze gate, Tier-3 safety, OOB, secrets

```bash
newgrp docker -c 'bash docs/reverify-v5.sh --full'          # v5.0 release gate: 992/992 PASS

GUARDIAN_ALLOW_LOCAL_LAB=1 \
  node --test tests/v5-tier3-safety.test.ts tests/approval-judge.test.ts   # 15/15
```

OOB callbacks bind one **loopback** canary listener; the harness passes that exact port to the app allowlist. Pin with loopback-only `GUARDIAN_CANARY_PORT` / `GUARDIAN_CANARY_DNS_PORT`; never bind off-loopback. `secretMatches` is `{kind, sha256Prefix, fieldPath?, count}` only; correlate against a locally held secret, never log the raw value.

### 10.5 v5.1 integration loop and pre-flip gate

```bash
# Between tweaks: smoke tier (realistic seed 42 + agentic --smoke + typecheck, parallel).
newgrp docker -c 'bash scripts/hillclimb-loop.sh'

# Once per batch: validation tier (3 dev seeds + 600 s agentic matrix).
newgrp docker -c 'bash scripts/hillclimb-loop.sh --full'

# Pre-flip release gate. Slice 3 introduces the opt-in flag; force it ON for the
# whole run so the flag-ON suite, 0-skip, and orphan checks are meaningful.
# The flag is default-off; its name is pinned by slice 3 (do not guess it here).
newgrp docker -c 'bash docs/reverify-v5.sh --full'

# Deterministic floor on the flag-ON tree: expect >= 25/59 at 100% precision.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box --no-llm \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v51-no-llm
'

# Agentic parity: control (flag off) vs variant (same cells, flag on).
# Pass condition: >= 95% precision, <= 10 pp held-out gap, no confirmed findings lost.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR="$HOME/guardian-data" \
         NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v51-parity-control
'
# Repeat the same command with the slice-3 flag exported and --out-dir /tmp/v51-parity-variant.
```

Until the flag flips, a v5.1 run is a **candidate measurement**, not a release result. Keep v5.0 scorecards in §2–§3 as the shipped numbers.

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
| Freeze gate | `5in05x` log | **PASS 992/992** |

**Discrepancies:**

1. **Engine-port is not shipped.** `a73f07e` reverted the merge; 25 existing Execution/E2E tests regressed. The 25/59 and 28/59 results are v5.1 candidate only.
2. **Shipped runtime has no deterministic floor:** agentic 7/59 (11.9%), no-LLM 0/59.
3. **Scorecard B is deterministic-only:** 66.9% dev / 64.9% held-out; do not present it as the product runtime.
4. **G4 is met on the deterministic surface only.**
5. **G9 is all-severity (−2.0 pp); H/C is −3.2 pp** (70.9% dev vs 67.7% held-out). Both are within 10 pp.
6. **Chains are 1/6**, below 50%; G8 open.
7. Freeze gate is **PASS (992/992)**; the earlier `GtumGa` failures were mid-change and are superseded.
8. **Final deterministic rerun:** dev holds at 115/172; held-out is 111/171, one below the earlier 112. The document uses the final rerun values.
9. **v5.1 integration is sliced, not a re-merge.** Slices 1–2 are in progress behind a default-off flag; the reverted branch is reference only. See §0.
10. **No v5.1 number is shipped.** The 25/59 / 28/59 candidate and any slice measurement become citable only after the flag flips and §0.3 is green.
