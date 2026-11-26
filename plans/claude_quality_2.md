# Claude systemic quality audit — round 2

> Status: **READY FOR EXECUTION — reviewer to triage and dispatch.** Author: Claude Code (Opus 5.5), 2026-11-26. Audited `main` between `eec50d9` and `2662064`. Round 1: [`plans/claude_quality.md`](claude_quality.md). Security round 3: [`plans/CLAUDE_AUDIT_R3.md`](CLAUDE_AUDIT_R3.md).

> Read-only audit: no code edited, no benchmarks run. Line numbers drift as `main` moves, so re-`grep` the symbol before editing.

## Method

- 10 read-only finders, each with one lens:
  - round-1 efficacy, measurement side (cq-1/2/3)
  - round-1 efficacy, engine side (cq-4/5/6/11/13a)
  - re-verification of open round-1 items (cq-7/8/9/10/12/13b)
  - throughput tuning vs target safety and approvals
  - test-suite health under swarm velocity
  - worker sandbox, provider reliability and cost
  - operator-facing truthfulness
  - data and schema lifecycle
  - complexity trajectory
  - real-world recall realism
- Result: **77 raw issues**, clustered into **15 themes**. 1 issue was dropped as a pure duplicate of round 1 or R3. The ranking pass split some themes into separately shippable items, giving **23 ranked items**.
- 2 adversarial skeptics reviewed each theme: one checked evidence accuracy on HEAD, the other asked whether the issue is systemic, new and impactful. None was refuted. The corrections they applied are listed in *Ranking rationale*.
- Coordinator spot-checks on `2662064`, all holding:
  - `approval-judge.ts` `riskLevel…default('medium')`.
  - The `broker.ts` probe-induced 5xx is treated as evidence and never trips the breaker (`errorInducingProbePattern`, around line 2978).
  - The `request-admission.ts` env-mode catch sets `explicitEnvironmentMode = grant.approvalPolicy === undefined` (around line 409).
  - `tests/QUARANTINE.json` has 91/91 entries with a single expiry of 2026-12-26 and has been touched only by `5249b9e`.
  - Ledger appends happen only behind an opt-in `--ledger` flag, and `benchmarks/results/ledger.jsonl` is empty.
- Scale: in this round **impact and leverage are scored 1–10** (round 1 used 1–5). Effort is S/M/L.

## Round-1 scorecard (on HEAD)

| Round-1 item | Status | Note |
|---|---|---|
| #1 Fail-closed scoring + wordlist off (cq-1) | **partially_effective** | The realistic and agentic matrices now fail closed on empty or failed cells. Still open: the realistic and reason graders, certify-phase1 ingest (asNumber(...,1), union-of-sites reason denominator), certify-v8:1430 and benchmark-recall (no unmatchedConfirmed) all still treat empty as precision 1. Ledger 'rawPrecision' is mislabeled in 3 aggregators. The wordlist was flipped only in benchmark-realistic.ts, and the engine default is still ON for the multihop, reason, realism and cli harnesses. The floor-lane conventional list is correctly filtered by its source tag (the bypass claim was refuted). Root cause: the cq-1 lease excluded the shared graders and certify. Continued by R2-05 and R2-06. |
| #2 Results ledger + held-out hygiene (cq-2) | **ineffective** | benchmarks/results/ledger.jsonl is 0 bytes. Every append sits behind an opt-in --ledger flag that nothing passes, and render-verification-tables and compareLedgerRows have no production callers. EffectiveConfig is declared by callers, not observed. Held-out draws always start at HMAC index 0. computeBenchmarkVersion content-hashing works. Continued by R2-05 and R2-06. |
| #3 Merge gate, QUARANTINE.json, Contract-change lint, regression-floor (cq-3) | **partially_effective** | worker-gate runs per worktree and catches real breakage. But quarantine is per file with cap=count (91/91) and a single expiry, it has not moved since seeding, and kernel failures inside it grew (H-13 after c9169d6) with no signal. The gate runs before merge rather than on the merged tree, and CI never runs it. The lint misses most numeric caps and src/domain.ts. regression-floor.sh has no caller, no baseline and a vacuous per-ID check, and its test:boundaries step contains a quarantined red suite. In practice it fails open over the precision kernel. Continued by R2-02, R2-03 and R2-05. |
| #4 Path-parity corpus (cq-4) | **partially_effective** | The 15-case corpus and multi-entry-point runner landed (c1e2b4e). They have never grown: 7 R3 kernel fixes added zero cases. TP verdicts under the cwe_only and free_text permutations are unasserted, and the 'other' label expectation splits by entry point without documentation. cq-4 itself added a new prose classifier (inferInjectionFamily). Retest health still exists on only 1 of 3 engines. Continued by R2-04, R2-11 and R2-15. |
| #5 Typed terminal outcomes (cq-5) | **partially_effective** | Producers write the typed statuses and the floor records unprobedTail, cappedOut and byClassUnprobed. Consumers were not migrated: store readiness and taint ignore the 5 new statuses, so dependents strand. Dispatch, store and planner use three different rules. The planner deferral gate counts stranded steps. The reconciler, snapshot, report, UI and coverage-gaps drop them. classifyProductAttribution is test-only. The planner closure still accepts evidence-free no_issue_found. Continued by R2-07, R2-14 and R2-13. |
| #6 Agent contract single source / AgentToolRegistry (cq-6) | **partially_effective** | The registry and AssignmentBudget landed. The @deprecated wall-clock and turn constants still drive live budgets, so seconds per turn fall as turns grow. Two sessions use the settlement fallback. Five cq-6-owned test files are quarantined instead of migrated. The alias counters are an undisposed module Map. Continued by R2-19. |
| #7 Same floor in --no-llm and agentic (cq-7) | **open** | Deferred to Wave 4 by the round-1 triage, gated on the ledger. The 75s/12% vs 240s split is unchanged. Only the cq-5 tail accounting landed. The preservation and lift metrics already exist in run-actor and certify-phase1 but are not persisted. Continued by R2-23. |
| #8 Measure the shipped configuration (cq-8) | **open** | Not landed. The privileged local-lab envelope, the no-profile M1 lane and the lack of a shipped-shape cell all remain. New since round 1: a harness-written runtime_confirmed SPA lane, a mutable worker image whose preflight checks a different image than runtime uses, and hillclimb returning 0 on a skipped leg. R2-06 covers the observed-config core. Shipped-shape tier cells stay cq-8. |
| #9 Fixture-leak barrier (cq-9) | **open** | Every fixture token count is identical to a50d462, and the only lint is v8-scoped. The problem has not spread, so this is a static, unmeasured liability. Blocked by the cq-8 ordering. Continued by R2-20. |
| #10 Typed persona/step metadata (cq-10) | **open** | Not landed. Usage is growing slowly (roleLabel 93->97, parseRole 42->43) through R3 and patch-retest sites, which reuse parseRoleLabel and fail closed. The UI still cannot express tenant. New side-channel instances: cq-5 retry identity in skills and prose, and the e9e5ffd lease-scope sentinel. The round-1 lease paths are wrong. Continued by R2-17 and R2-09. |
| #11 Capability manifest + unwired ratchet (cq-11) | **partially_effective** | The manifest and ratchet exist and block new unbaselined exports. But the baseline was bulk-refreshed twice in fix(gate) sweeps (1069->1181), resolvedBaselineExports has been 0 since creation, about 88% of entries are own-module noise, a syntactic import counts as wired (inert token telemetry), stale keepUnwired tickets go undetected, and the dead resolveProviderStallNoTokenMs that triage said to delete survives. Continued by R2-03. |
| #12 Taxonomy contract + conformance test (cq-12a/b) | **open** | Neither stage landed (no tests/taxonomy-conformance.test.ts, no vuln-taxonomy.ts). The drifts persist and cq-4 added another prose classifier. Newly verified: the shared floor impact boilerplate relabels XXE, SSRF, traversal and JWT specs as 'authorization' in classifyImpactDescriptor. The conformance ratchet can be decoupled from cq-10. Continued by R2-15. |
| #13 Run isolation (cq-13a/b) | **partially_effective** | 13a landed per-run fail-closed redaction, resolveJarKey and disposeRun (the broker owner maps are now per-run and disposed). The finally-guarded mutating-recipe restore promised in the 13a triage never landed, and nothing marks 13a partial. 13b is still open, and three new module-level per-run Maps landed outside disposal, one of them a FIFO-evicted safety budget. Continued by R2-08. |

## Summary table

| # | id | Improvement | Relation to prior rounds | Impact | Leverage | Effort | Confidence | Depends on |
|---|---|---|---|---|---|---|---|---|
| 1 | `R2-01` | Close three fail-open host safety decisions keyed on model- or worker-declared labels: Judge riskLevel default, probeClass breaker exemption, and the admission explicit-mode catch | new (same failure class as R3: host decision keyed on worker/LLM-declared field); the breaker part is an incomplete fix of 51376b3 (cq-3 (Contract-change lint missed it); R3 class) | 8 | 6 | S | high | — |
| 2 | `R2-02` | Make quarantine per-case and drift-detecting, derive unquarantinable suites from KERNEL_TEST_RE, and run the fast tier hermetically with production Node flags | incomplete_round1_fix (cq-3) | 8 | 9 | M | high | — |
| 3 | `R2-03` | Gate the merged tree, not the worktree: a merge queue, the fast tier in CI, monotone ratchets with prune-fail, and an unwired metric that measures reachability | incomplete_round1_fix (cq-3 / cq-11) | 6 | 8 | S-M | high | R2-02 (CI-required fast tier needs trustworthy quarantine) |
| 4 | `R2-04` | Make 'Verified fixed' mean reconfirmed absence: one retest-health assessor for all three retest engines, and split oracle_failed | carried_over_open (residual of R2-H-15/H-16/H-19) and incomplete_round1_fix of cq-4 ('fixed in A, not in B') (cq-4) | 7 | 6 | S-M | high | — |
| 5 | `R2-05` | Put the measurement layer on the default path: one 3-state ScorecardReader and ledger-row builder, no precision-1 defaults, a working regression-floor, and tracked held-out seed exposure | incomplete_round1_fix (cq-1 / cq-2 / cq-3) | 7 | 8 | M | high | R2-02 (test:boundaries/quarantine reconciliation) |
| 6 | `R2-06` | Record what the run actually ran: an engine-emitted effective_config event, wordlist default OFF, certify refusals, no harness-written confirmed findings, and a pinned worker image identity | incomplete_round1_fix (cq-2 config hash is declared, not observed; cq-1 wordlist default) plus newly surfaced harness-trust holes; cq-8 remainder stays open (cq-2 / cq-1 / cq-8) | 7 | 7 | M | high (floor-lane bypass sub-claim refuted and dropped) | R2-05 (owns bench-ledger.ts and certify ingest) |
| 7 | `R2-07` | Give cq-5's typed step outcomes one exhaustive STEP_STATUS table that every consumer derives from: store readiness and taint, dispatch, planner, reconciler, snapshot | incomplete_round1_fix (cq-5) | 7 | 7 | M | high | — |
| 8 | `R2-08` | Finish cq-13a: a finally-guarded recipe restore with a broker cleanup allowance, and a run-disposer registry plus lint for new per-run module Maps (fail closed, not FIFO-evict) | incomplete_round1_fix (13a restore) and carried_over_open (13b) (cq-13a / cq-13b) | 5 | 5 | S-M | high | R2-01 (broker.ts section lease); R2-04 (floor-recipe-engine.ts lease) |
| 9 | `R2-09` | Bound scoped approval leases: required TTL and maxUses, persona binding by default, a typed lease_scope column backfilled conservatively, and server-side blast radius | new (lease schema exists, wiring missing); the lease_scope sentinel is a new cq-10-class instance from e9e5ffd (cq-10 (sentinel/side-channel pattern)) | 6 | 5 | S-M | high | R2-01 (shared mutation classification passed to leases); R2-12 (store.ts/schema.ts migration ownership; or R2-09 owns v11 and R2-12 follows) |
| 10 | `R2-10` | Give LLM semantic dedupe a deterministic veto, so a model 'duplicate' verdict cannot drop a distinct finding before verification | new (to the audit series; code predates the window) (R3-H-13 class (dedupe)) | 6 | 5 | S | medium-high | — |
| 11 | `R2-11` | Make the cq-4 parity corpus mandatory for confirmation-kernel diffs, assert TP verdicts under every permutation, and backfill one case per R3 kernel class | incomplete_round1_fix (cq-4) | 6 | 7 | M | high | R2-03 (owns check-contract-change.ts); R2-02 (kernel suites must actually run) |
| 12 | `R2-12` | Give persistence one verified authority: unquarantine and fix the schema drift, verify the schema at store open, TS/SQL confirmation-gate parity, and fail-closed safety decoders | new (to the series), plus an incomplete cq-3 (drift hidden by quarantine) and incomplete R3-H-16 (retention coverage) (cq-3 / cq-10 / R3-H-16) | 5 | 5 | M | high (core), medium (retention impact) | R2-02 (quarantine format); R2-09 (coordinate store.ts migration ownership) |
| 13 | `R2-13` | Type provider failures once, add a run-level provider circuit, and make transient model failures retryable under a bounded budget, with a fault-injection contract test first | new (round 1 explicitly left provider reliability out of scope); a consequence of cq-5's non-retryable model_failure (cq-5 / cq-6) | 6 | 6 | M | medium-high | R2-07 (retryable semantics in STEP_STATUS); R2-01 (approval-judge.ts lease) |
| 14 | `R2-14` | Make 'No issue found' truthful: route-scoped, evidence-backed coverage that floor confirmations reach, typed precondition_unmet gaps, and a planner closure that needs evidence | new, plus incomplete cq-5 (planner closure, capped_out not consumed) (cq-5 / cq-12) | 6 | 6 | M | high | R2-15 (class->OWASP map) or a shared map landed here first; R2-07 (exec-recon-planner.ts section coordination) |
| 15 | `R2-15` | Ship cq-12a decoupled from cq-10: a taxonomy conformance ratchet, typed-first injection-family and impact classification, and per-class impact and remediation templates | carried_over_open, with a new fork added by cq-4 and a newly verified prose-relabel mechanism (cq-12a / cq-12b) | 5 | 6 | M | high | R2-11 (corpus cases as gate); R2-04 (floor-recipe-engine.ts lease ordering) |
| 16 | `R2-16` | Stage a single host-owned TargetLoadPolicy: an effective-policy snapshot first, one origin-down taxonomy, IP/port aggregate caps, throttle events, and a polite-target fixture with TargetClass forcing | new (cq-3 (lint misses the knobs)) | 6 | 6 | L (staged) | high | R2-01 (broker breaker section); R2-06 (effective_config event); R2-03 (lint widening for caps) |
| 17 | `R2-17` | cq-10 stage 1: typed persona tenant and privilege end to end (UI, API, bench), one resolver wrapping parseRoleLabel, and a fix for the live owner->member misclassification | carried_over_open (cq-10 (and cq-12 for the lexicon collapse)) | 6 | 6 | M-L | high | R2-12 / R2-09 (store.ts migration ordering) |
| 18 | `R2-18` | One host-produced findings projection for every operator surface (headline, report, Markdown, SARIF, receipt bundle) with operator triage as an overlay and a backingKind | new (to the series); recurrence of earlier point patches 312b1aa and ac71d5a (cq-12 (class mapping)) | 4 | 6 | M | high | R2-14 (coverage category separation); R2-10 (shared finding-keys module) |
| 19 | `R2-19` | Finish cq-6: delete the @deprecated budget constants that still drive live wall-clock, migrate only the quarantined tests that encode the budget contract, and wire or delete inert token telemetry | incomplete_round1_fix (cq-6 / cq-11) | 3 | 4 | S | high | R2-07 (exec-dispatch.ts); R2-02 (per-case quarantine format) |
| 20 | `R2-20` | cq-9 step 1: a fixture-contamination ratchet derived from benchmark blueprints, landed together with a novel-vocabulary cell | carried_over_open (cq-9) | 3 | 4 | M | high | R2-05 (ledger for the novel cell); R2-06 (wordlist default OFF) |
| 21 | `R2-21` | Provider runtime policy and cost truth: explicit per-profile timeouts and compaction recomputed per failover, no silent Flash price defaults, abort-path cost, and cost per confirmation recorded in the ledger | new (cq-6 (budget sizing)) | 4 | 4 | M | medium | R2-13 (typed provider errors, fault-injection harness); R2-05 (ledger) |
| 22 | `R2-22` | De-duplicate the safety primitives copied by lease splits (chromium launch, citation walkers) and close the carried-over worker mount permission exposures (M-8/L-7) | carried_over_open (permissions predate the window) and new (lease-split duplication) (cq-4 / cq-11 (lease-era duplicates)) | 3 | 3 | M | high | R2-12 (evidence-citations module) |
| 23 | `R2-23` | Fold cq-7 into the ledger and EffectiveConfig: persist the existing floor-preservation and agentic-lift metrics, record the floor duration policy, fix the 'exact --no-llm' docstring, then run the 2-arm A/B | carried_over_open (planned Wave-4 deferral, blocked on the ledger) (cq-7) | 2 | 2 | S | high | R2-05; R2-06 |

## Ranking rationale

The score is (impact x leverage) / effort, weighted by confidence. Precision, target safety and approval invariants act as overrides, so small fixes that close fail-open safety decisions rank above larger measurement work with similar raw scores.

R2-01 ranks first. It is S effort, high confidence, and closes three places where a host safety decision trusts a model- or worker-declared label: Judge riskLevel defaulting to medium and auto-approving, injection probeClass skipping the origin-down breaker, and the admission catch setting explicit=true. I re-checked the key lines on HEAD.

R2-02 and R2-03 come next because they make round-1 cq-3 and cq-11 actually effective. Right now the gate reports green while kernel failures grow inside whole-file quarantine, and merges are gated on worktrees rather than the merged tree. Every later item depends on a trustworthy gate, so these have the highest leverage on effort already spent.

R2-04 (retest truthfulness) ranks above the measurement work despite a narrower blast radius. 'Verified fixed' on an unbuildable receipt is the most operator-visible false statement, and the fix is S-M.

R2-05 and R2-06 complete cq-1 and cq-2. The ledger is empty, graders default to precision 1, and EffectiveConfig is declared rather than observed. Without them no capability claim, including the post-fix re-measurement of R2-01..04, is traceable.

R2-07 completes cq-5. Dependents strand and the planner deferral gate is fooled, which costs recall directly.

R2-08 (recipe restore) and R2-09 (lease bounds) are target-safety and approval items. They rank above several higher-leverage maintainability items because those invariants are non-negotiable and both fixes are S-M wiring into existing columns and patterns.

R2-10 (dedupe veto) is a cheap direct recall fix.

R2-11 through R2-15 are incomplete cq-4/cq-12 work and new persistence, provider and coverage classes. Each is M effort with solid evidence, ordered by impact.

R2-16, the full target-load-policy refactor, is valuable but L and touches hot files, so it is staged behind R2-01 and R2-06.

Carried-over items that are not regressing rank last: cq-10 (R2-17), cq-6 cleanup (R2-19), cq-9 (R2-20) and cq-7 (R2-23). cq-9 and cq-7 are explicitly sequenced behind the ledger.

Verdict corrections applied:
- The exec-floor-lane wordlist bypass was refuted and dropped.
- Env mismatch explains only a minority of quarantine entries.
- The retry is surfaced, not silent.
- The Judge fail-open is gated by three regex safeguards and carried a Contract-Change trailer. The defect is the missing-field default plus the audit attribution.
- The env-mode 500-event cap fails closed. Only the catch fails open.
- There are three safety classifiers, not four.
- The ROADMAP:861 stall evidence predates the watchdog fix.
- The umask class is pre-window carry-over.
- The ModelGate parity claim is low impact.
- The --resume-snapshot claim was miscited.
- costPerFinding is persisted in matrix JSON.
- Same-run floor and agentic lift metrics already exist.

Lease conflicts are resolved by owner:
- check-contract-change.ts: R2-03
- bench-ledger.ts and certify: R2-05
- exec-dispatch.ts: R2-07 first
- broker.ts breaker section: R2-01 first
- floor-recipe-engine.ts: R2-04, then R2-08, then R2-15
- store.ts migrations: R2-09 or R2-12, one writer, with R2-17 after

Suggested first parallel wave with disjoint leases: R2-01, R2-02, R2-04, R2-07 and R2-10.

---

## 1. Close three fail-open host safety decisions keyed on model- or worker-declared labels: Judge riskLevel default, probeClass breaker exemption, and the admission explicit-mode catch

`id: R2-01` · relation: new (same failure class as R3: host decision keyed on worker/LLM-declared field); the breaker part is an incomplete fix of 51376b3 · round-1 link: cq-3 (Contract-change lint missed it); R3 class · impact 8/10 · leverage 6/10 · effort S · confidence high

**Depends on:** —

**Problem.** Three host safety decisions take their input from a label the model or worker supplies, and fail open when that label is missing or matches. (a) The safety Judge schema sets riskLevel to default('medium'). Since b5af3ea, under the default auto_review policy, Stage 2 turns a low or medium escalate_human into approve and logs decidedBy 'auto-review:judge'. A Judge reply that omits riskLevel is therefore auto-approved for any request the three regex safeguards miss. The body-aware mutation classification from admission (isStructuralMutation, jsonrpc_destructive) never reaches the Judge. (b) In broker.ts, any 5xx whose free-text probeClass matches the injection regex returns early. This happens before the ORIGIN_DOWN_5XX_STATUSES check (502-504, 520-526) and the route breaker, and probeInduced5xx has no threshold. The protection 51376b3 says it 'keeps' cannot be reached during the riskiest traffic. (c) The explicit-environment-mode catch in request-admission sets explicit=true when approvalPolicy is undefined. That puts the request on the permissive allowed_environment_contract branch.

**Verified evidence.**

- src/server/approval-judge.ts:124-128 riskLevel .default('medium') (re-checked on HEAD); 1110-1150 low/medium escalate_human becomes approve with decidedBy auto-review:judge; domain.ts:627 makes auto_review the default
- git show b5af3ea -- tests/v5-security-approvals.test.ts: the mocked riskLevel was moved from medium to high, so the medium-escalation path is no longer covered under the 'cannot flip' test name
- src/server/broker.ts:2971-2974 early return for a 5xx under an injection-class probeClass (re-checked on HEAD), placed before ORIGIN_DOWN_5XX_STATUSES at ~2997; verify-rpc.ts:674 forwards the worker's probeClass unchanged
- tests/v6-transport.test.ts:403-446 asserts that a 502 under an injection-class probe leaves the circuit closed, so the suite locks the gap in
- src/server/request-admission.ts:359-382 catch sets explicit=(grant.approvalPolicy===undefined); 1669-1680 explicit mode grants allowed_environment_contract; store-runs.ts:441-449 already has an unbounded hasExplicitEnvironmentMode that admission does not use
- src/server/request-admission.ts:1600 classifyRequestMutation has one caller; its result is not passed to approval-judge or to lease eligibility (985-1001). R3-H-1 recommended sharing it and that never landed

**Observed symptoms.** State-changing probes can be auto-approved when the Judge leaves out a field, and the audit trail credits the Judge. Injection phases keep sending traffic (within the per-origin RPS and in-flight caps) to an origin that returns edge 52x or 502-504. A store exception during admission can widen approval.

**Systematic improvement.** Host-derived safety inputs, fail-closed parsing, and an auditable normalization. Parse the Judge strictly: a missing riskLevel means high. Set risk = max(hostFloor, judgeRisk), where hostFloor comes from classifyRequestMutation plus the domain HIGH_RISK tokens. Never convert escalate_human to approve unless hostFloor is low. Record originalJudgeDecision and originalRiskLevel as structured fields, and set decidedBy to 'auto-review:policy'. The broker decides the breaker exemption itself: origin-down statuses and transport errors are never exempt, and probe-induced 5xx is capped per window. Admission calls the store's hasExplicitEnvironmentMode, and its catch never yields explicit=true.

**First PR-sized steps.**

1. PR-1a (approval-judge.ts, tests/approval-judge.test.ts, tests/v5-security-approvals.test.ts): remove .default('medium') and treat a missing riskLevel as 'high'. Add a hostFloor input computed from classifyRequestMutation and pass it from the request-admission call site. Add structured originalJudgeDecision and riskLevel fields. Restore a medium-escalation test case and add a missing-riskLevel case. Include a Contract-change trailer.
2. PR-1b (broker.ts breaker block ~926-930 and 2966-3007, tests/v6-transport.test.ts): exempt only plain 500/501 under an error-inducing probe class. Never exempt ORIGIN_DOWN_5XX_STATUSES or transport failures. Add a probeInduced5xx per-window threshold that opens the route breaker. Update the v6-transport assertion deliberately, with a trailer.
3. PR-1c (request-admission.ts:359-382 only, plus a new test): replace the 500-event scan with storage.hasExplicitEnvironmentMode(runId). In the catch, set explicit=false and emit a degradation event.
4. Audit tests/approval-judge.test.ts:124,232,384 for medium-escalation mocks that now assert approve, and decide per case.

**Success metric.** A unit matrix over decision x riskLevel (including missing) x hostFloor never approves when hostFloor>low or riskLevel is missing. A 502 or 52x burst under any probeClass opens the origin breaker. The admission catch path cannot produce allowed_environment_contract. The --no-llm deterministic floor on dev seed 42 is unchanged.

**Risks / invariants to preserve.** A stricter Judge adds HITL prompts on agentic runs, which can lower agentic recall in auto_review benchmarks. Measure on the smoke tier; do not relax the floor. The breaker change can open the circuit on targets that really answer injections with 502, so keep plain 500 as evidence. Breaker and lease code in broker.ts and request-admission.ts are hot shared files and need short section leases.

**Suggested lease.** `src/server/approval-judge.ts`, `src/server/broker.ts (breaker section 900-940, 2940-3010 only)`, `src/server/request-admission.ts (359-382 only)`, `tests/approval-judge.test.ts`, `tests/v5-security-approvals.test.ts`, `tests/v6-transport.test.ts`

---

## 2. Make quarantine per-case and drift-detecting, derive unquarantinable suites from KERNEL_TEST_RE, and run the fast tier hermetically with production Node flags

`id: R2-02` · relation: incomplete_round1_fix · round-1 link: cq-3 · impact 8/10 · leverage 9/10 · effort M · confidence high

**Depends on:** —

**Problem.** tests/QUARANTINE.json quarantines whole files. It has 91 entries against a cap of 91, all expire 2026-12-26, 76 owners are triage buckets, and only the seeding commit has touched it. run-fast-tests.sh drops quarantined files entirely. About 520 passing cases go ungated along with 188 failing ones, across 13 KERNEL_TEST_RE suites, and failures inside them keep growing: t2-receipt-kernel 1->2, t2-oracle-invariants 3->4, v7-proofreceipt 5->7, t2-composite-hydrate 2->3, specs-recall 1->2. H-13 SameSite went red after c9169d6 with no gate signal. Files that now pass (xben-readback, ux-wave-exec-polish) stay quarantined. UNQUARANTINABLE is a separate hand list of 7 files and does not match the Contract-change lint's KERNEL_TEST_RE, so the lint protects kernel files that quarantine lets stop running. The runner inherits ambient env and runs without production Node flags. That env mismatch explains only a minority of entries (roughly 0-3 of 11-15 sampled), so most entries are real kernel or fixture drift.

**Verified evidence.**

- tests/QUARANTINE.json: 91/91 entries (re-counted on HEAD), single expiry, git log shows only 5249b9e
- scripts/run-fast-tests.sh:74-82 UNQUARANTINABLE vs scripts/check-contract-change.ts:82 KERNEL_TEST_RE; :295 filters quarantined files out
- Reproduced failure growth in the quarantined kernel suites. tests/v7-floor-recipes failed 8/21 then 7/21, so it is nondeterministic
- c9169d6 (22:55) turned H-13 red inside a file quarantined at 21:48
- runOne execFile passes no env and no hardening flags; the f2d541c -> 9ca47ec -> dc8b48c chain shows the production-only crash class
- plans/claude_quality.md:168-170 round-1 metric: 'quarantine list shrinks every week; never bulk-realign kernel suites'. Not met
- tests/arch-b3-cascade.test.ts:526 (schema authority) is quarantined and hides real column drift (see R2-12)

**Observed symptoms.** worker-gate reports '100% green' (792bb75) while precision-kernel, recall and schema-authority assertions fail in growing numbers. The same file is red locally and green in CI. All entries expire on one date.

**Systematic improvement.** Entries become {file, testName, assertionLocation, ownerStream, expires}. The runner always executes quarantined files at the same concurrency. It fails on any unlisted failure. A listed case that now passes twice in a row produces a 'remove entry' failure, without editing the repo. The cap only decreases, checked against git history. The unquarantinable set is imported from one exported KERNEL_TEST_RE plus the schema-authority and provider-redaction suites. Child processes get an allowlisted env, a per-file temp KOVO_DATA_DIR and the production Node flags from one runtime-profile constant. Then re-triage once: fix the product or fix stale fixtures with a Contract-change trailer, never bulk-realign.

**First PR-sized steps.**

1. PR-2a (scripts/run-fast-tests.sh, tests/QUARANTINE.json schema v2): parse per-test results with --test-reporter=tap or junit. Key entries on file+testName. Run quarantined files, fail on new failures, report now-passing cases. Convert the 91 entries mechanically, giving each its current failing-case names.
2. PR-2b (scripts/check-contract-change.ts export only, run-fast-tests.sh): export KERNEL_TEST_RE from a small new scripts/test-tiers.ts and import it in both places. Kernel cases become quarantinable only with a live STREAM-BACKLOG owner and an expiry of 14 days or less.
3. PR-2c (new scripts/runtime-profile.ts, run-fast-tests.sh runOne): allowlisted env, temp KOVO_DATA_DIR, hardened Node flags read from the same constant as package.json scan/start and cli.ts. Remove provider-stream from the static test:boundaries list or make that list honor quarantine.
4. Triage streams (one per kernel file owner): t2-receipt-kernel H-13 vs c9169d6, the v7-proofreceipt and t2-oracle-invariants C-7 stale fixtures, specs-recall privileged delete, floor-regress twin, movea-retest-norm H-5. Each gets fixed or carries an explicit per-case entry.

**Success metric.** No whole-file entries remain. maxQuarantined decreases every week. Zero quarantined KERNEL_TEST_RE cases without a live owner. A deliberately injected new failure in a quarantined kernel file turns worker-gate red. The local and CI verdict on provider-stream agree.

**Risks / invariants to preserve.** Making kernel cases unquarantinable will turn the gate red on about 20 kernel cases at once. That is correct, but it needs a planned triage window or swarm merges stall. Fingerprints must not key on assertion prose, which drifts. Running quarantined files adds wall time to the 60s budget. Nondeterministic suites need two consecutive passes before they count as passing.

**Suggested lease.** `scripts/run-fast-tests.sh`, `tests/QUARANTINE.json`, `scripts/test-tiers.ts (new)`, `scripts/runtime-profile.ts (new)`, `package.json (test:boundaries only)`

---

## 3. Gate the merged tree, not the worktree: a merge queue, the fast tier in CI, monotone ratchets with prune-fail, and an unwired metric that measures reachability

`id: R2-03` · relation: incomplete_round1_fix · round-1 link: cq-3 / cq-11 · impact 6/10 · leverage 8/10 · effort S-M · confidence high

**Depends on:** R2-02 (CI-required fast tier needs trustworthy quarantine)

**Problem.** worker-gate runs only in each stream's worktree. The pulse still says 'merge it, run worker-gate, push', and tests-only branches merge without the gate. CI (verify.yml) never runs run-fast-tests, worker-gate, check-unwired or check-contract-change. In 42 merges over about 87 minutes, main went red. 'fix(gate)' sweeps (ca3e395, 792bb75) then re-baselined other streams' breakage under one generic trailer, including loosening a ReDoS timing budget from 100 to 250ms. --write-baseline rewrites unwired-baseline.json wholesale (1069 -> 1112 -> 1181), and the ok predicate ignores resolvedBaselineExports (0 since creation). About 88% of entries are export-only noise. A syntactic import counts as 'wired' even when the code is unreachable at runtime, as with token-telemetry, where no caller passes runId or onTelemetry. The Contract-change lint matches only *_DEFAULT|_BUDGET|_MS exports under src/server, accepts one trailer for a whole range, and checks nothing on main after a push.

**Verified evidence.**

- git show ca3e395 / 792bb75: cross-stream realign plus baseline refresh under one trailer; tests/r2-ws19-graph-dos.test.ts:66,84,91 budget loosened
- scripts/parallel-pulse.sh:110-113; AGENTS.md:33; .github/workflows/verify.yml:30-39 (no fast tier or ratchets)
- scripts/check-unwired.ts:807-812 ok ignores resolved; 859-868 wholesale rewrite; 634 scans src/server only; live --json: ok=true, resolved=0
- src/server/exec-dispatch.ts:3053 resolveProviderStallNoTokenMs is dead, yet still baselined at unwired-baseline.json:423 even though the cq-11 triage (claude_quality.md:616) said to delete it
- src/server/agent-session.ts:3841-3853 providerOpts sets no runId/onTelemetry, so createTelemetryEmitter returns undefined and merge 151cf7a's telemetry claim is inert
- scripts/check-contract-change.ts:84,87,286-291,362-387; 0 of ~15 new exported caps match; defaultMaxRpsPerOrigin in src/domain.ts was changed 5->10 by 51376b3 and is invisible to the lint

**Observed symptoms.** Several gate-restore commits a day. Baselines only grow. Security assertions change inside other streams' commits. The hourly 'unwired primitives' metric is flat by construction.

**Systematic improvement.** scripts/merge-stream.sh merges into a temp ref, runs worker-gate on the merged tree, fast-forwards only on PASS, and refuses merges while main is red. This applies to tests-only branches too. CI runs run-fast-tests --suites-only, check-unwired and check-contract-change against the merge base. --write-baseline may only remove entries; additions need a per-entry owner, ticket and expiry, and changes to ratchet files plus loosened literals in r2-*/r3-*/security tests need operator review (CODEOWNERS-style). resolvedBaselineExports>0 fails until pruned. Exports used only inside their own module are dropped from the metric, and keepUnwired entries that are wired internally are flagged. The tunable regex is widened to *_CAP|*_MAX_*|*_IN_FLIGHT|*_RPS|*_LIMIT and covers src/domain.ts. One trailer line is required per changed id.

**First PR-sized steps.**

1. PR-3a (scripts/merge-stream.sh new, scripts/parallel-pulse.sh, AGENTS.md pulse wording): merge queue on the merged tree, with a red-main lock file outside the repo.
2. PR-3b (.github/workflows/verify.yml): add the fast tier (suites-only), check-unwired, and check-contract-change with an explicit merge-base. Make them required once R2-02 lands.
3. PR-3c (scripts/check-unwired.ts, scripts/unwired-baseline.json): removal-only write, prune-fail, own-module filter, a stale-keepUnwired check, and scripts/ plus benchmarks/**/grader in scope. Regenerate once; the baseline should shrink by about 1000.
4. PR-3d (scripts/check-contract-change.ts): wider tunable regex including src/domain.ts, per-id trailer lines, extend KERNEL/GATE scope to tests/r2-*, tests/r3-*, tests/*security*, and run against merge-base when on main.
5. PR-3e (src/server/exec-dispatch.ts:3050-3057 only, after R2-07 merges; src/server/token-telemetry.ts): delete resolveProviderStallNoTokenMs. Either wire token telemetry by passing runId in agent-session providerOpts (coordinate with the R2-19 owner) or delete the module.

**Success metric.** Zero 'fix(gate)' realign commits per batch. Main red time is about 0 minutes. unwired-baseline count goes down every week, from about 1181 to under 200 real entries after the own-module filter. CI fails on a new unbaselined export or an untrailered change to an exported cap.

**Risks / invariants to preserve.** Serializing merges lowers swarm throughput, and that is the intended trade. Self-authored 'Ratchet-change' records are still self-service unless an operator ack is required. Per-batch caps can be gamed by removing export keywords. Required CI is only meaningful once the fast tier is green under R2-02.

**Suggested lease.** `scripts/merge-stream.sh (new)`, `scripts/parallel-pulse.sh`, `AGENTS.md (pulse/merge sections)`, `scripts/check-unwired.ts`, `scripts/unwired-baseline.json`, `scripts/check-contract-change.ts (owner; R2-02 and R2-11 hand off via this stream)`, `.github/workflows/verify.yml`

---

## 4. Make 'Verified fixed' mean reconfirmed absence: one retest-health assessor for all three retest engines, and split oracle_failed

`id: R2-04` · relation: carried_over_open (residual of R2-H-15/H-16/H-19) and incomplete_round1_fix of cq-4 ('fixed in A, not in B') · round-1 link: cq-4 · impact 7/10 · leverage 6/10 · effort S-M · confidence high

**Depends on:** —

**Problem.** classifyRetestHealth exists only in floor-recipe-engine.ts:1169, used at :1421. In retestPersistedAgentScript, a rejected composite stage, an unbuildable ProofReceipt and a failed receipt verification all set reason 'oracle_failed'. That maps to dismissed and then 'fixed', which the UI renders as 'Verified fixed'. The declarative path maps deterministicProofPassed=false with controlPassed=true to dismissed, and then to fixed. The Verify Fix handler records the verdict unchanged. After a patch, a drifted session or a broken receipt builder therefore reads as a fix.

**Verified evidence.**

- src/server/agent-script-proof.ts:600,663,705 set reason oracle_failed; 861 maps to dismissed; 895 maps to fixed
- src/server/replay-verifier.ts:774-795,944-974: dismissed when controlPassed even if the proof check failed
- src/server/exec-verify.ts:4073-4100: Verify Fix records retestRes.verdict unchanged
- src/report-summary.ts:36; src/components/.../findings-inspector.tsx:37 render 'Verified fixed'
- plans/CLAUDE_AUDIT_R2.md:649-677,1015,1327 step 7 ('never map oracle_failed to fixed') is still open; c60f6a6 fixed floor recipes only

**Observed symptoms.** After remediation, operators see 'Verified fixed' on findings that were never reconfirmed absent. This is the most operator-visible truthfulness defect in the product.

**Systematic improvement.** Add src/server/retest-health.ts with assessRetestHealth(baseline, probeArms, session) used by the floor, declarative and agent-script retests. Split oracle_failed into claim_not_reproduced, which may map to fixed only after the baseline and probe-arm health checks pass, and receipt_unbuildable / composite_stage_rejected / session_drifted, which map to inconclusive. Add parity corpus cases for drifted-session and unbuildable-receipt retests.

**First PR-sized steps.**

1. PR-4a (src/server/retest-health.ts new, src/server/floor-recipe-engine.ts:1169-1180 re-export only): move classifyRetestHealth into the shared module unchanged.
2. PR-4b (src/server/agent-script-proof.ts): typed reasons; map receipt and composite failures to inconclusive; call assessRetestHealth before 'fixed'.
3. PR-4c (src/server/replay-verifier.ts retest mapping ~774-795, 944-974): require deterministicProofPassed-equivalent arm health before fixed.
4. PR-4d (tests/parity/corpus/*.json + tests/path-parity.test.ts): add retest cases for session drift, unbuildable receipt and composite stage rejection, asserting inconclusive on all three engines.

**Success metric.** Across the three engines, no retest yields 'fixed' when the receipt is unbuildable, a composite stage is rejected, or the session is drifted (corpus-enforced). The UI shows 'Retest inconclusive' with a typed reason.

**Risks / invariants to preserve.** Some honest fixes will now show as inconclusive. That is acceptable and truthful. It must not change first-confirmation verdicts, so run the parity corpus before and after. floor-recipe-engine.ts is also wanted by R2-08 and R2-15, so serialize.

**Suggested lease.** `src/server/retest-health.ts (new)`, `src/server/agent-script-proof.ts`, `src/server/replay-verifier.ts (retest section only)`, `src/server/floor-recipe-engine.ts (1160-1180, 1410-1430 only)`, `tests/parity/corpus/`, `tests/path-parity.test.ts`

---

## 5. Put the measurement layer on the default path: one 3-state ScorecardReader and ledger-row builder, no precision-1 defaults, a working regression-floor, and tracked held-out seed exposure

`id: R2-05` · relation: incomplete_round1_fix · round-1 link: cq-1 / cq-2 / cq-3 · impact 7/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R2-02 (test:boundaries/quarantine reconciliation)

**Problem.** cq-1's lease excluded the shared graders and certify ingest, so fail-closed scoring stopped at the matrices. realistic and reason graders still return precision=1 on empty input. certify-phase1 uses asNumber(card.precision,1), 1-on-tp+fp=0, min-over-1-defaults, and a union-of-sites reason denominator, so crashed reason cells are fully absorbed. certify-v8:1430 defaults to 1. benchmark-recall drops unmatchedConfirmed. Three aggregators write the ledger 'rawPrecision' from the headline precision. The ledger is opt-in behind --ledger, which nothing passes, and ledger.jsonl is 0 bytes. regression-floor.sh reads t.confirmed where the field is outcome, so the lost-TP check is vacuous. It has no baseline, its test:boundaries step contains the quarantined red provider-stream suite (also run in CI), and nothing invokes it, so the golden E2E moved there has no runner. Held-out draws always start at HMAC index 0.

**Verified evidence.**

- benchmarks/realistic-bench/grader/score.ts:266,271; benchmarks/reason-bench/grader/score.ts:212
- scripts/certify-phase1.ts:573,578,1003,1033,1040-1063,1055,1317,1367,1432-1465,1550
- scripts/benchmark-recall.ts:205 countFalsePositives without unmatchedConfirmed
- scripts/benchmark-realistic-matrix.ts:170,398; scripts/certify-v8.ts:1430,3164; scripts/benchmark-agentic-matrix.ts:~647,~1033 rawPrecision mislabel
- benchmarks/results/ledger.jsonl 0 bytes (re-checked on HEAD); no .sh, package.json or workflow passes --ledger
- scripts/regression-floor.sh:104-106 vs scripts/benchmark-core.ts:774-780 (outcome); no benchmarks/baselines/
- scripts/run-fast-tests.sh:70-71 golden E2E excluded 'to run in regression-floor'; .github/workflows/verify.yml:33-36 runs test:boundaries including quarantined provider-stream

**Observed symptoms.** A crashed held-out or reason cell can certify at 100% precision. No capability claim traces to a SHA, config hash or benchmarkVersion. About 3K lines of verifier rewrites (c9169d6, 0e8c6b0, c79ea93, 4cb5a68) and the default flips (51376b3, b5af3ea) have no recorded floor.

**Systematic improvement.** Add scripts/score-primitives.ts: ratioOrNull, a schema-validated ScorecardReader with the cell states ok_with_claims, ok_no_claims and failed_inert, and buildLedgerRow() as the only row constructor. Every grader, aggregator and certify ingest goes through it. failed_inert makes the certificate INVALID, and reason denominators count expected targets. Ledger rows are written by default to a gitignored per-run directory, and only certifying or batch-boundary rows are promoted into the committed ledger, which avoids merge conflicts. regression-floor uses outcome==='confirmed', a committed baseline taken from a ledger row, and a quarantine-derived test:boundaries; it runs nightly and at batch boundaries. Seed exposure is recorded per certificate, and smoke uses a separate HMAC domain.

**First PR-sized steps.**

1. PR-5a (scripts/score-primitives.ts new, tests/score-parity.test.ts new): reader plus buildLedgerRow, and a parity test that feeds empty, failed and ok_no_claims cells through every grader and aggregator.
2. PR-5b (benchmarks/realistic-bench/grader/score.ts, benchmarks/reason-bench/grader/score.ts, scripts/benchmark-recall.ts): add rawPrecision to reason-bench, pass unmatchedConfirmed, and add the Contract-change trailer and CHANGELOG row.
3. PR-5c (scripts/certify-phase1.ts, scripts/certify-v8.ts, scripts/benchmark-realistic-matrix.ts, scripts/benchmark-agentic-matrix.ts): consume the reader and buildLedgerRow, and mark failed or inert cells INVALID.
4. PR-5d (scripts/regression-floor.sh, benchmarks/baselines/ new, package.json test:boundaries): fix the field, commit a baseline, derive boundaries from quarantine, and add a nightly job to verify.yml (coordinate with the R2-03 owner).
5. PR-5e (scripts/bench-ledger.ts drawUnburnedHeldoutSeeds, benchmarks/realistic-bench/generator/seeds.ts): a separate smoke domain and draws after the highest recorded exposed index.

**Success metric.** The parity test proves that an empty or failed cell never yields precision 1 in any path. ledger.jsonl has the cq-1/2/5 re-baseline rows. regression-floor passes on main and fails on an injected lost TP. Every merge touching confirmation paths cites a ledger row whose SHA is an ancestor.

**Risks / invariants to preserve.** Treating ok_no_claims as a failure would flip clean-control and reason cells without cause, so three states are needed. Grader changes move historical numbers and need a re-baseline row. A committed ledger edited from many worktrees causes conflicts, hence the per-run files. 'Floor-deferred' trailers can become boilerplate without an expiry.

**Suggested lease.** `scripts/score-primitives.ts (new)`, `benchmarks/realistic-bench/grader/score.ts`, `benchmarks/reason-bench/grader/score.ts`, `scripts/benchmark-recall.ts`, `scripts/certify-phase1.ts`, `scripts/certify-v8.ts`, `scripts/benchmark-realistic-matrix.ts`, `scripts/benchmark-agentic-matrix.ts`, `scripts/regression-floor.sh`, `scripts/bench-ledger.ts (owner; R2-06 hands off)`, `benchmarks/baselines/ (new)`

---

## 6. Record what the run actually ran: an engine-emitted effective_config event, wordlist default OFF, certify refusals, no harness-written confirmed findings, and a pinned worker image identity

`id: R2-06` · relation: incomplete_round1_fix (cq-2 config hash is declared, not observed; cq-1 wordlist default) plus newly surfaced harness-trust holes; cq-8 remainder stays open · round-1 link: cq-2 / cq-1 / cq-8 · impact 7/10 · leverage 7/10 · effort M · confidence high (floor-lane bypass sub-claim refuted and dropped)

**Depends on:** R2-05 (owns bench-ledger.ts and certify ingest)

**Problem.** computeEffectiveConfig stamps whatever the caller passes in. conventionalWordlistEnabled() defaults to ON, and only benchmark-realistic.ts sets the env. multihop, reason, realism and cli run Execution in-process with the wordlist ON, and multihop still stamps wordlistOn:false. The exec-floor-lane list itself is filtered by its source:'conventional' tag, so the earlier bypass claim is refuted. certify-phase1 hashes literals, and certify-v8 falls back to the tree version on mixed benchmarkVersions and never checks reportable or wordlistOn. scripts/benchmark-realism.ts writes runtime_confirmed findings into the Store with a harness-built verifiedInline result and no ProofReceipt for the non-browser SPA proofs (0b65c36 called this a capability PASS). The worker image is a mutable kovo-worker:v4 tag with no source label. The preflight inspects the literal tag while the runtime honors KOVO_WORKER_IMAGE, and sdkVersion strings (v6-mvp vs v8) are never compared. hillclimb-loop writes rc 0 for a skipped agentic leg.

**Verified evidence.**

- src/server/deterministic-engine.ts:98-112,4921,4956; scripts/benchmark-realistic.ts:2982-2983; scripts/bench-ledger.ts:212-215
- scripts/benchmark-multihop.ts:3344,4066 wordlistOn:false without setting the env; benchmark-reason.ts and benchmark-realism.ts record no provenance
- scripts/certify-phase1.ts:1837-1852; scripts/certify-v8.ts:2436-2442
- scripts/benchmark-realism.ts:3034-3058 createReplaySpec verifiedInline + upsertChainFinding runtime_confirmed provenance agent_only
- worker/Dockerfile:133,153 (no LABEL); src/server/worker-backend.ts:2273,2286 vs scripts/benchmark-backend.ts:63-68; src/server/verify-rpc.ts:479 vs worker/kovo_verify/kovo_verify.ts:158
- scripts/hillclimb-loop.sh:46-49 'echo 0' on a skipped leg

**Observed symptoms.** Multihop and reason numbers can include wordlist inflation while their rows say OFF. Enterprise-SPA 'PASS' is harness work. A stale worker image can make a fix look ineffective, and nobody can tell afterward.

**Systematic improvement.** Execution emits one run.effective_config event with the resolved environment, tier, approvalPolicy, wordlist switch, conventional endpoints probed, receipt mode, siblings, floor caps (including the floor duration, which absorbs cq-7 recording), model profile id and worker image ID. computeEffectiveConfig reads the event and fails when a caller literal disagrees. Flip the wordlist default to OFF. certify refuses rows that are mixed-version, have a null hash, are reportable=false or wordlistOn=true. The Store refuses verifiedInline or runtime_confirmed unless a verifier-issued receipt or backing kind is present, so the SPA lane must be moved into src/server or tagged harness_assisted and excluded. The image gets a source-hash LABEL, the preflight resolves the same image as the runtime, the image ID is recorded per row, and hillclimb exits nonzero on a skipped leg.

**First PR-sized steps.**

1. PR-6a (src/server/deterministic-engine.ts:98-112 only, scripts/hillclimb-loop.sh): default OFF; fail on a skipped leg.
2. PR-6b (src/server/execution.ts emit event near run start; scripts/bench-ledger.ts computeEffectiveConfig, after R2-05 lands): observed config, with a mismatch failure.
3. PR-6c (src/server/store-session.ts createReplaySpec/upsertChainFinding guard, scripts/benchmark-realism.ts SPA lane): reject self-built verifiedInline; retag the lane harness_assisted.
4. PR-6d (worker/Dockerfile, scripts/benchmark-backend.ts, src/server/verify-rpc.ts hello check): LABEL plus resolved-image preflight plus an sdkVersion handshake.
5. PR-6e (scripts/certify-phase1.ts, scripts/certify-v8.ts ingest checks; coordinate with the R2-05 owner).

**Success metric.** Every ledger row's effectiveConfig is derived from the event, and a test proves that a caller literal disagreeing with the run fails. No scripts/ path can persist runtime_confirmed without a receipt. Image ID and sdkVersion appear in every row and mismatches refuse certification.

**Risks / invariants to preserve.** Flipping the default may drop multihop or reason numbers. That is the honest number and should be recorded as a discontinuity row. Tightening the Store invariant may break other script writers, so audit them with grep first. Do not relax local-lab double gating or approval tiers to make shipped-shape cells score. Report Tier-1/2 as tier-labeled numbers.

**Suggested lease.** `src/server/deterministic-engine.ts (98-112 only)`, `src/server/execution.ts (effective_config emit only)`, `src/server/store-session.ts (replay-spec/finding write guard)`, `scripts/benchmark-realism.ts`, `scripts/benchmark-multihop.ts`, `scripts/benchmark-backend.ts`, `worker/Dockerfile`, `scripts/hillclimb-loop.sh`

---

## 7. Give cq-5's typed step outcomes one exhaustive STEP_STATUS table that every consumer derives from: store readiness and taint, dispatch, planner, reconciler, snapshot

`id: R2-07` · relation: incomplete_round1_fix · round-1 link: cq-5 · impact 7/10 · leverage 7/10 · effort M · confidence high

**Depends on:** —

**Problem.** cq-5 (f60b5a4) added turn_capped, nudged_out, rotated_partial, model_failure and infra_failed at the producer side only. store-runs refreshReadyChainSteps still taints only on tainted/canceled/blocked and readies only on 'complete'. Dependents of the five new statuses therefore stay pending forever, re-checked on HEAD. Dispatch's permanentlyBlockedStepIds (a second rule) and the planner's CONTINUABLE set (a third rule) disagree. Stranded dependents of capped, nudged or rotated parents are counted as dispatchable, which inflates stranded-ready numbers and satisfies the O3 planner deferral gate ('ready >= buffer'), suppressing LLM planner rounds and costing recall. A retry step depends on the capped original, and the original's other dependents are never re-pointed. The RunActor reconciler and countDrySteps only know complete/canceled.

**Verified evidence.**

- src/server/store-runs.ts:1340-1352 (re-checked on HEAD)
- src/server/schema.ts:150-169 vs src/server/exec-dispatch.ts:1063-1070,1141-1182 vs src/server/exec-recon-planner.ts:4417-4425
- src/server/exec-recon-planner.ts:5288-5349 deferral gate uses dispatchableReadySteps
- src/server/exec-recon-planner.ts:1519-1539 retry depends on the original; dependents not re-pointed
- src/server/run-actor.ts:2503-2520; src/server/run-snapshot.ts:366-379
- git show f60b5a4 --stat: store-runs, run-actor, run-snapshot, report and score.ts were never touched

**Observed symptoms.** Chain dependents silently strand. Funnel and stranded-ready counts are inflated. Planner rounds are deferred on phantom ready work.

**Systematic improvement.** Add a browser-safe src/step-status.ts with STEP_STATUS satisfying Record<ChainStepStatus, {terminal, retryable, satisfiesDependency, killsDependents, lostWork, glyph}>. Pick one semantic. Recommended: capped, nudged and rotated parents do NOT satisfy dependents; dependents are re-pointed to the retry; when the retry is exhausted, dependents become typed lost (counted as lost work). Store refresh, permanentlyBlockedStepIds, the planner creation check, the reconciler and countDrySteps all derive from the table. Add a property test that store propagation and dispatch agree for every status pair.

**First PR-sized steps.**

1. PR-7a (src/step-status.ts new, src/server/schema.ts re-export, tests/step-status-agreement.test.ts new): table plus property test (red until 7b).
2. PR-7b (src/server/store-runs.ts refreshReadyChainSteps 1330-1360, src/server/exec-dispatch.ts 1063-1182): derive from the table.
3. PR-7c (src/server/exec-recon-planner.ts 1519-1539 retry re-point, 4417-4425 CONTINUABLE): one shared predicate.
4. PR-7d (src/server/run-actor.ts 2503-2520, src/server/run-snapshot.ts 366-379): typed reconciliation and dry-streak.
5. Follow-on stream (report/UI): rename the 'Verified steps' tile to 'Steps finished' with lost and capped segments (store-runs.ts:3107-3112, report.tsx:345, report-export.ts:437, glyphs.tsx, overview.tsx:93). Separately, wire classifyProductAttribution into grader/score.ts with a trailer and ledger row.

**Success metric.** The property test passes for all status pairs. Zero pending steps whose dependency is terminal at run end, checked on the smoke tier. The planner deferral gate never counts a step with a terminal non-satisfying dependency. The report shows lost and capped counts.

**Risks / invariants to preserve.** Making capped parents satisfy dependents would fire continuations off unverified partial state, so choose the conservative semantic. The retry re-point must stay inside the one-retry cap and RunSafetyBudgets. Scope the literal-comparison lint to terminal statuses only, since 'running' and 'pending' checks are legitimate. exec-dispatch.ts is also wanted by R2-13 and R2-03e, so this stream goes first.

**Suggested lease.** `src/step-status.ts (new)`, `src/server/schema.ts (status consts only)`, `src/server/store-runs.ts (refreshReadyChainSteps section)`, `src/server/exec-dispatch.ts (1060-1190)`, `src/server/exec-recon-planner.ts (1510-1540, 4410-4430, 5285-5350)`, `src/server/run-actor.ts (2500-2520)`, `src/server/run-snapshot.ts`

---

## 8. Finish cq-13a: a finally-guarded recipe restore with a broker cleanup allowance, and a run-disposer registry plus lint for new per-run module Maps (fail closed, not FIFO-evict)

`id: R2-08` · relation: incomplete_round1_fix (13a restore) and carried_over_open (13b) · round-1 link: cq-13a / cq-13b · impact 5/10 · leverage 5/10 · effort S-M · confidence high

**Depends on:** R2-01 (broker.ts section lease); R2-04 (floor-recipe-engine.ts lease)

**Problem.** cq-13a (c74834f) never touched floor-recipes.ts or floor-recipe-engine.ts. The persisted_mutation state_restore is still a straight-line `if (args.reset)` after the readback, while race_burst uses finally. The realistic skip trigger is deps.request throwing during post_mutation_read (BrokerDenied, approval, deadline abort). runFloorRecipe catches the throw and builds a fallback receipt, so the mutation stays applied. A non-selfState baselineWrite never restores the owner's original value, even on success. A finally restore on the same grant, signal and budget would throw again. Meanwhile three new module-level per-run Maps landed outside disposal: the async-poll safety budget (a copy of the custody budget with a '__default__' bucket and FIFO 2048, which fails open on eviction), cq-6 alias counters (unbounded), and token telemetry (LRU 512). Their reset helpers are test-only and baselined as unwired.

**Verified evidence.**

- src/server/floor-recipes.ts:961-971 vs 1268-1272; 1773-1786 catch builds fallbackReceipt; 728-731 require never throws
- src/server/floor-recipe-engine.ts:565-581 reset only from hyp.functionState.reset
- plans/ROADMAP-v5.md:1068 and claude_quality.md:618 put the restore in 13a; tests/cq-13a-redaction-restore.test.ts has no restore case
- src/server/derived-custody.ts:52-61 vs src/server/verify-support.ts:227-280: same shape, only custody registered at execution.ts:794,904
- src/server/verify-runner.ts:140-168; src/server/token-telemetry.ts:113,161-174,400; scripts/unwired-baseline.json:1146,1156
- src/server/broker.ts:4424-4480 executeHttp throws BrokerDenied/throwIfAborted, so cleanup needs its own allowance

**Observed symptoms.** An aborted mutating floor proof can leave a record or tenant scope drifted for later probes by the same persona, which is the 0df720d drift class. Safety budgets can silently reset. Memory grows slowly in long-lived servers.

**Systematic improvement.** ctx.registerRestore() right after baseline_read, drained in a finally inside runFloorRecipe using a broker-level cleanup allowance with an independent short signal. The allowance must stay within approval leases and scope. If the restore fails, invalidate and re-mint the persona session and emit a degradation event. Cover the baselineWrite case. Add registerRunDisposer(fn), drained by cleanupRunState, and move the async-poll budget into RunSafetyBudgets with runId required, denial with a counter at the cap, and no '__default__'. Add a worker-gate lint ratchet against new top-level Map/Set keyed by run, assignment or persona outside the registry, and forbid baselining reset*/dispose* helpers for per-run state.

**First PR-sized steps.**

1. PR-8a (src/server/floor-recipes.ts, src/server/broker.ts cleanup-allowance hook only, tests/floor-recipe-restore.test.ts new): finally restore plus a throw-injection test after mutation_probe, asserting the restore was sent or the session re-minted.
2. PR-8b (src/server/run-disposers.ts new, src/server/execution.ts cleanupRunState 785-795): registry; register alias, telemetry and async-poll.
3. PR-8c (src/server/verify-support.ts 227-280, src/server/run-safety-budgets.ts): migrate the async-poll budget, fail closed at the cap.
4. PR-8d (scripts/check-run-scoped-state.ts new, scripts/worker-gate.sh): ratchet lint from today's count. Mark 13a partial and then done in plans/ROADMAP-v5.md.

**Success metric.** The throw-injection test shows restore attempted, or the session invalidated, on every abort path. Zero per-run module Maps outside the registry beyond the baseline. The async-poll budget denies, and never resets, at the cap.

**Risks / invariants to preserve.** The restore is itself a live mutation and must go through approval and scope gates, so do not let the cleanup allowance bypass them. A planner rule rejecting mutating recipes without a restore risks recall, so make it soft (a pre-proof baseline counts as the declared restore) and check parity-corpus confirmation counts. broker.ts is shared with R2-01, so serialize.

**Suggested lease.** `src/server/floor-recipes.ts`, `src/server/floor-recipe-engine.ts (560-585 only)`, `src/server/run-disposers.ts (new)`, `src/server/verify-support.ts (227-280)`, `src/server/run-safety-budgets.ts`, `scripts/check-run-scoped-state.ts (new)`

---

## 9. Bound scoped approval leases: required TTL and maxUses, persona binding by default, a typed lease_scope column backfilled conservatively, and server-side blast radius

`id: R2-09` · relation: new (lease schema exists, wiring missing); the lease_scope sentinel is a new cq-10-class instance from e9e5ffd · round-1 link: cq-10 (sentinel/side-channel pattern) · impact 6/10 · leverage 5/10 · effort S-M · confidence high

**Depends on:** R2-01 (shared mutation classification passed to leases); R2-12 (store.ts/schema.ts migration ownership; or R2-09 owns v11 and R2-12 follows)

**Problem.** Durable leases are created with expiresAt null, and no caller passes expiresInMs, while single-use grants get 15 minutes. 'uses' is incremented but never capped. leaseAuthorizes(runId, origin, method, path) takes no persona, although personaHandle is stored. Bulk and lease approvals are recorded as riskLevel 'low'. The blast-radius preview is computed client-side over pending cards only. Host scope uses a sentinel method/pattern pair. Prefix scope is inferred from the '/x/**' shape, so pre-e9e5ffd rows matched by exact routePattern now widen into subtree grants with no migration. Mitigations already in place: scopeRevision binding, host leases exclude DELETE and high-risk paths, and glob paths are rejected.

**Verified evidence.**

- src/server/store-runs.ts:1477,1532 (15-min single-use) vs 1634 (durable null); 1690-1773 leaseAuthorizes has no persona; 2077, 2105-2122 riskLevel low
- src/components/run/views/queue.tsx:95-176 matchingPendingApprovalIds client-side
- src/domain.ts:37-54 sentinels; store-runs.ts:1573-1640 shape inference; git show e9e5ffd^ leaseAuthorizes was exact inArray
- src/server/request-admission.ts:985-1001 lease eligibility ignores isStructuralMutation/jsonrpc_destructive

**Observed symptoms.** One host-lease click authorizes unbounded future writes by any persona for the rest of the scope revision. The audit trail records these as low risk.

**Systematic improvement.** Leases require a TTL (default 30 minutes, operator-adjustable) and maxUses. They bind to personaHandle by default, with an explicit cross-persona opt-in so BOLA/IDOR differential runs don't stall. Add lease_scope TEXT with a CHECK in ('route','prefix','host_nondestructive') through a v11 migration. Backfill existing '/**'-shaped rows as 'route', never 'prefix'. Lease eligibility consumes the shared mutation classification from R2-01. The blast-radius endpoint is computed server-side over the endpoint inventory. Record the original risk tier, not 'low'.

**First PR-sized steps.**

1. PR-9a (src/server/store.ts v11 migration, src/server/schema.ts approval_leases, src/server/store-runs.ts lease create/authorize sections): lease_scope column with backfill as route; TTL and maxUses enforced; persona check.
2. PR-9b (src/server/request-admission.ts 985-1001, 1647-1652): eligibility rejects structural or destructive classifications.
3. PR-9c (src/server/api route for blast radius + src/components/run/views/queue.tsx): server-side preview.
4. Tests: lease expiry, use cap, cross-persona denial, and legacy '/x/**' row not widened.

**Success metric.** No active lease without expiresAt and maxUses. A legacy glob-shaped row authorizes only its exact pattern. A cross-persona request under a persona-bound lease prompts. Smoke-tier approval prompt count is recorded before and after.

**Risks / invariants to preserve.** Persona binding without the opt-in stalls authz differential runs on approvals. Lease reuse is disabled in local-lab, so benchmarks won't show regressions, and that needs a unit fixture. Schema migration touches store.ts, so coordinate with the R2-12 owner (one writer).

**Suggested lease.** `src/server/store-runs.ts (lease sections 1470-1780, 2060-2130)`, `src/server/store.ts (v11 migration block only)`, `src/server/schema.ts (approval_leases only)`, `src/server/request-admission.ts (985-1001, 1640-1660)`, `src/components/run/views/queue.tsx`, `src/domain.ts (lease sentinels 37-54)`

---

## 10. Give LLM semantic dedupe a deterministic veto, so a model 'duplicate' verdict cannot drop a distinct finding before verification

`id: R2-10` · relation: new (to the audit series; code predates the window) · round-1 link: R3-H-13 class (dedupe) · impact 6/10 · leverage 5/10 · effort S · confidence medium-high

**Depends on:** —

**Problem.** findNearbyFindings returns any same-origin, same-category row, even one on another endpoint. When the LLM returns isDuplicate with an id in that set, the verdict is accepted (dedupe.ts:719-743). The method, param, field, mutation and handler conflict guards exist only in deterministicSemanticFallback. The worker runner returns rejected:true before the verifyNow path, so a second, distinct BOLA on a different route can disappear on agentic runs.

**Verified evidence.**

- src/server/dedupe.ts:519-548 (guards only in fallback), 566-614, 719-743
- src/server/exec-worker-runner.ts:1515-1559,1656 rejection before verification
- src/report-summary.ts:131-150 a report-time copy of ORIGIN_WIDE_CWE_KEYS (in sync today; drift risk)

**Observed symptoms.** Agentic recall loss on multi-endpoint authz classes that never shows up as a miss category.

**Systematic improvement.** Extract the fallback's probe-conflict predicate (same origin, method, route template, input location and handler, with no conflicting param, field or mutation) into one exported function. The LLM may only merge candidates that pass it. Otherwise the candidate continues to verification and is recorded as a sibling. Charge sibling verification to RunSafetyBudgets and skip it for structural duplicates. Move ORIGIN_WIDE_CWE_KEYS into a shared browser-safe src/finding-keys.ts used by the server and the report layer.

**First PR-sized steps.**

1. PR-10a (src/server/dedupe.ts): extract sameFindingPredicate and apply it as a veto on the LLM path.
2. PR-10b (tests/dedupe-veto.test.ts new): two distinct-endpoint BOLA candidates with an LLM mock that says duplicate; both reach verification.
3. PR-10c (src/finding-keys.ts new, src/server/finding-fingerprint.ts, src/report-summary.ts): a single key module.

**Success metric.** The veto test passes. The agentic smoke tier shows no fewer confirmed authz findings than before, and on the multi-endpoint authz fixture it should show more.

**Risks / invariants to preserve.** More candidates reach verification, which adds requests to the target. Keep it inside budgets. Some true duplicates may now confirm twice, so rely on fingerprint dedupe at persist time.

**Suggested lease.** `src/server/dedupe.ts`, `src/finding-keys.ts (new)`, `src/server/finding-fingerprint.ts`, `src/report-summary.ts (131-150 only)`, `tests/dedupe-veto.test.ts (new)`

---

## 11. Make the cq-4 parity corpus mandatory for confirmation-kernel diffs, assert TP verdicts under every permutation, and backfill one case per R3 kernel class

`id: R2-11` · relation: incomplete_round1_fix · round-1 link: cq-4 · impact 6/10 · leverage 7/10 · effort M · confidence high

**Depends on:** R2-03 (owns check-contract-change.ts); R2-02 (kernel suites must actually run)

**Problem.** Only c1e2b4e has touched tests/parity or path-parity.test.ts. Seven R3 confirmation fixes (0e8c6b0, 303dc87, c79ea93, 4cb5a68, 158b9d7, c9169d6, 2d08b72) added bespoke r3-*.test.ts files and zero corpus cases. The 15 hand-authored cases have no boolean, timing, OOB, SSRF, redirect, race, browser or retest case. TP verdicts under cwe_only and free_text are never asserted. evaluateClaims and the strict receipt paths expect opposite results for the 'other' label, which is undocumented. Five R3 IDs were each split across two commits. One result: the composite terminal-exchange resolution now exists twice with different last fallbacks.

**Verified evidence.**

- git log -- tests/parity tests/path-parity.test.ts (only c1e2b4e)
- tests/path-parity.test.ts:123,511-550,603-632,726-743
- src/server/composite-receipt.ts:235-242 vs src/server/exec-verify.ts:633-655
- scripts/check-contract-change.ts:71-82 protects existing kernel tests but never requires a corpus addition

**Observed symptoms.** Each R3 guard is proven at one entry point only. The next audit will find 'fixed in A, not in B' variants.

**Systematic improvement.** Add a path-triggered rule: any diff to replay-verifier, verify-claims, proof-receipt, floor-recipe*, composite-receipt, oracle-invariants, exec-verify, v8-oracle-* or verify-support must touch tests/parity/corpus or carry 'Parity-case: <id>' naming an existing case. The lint verifies the id exists. Assert TP verdicts under all permutations in each entry point. Document the 'other' layering as an explicit exception table. Backfill TP and FP cases for the boolean, timing, OOB, SSRF, redirect and race classes and each R3 kernel class, seeded from recorded confirmations without embedding raw probe strings. Consolidate composite terminal resolution into one function, owned here or by R2-15.

**First PR-sized steps.**

1. PR-11a (tests/path-parity.test.ts): TP asserts across all 5 permutations; an explicit 'other' exception table.
2. PR-11b (tests/parity/corpus/*.json): about 10 new cases, one per missing class and R3 kernel ID.
3. PR-11c (scripts/check-contract-change.ts rule, delivered via the R2-03 owner): Parity-case requirement on kernel diffs.
4. PR-11d (src/server/composite-terminal.ts new, composite-receipt.ts, exec-verify.ts 633-655): a single resolver plus a corpus case without terminalExchangeId.

**Success metric.** The corpus covers every manifest receipt class, and a lint fails on uncovered classes, with a ticketed exemption allowed. 100% of kernel-touching merges carry a corpus change or a valid Parity-case id.

**Risks / invariants to preserve.** Forcing identical 'other' verdicts could drop TPs the strict receipt correctly confirms, so document the layering instead. Agents may add trivial cases to satisfy the rule, so require each case to assert at least two entry points.

**Suggested lease.** `tests/path-parity.test.ts`, `tests/parity/corpus/`, `src/server/composite-terminal.ts (new)`, `src/server/composite-receipt.ts (235-242)`, `src/server/exec-verify.ts (633-655 only)`

---

## 12. Give persistence one verified authority: unquarantine and fix the schema drift, verify the schema at store open, TS/SQL confirmation-gate parity, and fail-closed safety decoders

`id: R2-12` · relation: new (to the series), plus an incomplete cq-3 (drift hidden by quarantine) and incomplete R3-H-16 (retention coverage) · round-1 link: cq-3 / cq-10 / R3-H-16 · impact 5/10 · leverage 5/10 · effort M · confidence high (core), medium (retention impact)

**Depends on:** R2-02 (quarantine format); R2-09 (coordinate store.ts migration ownership)

**Problem.** The schema-authority test (arch-b3-cascade:526) fails on six columns that the v10 DDL adds but schema.ts lacks: findings status, severity, cwe, origin and triage_status, plus operations created_at. cq-3 quarantined it. schema.ts and the DDL also disagree on the max_rps_per_origin default (10 vs 5). The TS assertConfirmationEvidence and the SQL trigger accept different backings in both directions, and no parity test exists. getDeclinedOrigins returns [] on a parse failure, which re-admits declined origins. artifact-ttl protection uses a key-name regex with empty catches, so a failed query shrinks the protected set and the prune still runs. It also never scans sast_runs.raw_artifact_id, messages.evidence_ids or lab_telemetry.artifact_id, and store-session keeps a second, different citing-column list. About 20 direct .db writes outside store-*.ts bypass repository invariants, including exec-verify findings writes, one without a run_id predicate.

**Verified evidence.**

- tests/arch-b3-cascade.test.ts:526 fails on HEAD; tests/QUARANTINE.json:11
- src/server/store.ts:1225-1253 vs src/server/schema.ts:477-500,575-580; schema.ts:119 vs store.ts:356
- src/server/store.ts:147-188 vs src/server/store-findings.ts:1131-1205
- src/server/store-runs.ts:189-215 declined_origins fail-open; callers subdomain-discovery.ts:1443, store-runs.ts:533/2458/2873
- src/server/artifact-ttl.ts:129-151,175-260 vs src/server/store-session.ts:1874-1910
- src/server/exec-verify.ts:2539-2560,4160-4180 direct writes

**Observed symptoms.** Unnoticed schema drift. Opt-in retention can delete cited evidence after a transient error. Corrupt scope state re-admits declined origins. Proof acceptance depends on which gate a write path hits.

**Systematic improvement.** Add the six columns to schema.ts. Make the authority test unquarantinable, with a derived table count, and have it compare defaults and NOT NULL. Store.verifySchema() at open compares PRAGMA table_info with the Drizzle config and fails closed. Add a TS/SQL parity test over a shared fixture matrix (floor_artifact, receipt-without-object, oob) and either align the trigger or document it as deliberately stricter. Trigger installation stops swallowing 'syntax error'; check json_extract capability once at open. getDeclinedOrigins throws, and admission denies. artifact-ttl aborts the prune on any protection error. A shared CITING_COLUMNS constant serves both TTL and run-delete, with a schema-walk test. Add a ratchet lint on direct findings-table writes outside store-*.ts, routing the exec-verify writes through the repository and adding the run_id predicate.

**First PR-sized steps.**

1. PR-12a (src/server/schema.ts, tests/arch-b3-cascade.test.ts, tests/QUARANTINE.json entry removal): fix the drift and unquarantine.
2. PR-12b (src/server/store.ts verifySchema + trigger install): fail closed at open.
3. PR-12c (src/server/store-runs.ts 189-215; src/server/artifact-ttl.ts; src/server/evidence-citations.ts new used by store-session.ts 1874-1910): fail-closed decoders and one citing-column list.
4. PR-12d (tests/confirmation-gate-parity.test.ts new): TS vs SQL matrix.
5. PR-12e (src/server/exec-verify.ts 2539-2560, 4160-4180 → store-findings repository method; scripts/check-direct-db-writes.ts ratchet).

**Success metric.** The authority test is green and unquarantinable. Store open fails on injected drift. The parity matrix shows TS and SQL agree or match a documented table. A protection-query error aborts the prune in a test. The direct-write count only goes down.

**Risks / invariants to preserve.** verifySchema could refuse to open user data dirs that already have drift, so ship a repair migration in the same release. Aligning the gates could weaken one side, so the alignment must never accept a backing that neither side accepts today. Do not delete drizzle/ until db:generate consumers are confirmed absent.

**Suggested lease.** `src/server/schema.ts`, `src/server/store.ts`, `src/server/store-runs.ts (189-245 only)`, `src/server/artifact-ttl.ts`, `src/server/evidence-citations.ts (new)`, `src/server/store-session.ts (1874-1910 only)`, `tests/arch-b3-cascade.test.ts`, `tests/confirmation-gate-parity.test.ts (new)`

---

## 13. Type provider failures once, add a run-level provider circuit, and make transient model failures retryable under a bounded budget, with a fault-injection contract test first

`id: R2-13` · relation: new (round 1 explicitly left provider reliability out of scope); a consequence of cq-5's non-retryable model_failure · round-1 link: cq-5 / cq-6 · impact 6/10 · leverage 6/10 · effort M · confidence medium-high

**Depends on:** R2-07 (retryable semantics in STEP_STATUS); R2-01 (approval-judge.ts lease)

**Problem.** Provider errors are classified by prose regex at four disagreeing layers (MODEL_FAILURE_ERROR_RE, classifyFailoverError, isQuotaBody, provider.ts:1688). QuotaExhaustedError is declared but never thrown. model_failure and infra_failed are terminal and non-retryable, and dependents of a model_failure step are cascade-blocked. Pool retries only happen before the first emitted event. With a single profile, orderProfiles falls back to the open profile, and no dispatch code consults profile health. A 402 or auth failure therefore turns every ready step into model_failure and blocks its dependents, and the run 'completes' with no provider status. A Judge call failure returns stage fail_safe, which no consumer surfaces.

**Verified evidence.**

- src/server/exec-dispatch.ts:1097-1103,1153-1161; src/server/schema.ts:151-161
- src/server/provider.ts:374-379 (never thrown), 889, 1379-1393, 1407-1419, 1497-1558
- src/server/exec-worker-runner.ts:711-750,781-799
- src/server/approval-judge.ts:1166-1175 fail_safe; no consumer outside the file

**Observed symptoms.** Quota exhaustion yields a 'complete' run full of model_failure steps. Agentic recall varies with provider health, and lost steps are never re-dispatched. Note: the ROADMAP:861 stall figure came from the old 28s watchdog, since fixed, so recall sensitivity is a hypothesis to be measured.

**Systematic improvement.** Add a fault-injection contract test (429 with Retry-After, 402, mid-stream drop, silence) first. Throw typed errors from makeFetch and the pool (rate_limited, quota, auth, server, stall, stream_drop, context_overflow, with retryAfterMs and emitted), and classify once. Add a run-level provider circuit: when every profile for a role is hard-open for quota or auth, emit provider_paused and stop dispatch. Transient kinds become retryable under cq-5's one-retry-per-key cap, charged to RunSafetyBudgets. Mid-stream retry is allowed only when no tool call from the dropped turn has executed, and re-enters the same scope, tier and approval gates. The Judge retries once, then fail_safe is surfaced distinctly in the UI and report.

**First PR-sized steps.**

1. PR-13a (tests/provider-fault-injection.test.ts new): fault matrix against a stub transport.
2. PR-13b (src/server/provider.ts): typed errors; delete the duplicate regex classifiers.
3. PR-13c (src/server/exec-dispatch.ts classifyWorkerErrorToStepStatus + STEP_STATUS retryable flags, after R2-07; src/server/exec-worker-runner.ts 711-799): typed mapping plus the provider_paused circuit.
4. PR-13d (src/server/approval-judge.ts 1166-1175, after R2-01): one retry plus a structured fail_safe surfaced to the report.

**Success metric.** The fault matrix passes. A 402 run ends provider_paused within one dispatch tick with no new model_failure steps. A transient 429 step is re-dispatched once. Record stall and retry counts in the ledger.

**Risks / invariants to preserve.** Unbounded retries bring back duplicate-trial churn. Mid-stream resume could re-issue target requests, which is a target-safety invariant, so require the idempotency check. Overlaps exec-dispatch.ts with R2-07 and approval-judge.ts with R2-01, so serialize.

**Suggested lease.** `src/server/provider.ts`, `src/server/exec-worker-runner.ts (700-800)`, `src/server/exec-dispatch.ts (1090-1110 only, after R2-07)`, `tests/provider-fault-injection.test.ts (new)`

---

## 14. Make 'No issue found' truthful: route-scoped, evidence-backed coverage that floor confirmations reach, typed precondition_unmet gaps, and a planner closure that needs evidence

`id: R2-14` · relation: new, plus incomplete cq-5 (planner closure, capped_out not consumed) · round-1 link: cq-5 / cq-12 · impact 6/10 · leverage 6/10 · effort M · confidence high

**Depends on:** R2-15 (class->OWASP map) or a shared map landed here first; R2-07 (exec-recon-planner.ts section coordination)

**Problem.** upsertCoverageEntry is keyed (run, goalRevision, origin, category), overwrites status last-writer-wins, and drops route and exchangeIds. The tool promises 'route-scoped'. no_issue_found needs no evidence, and ruled_out needs only a free-text enforcingControl. recordReportedFindingCoverage skips any category that is not an OWASP value, and about 15 floor categories (xxe, ssrf, xss, path-traversal, open-redirect, jwt, race and others) are not, so most floor confirmations never mark their cell. The planner treats any no_issue_found or ruled_out row as closing the assignment, which cq-5 said only proved or gap_coded should do, and this costs recall. Tier, persona-count, browser and canary preconditions silently empty whole queues with no event. buildCoverageGapReport has five prose-regex kinds, marks a route covered after any exchange, and has not changed since d53e237, so it never reads cq-5's capped_out events.

**Verified evidence.**

- src/server/store-findings.ts:1904-1938; src/server/exec-worker-runner.ts:587-611; src/server/agent-session.ts:2954-2956
- src/server/exec-exchange.ts:202-220; src/server/deterministic-specs.ts:391-393,918-1964 categories
- src/server/exec-recon-planner.ts:3446-3451 closure
- src/server/exec-floor-lane.ts:551-557; exec-recon-planner.ts:2829; execution.ts:714-729 silent guards
- src/server/coverage-gaps.ts:23-29,71-74,315-356; exec-floor-lane.ts:1096-1111 capped_out unconsumed

**Observed symptoms.** The OWASP table can say 'No issue found' on a host with a confirmed floor finding. A Tier-2, one-persona, no-canary run reports few gaps while whole classes were never attempted.

**Systematic improvement.** Separate Finding.category (grader key) from coverageCategory everywhere through a class->OWASP map, which is a cq-12a deliverable. Extend the existing negative-edge coverage store (route, exchangeIds, branchKey) instead of adding a parallel table. no_issue_found and ruled_out require run-scoped, origin-matched exchangeIds. Coverage rank is monotone, with demotion allowed when the linked finding is superseded or dismissed. The planner closure in the same PR accepts only proved, gap_coded or evidence-backed rows. Existing guards emit typed coverage.precondition_unmet events, observational only, never gating. The gap report consumes precondition_unmet, capped_out and host_skipped keyed per route and class.

**First PR-sized steps.**

1. PR-14a (src/server/exec-exchange.ts 202-220, src/server/coverage-category.ts new): category->OWASP map (shared with R2-15), so floor confirmations mark cells.
2. PR-14b (src/server/store-findings.ts upsertCoverageEntry, src/server/exec-worker-runner.ts 587-611, src/server/exec-recon-planner.ts 3446-3451): evidence requirement, monotone rank, planner closure.
3. PR-14c (src/server/exec-floor-lane.ts 551-557, exec-recon-planner.ts 2829, execution.ts 714-729): emit precondition_unmet events.
4. PR-14d (src/server/coverage-gaps.ts): consume the typed events; key uncovered routes on method+route+class.

**Success metric.** No coverage cell reads no_issue_found where a confirmed finding exists, enforced by a test. Every guard that empties a queue emits one typed event. The gap report lists capped_out and precondition_unmet per route and class on the smoke tier.

**Risks / invariants to preserve.** Requiring exchangeIds may close fewer assignments and spend more turns. Keep it inside budgets. Worker-declared exchangeIds must be verified as run-owned, or this repeats R3-H-13. The registry must not change guard semantics.

**Suggested lease.** `src/server/coverage-category.ts (new)`, `src/server/exec-exchange.ts (200-225)`, `src/server/store-findings.ts (1900-1940)`, `src/server/exec-worker-runner.ts (580-615)`, `src/server/coverage-gaps.ts`, `src/server/exec-floor-lane.ts (545-560)`

---

## 15. Ship cq-12a decoupled from cq-10: a taxonomy conformance ratchet, typed-first injection-family and impact classification, and per-class impact and remediation templates

`id: R2-15` · relation: carried_over_open, with a new fork added by cq-4 and a newly verified prose-relabel mechanism · round-1 link: cq-12a / cq-12b · impact 5/10 · leverage 6/10 · effort M · confidence high

**Depends on:** R2-11 (corpus cases as gate); R2-04 (floor-recipe-engine.ts lease ordering)

**Problem.** No conformance test or vuln-taxonomy module exists. CWE drifts persist: CWE-362 maps three ways, 269 is missing from the exec-verify bfla family, business_logic sets disagree, and grader 284 maps to bfla while the product maps it to bola. cq-4 added inferInjectionFamily, an ordered prose regex over title, description and claim. Its typed override (context.injectionFamily) has no caller, and a null family widens the stripped-fingerprint search to every family. New finding: classifyImpactDescriptor reads free-text impact, and the shared baseFields boilerplate (inherited by 26 of 27 floor specs) contains authorization wording, so XXE, SSRF, traversal and JWT specs classify as 'authorization' (tsx-verified). That text feeds the replay impact gate and the receipt-class fallback. Severity is path-dependent (open_redirect is medium in SEVERITY_BY_CLASS and low as a spec literal) and is frozen from the model's value. IMMUTABLE_CONFIRMED_FINDING_FIELDS omits severity while the store lock freezes it.

**Verified evidence.**

- src/server/verify-claims.ts:507 (override unset), 1745-1757, 1474/1783/1818/1861 consumers; oracle-invariants.ts:3619-3631 null-family widening
- src/server/oracle-invariants.ts:579-616 classifyImpactDescriptor; src/server/deterministic-specs.ts:206-207, 1403-1405 point-patch comment
- src/server/replay-verifier.ts:520-525; src/server/floor-recipe-engine.ts:3502-3513
- src/server/floor-recipe-engine.ts:3402-3440, 791-812; src/server/exec-verify.ts:217-224,316-338; benchmarks/realistic-bench/grader/match.ts:9,86
- CWE-(?:...) alternation sites 10 in 2 files -> 13 in 3 files

**Observed symptoms.** Sibling CWEs fail closed or are charged to strictPrecision. Floor XXE and SSRF findings carry authorization impact text and may be routed through authorization gates. Open redirect severity depends on which path confirmed it.

**Systematic improvement.** Add tests/taxonomy-conformance.test.ts. It is read-only over all tables (exported inferInjectionFamily, the grader cweClassKey, IMPACT_CLASS_CWES, CWE_TO_RECEIPT_CLASS, the exec-verify families, SEVERITY_BY_CLASS) and records today's disagreements as a shrinking ratchet, so it can merge before cq-10. classifyImpactDescriptor and classifyBoundaryClaim stop reading impact, title and description whenever a typed CWE or vulnClass exists. Callers populate context.injectionFamily from the spec or receipt class. When typed and prose disagree, the result fails closed to an ambiguous family-specific requirement, never to the null any-family path. Per receipt class, add impact and remediation templates and a default severity band derived in bindConfirmedFindingIdentity. Add severity to IMMUTABLE_CONFIRMED_FINDING_FIELDS. The grader stays independent, cross-checked by the conformance test.

**First PR-sized steps.**

1. PR-15a (tests/taxonomy-conformance.test.ts new; export-only edits in verify-claims.ts and floor-recipe-engine.ts): the ratchet.
2. PR-15b (src/server/oracle-invariants.ts 579-616): typed-first impact classification; assert classify(spec fields)==table class for every floor spec.
3. PR-15c (src/server/verify-claims.ts 1745-1757 and the callers in replay-verifier/exec-verify): populate injectionFamily; prose becomes a counted fallback.
4. PR-15d (src/server/deterministic-specs.ts 190-210 baseFields): per-class impact and remediation templates; delete the 1405 point patch.
5. PR-15e (src/server/exec-verify.ts 217-224, 368-427): severity band derivation plus an immutability list fix. Plan a migration for already-confirmed rows.

**Success metric.** The conformance disagreement count only goes down. The tsx check shows XXE, SSRF, traversal and JWT floor specs classify to their own class. The parity corpus (cmdi-cross-family-fp, sqli-echoed-error-fp) stays green before and after. The CWE-alternation grep ratchet holds.

**Risks / invariants to preserve.** Narrowing classifier inputs changes gate verdicts, so gate on the parity corpus and the --no-llm floor. Grader changes need a trailer and a re-baseline. Re-deriving severity on locked rows needs versioning. Do not template titles, since they carry endpoint information; validate and prefix instead.

**Suggested lease.** `tests/taxonomy-conformance.test.ts (new)`, `src/server/oracle-invariants.ts (579-616, 4370-4390)`, `src/server/verify-claims.ts (1740-1830)`, `src/server/deterministic-specs.ts (190-210)`, `src/server/exec-verify.ts (215-430)`

---

## 16. Stage a single host-owned TargetLoadPolicy: an effective-policy snapshot first, one origin-down taxonomy, IP/port aggregate caps, throttle events, and a polite-target fixture with TargetClass forcing

`id: R2-16` · relation: new · round-1 link: cq-3 (lint misses the knobs) · impact 6/10 · leverage 6/10 · effort L (staged) · confidence high

**Depends on:** R2-01 (broker breaker section); R2-06 (effective_config event); R2-03 (lint widening for caps)

**Problem.** Target load is the product of about 8 separately owned knobs: broker in-flight and RPS, apex bucket, adaptiveRps, phase0 lanes, baseline-capture lanes, Phase-B AIMD, floor request cap, and resolveGrantMaxRps(grant,5). Each has its own constants, env parsers and status taxonomy. Broker origin-down covers 502-504 and 520-526, phase0 covers 520-526 only, and these merged 18 minutes apart. run-safety-budgets.ts has not changed in the window. The apex cap is skipped run-wide under local-lab, and registrableApex is null for IP literals, so IP-literal and multi-port targets escape the aggregate cap. AIMD treats worker error text containing '429' as llm_429. Throttle and apex state emit no run events. No fixture emits 429 with Retry-After or edge 52x, and lease reuse and external caps are disabled in local-lab, the only environment benchmarks run in.

**Verified evidence.**

- src/server/run-safety-budgets.ts:10-34 (last touched e2a64fe)
- src/server/broker.ts:1846-1933, 1858, 3542, 4793; src/server/phase0-recon.ts:3815-3831; src/server/exec-recon-planner.ts:219-226; src/server/exec-dispatch.ts:1612-1866
- commits 51376b3, efdac83, d9c8fe7 merged within 30 minutes; defaultMaxRpsPerOrigin 5->10 in src/domain.ts
- src/server/execution.ts:3563-3566; getCircuitState/getApexBucketCount have no external callers
- src/server/public-suffix.ts:309; run-actor.ts:1914,2134 local-lab disables lease reuse

**Observed symptoms.** No one can state the aggregate peak load a run places on one customer IP. Politeness regressions can only surface on customer systems.

**Systematic improvement.** Stage 1: resolve a read-only EffectivePolicy snapshot per run (all lane limits plus TargetClass per origin), persist it and show it in the UI, and move the constants and ONE status taxonomy (origin_down, throttled, transient) into run-safety-budgets.ts or a sibling it re-exports. Stage 2: inject it per lane and delete the local env parsers, one lane per PR. Add per-IP aggregate buckets for IP literals and ports. Emit throttle events, and keep LLM 429 on a separate channel. Add a <60s polite-target fixture (429 with Retry-After, 503/52x bursts, multi-vhost on one IP) that forces the external TargetClass on loopback through an injected TargetClass, not by toggling env-wide local-lab flags, and run it as a worker-gate class guard.

**First PR-sized steps.**

1. PR-16a (src/server/run-safety-budgets.ts + src/server/target-load-policy.ts new): constants plus a single status taxonomy, with re-exports only.
2. PR-16b (src/server/execution.ts: persist the effective policy event; coordinate with R2-06's effective_config event, which is the same event).
3. PR-16c (tests/polite-target.test.ts new + local-lab/polite-target fixture): TargetClass forcing knob in broker grant construction.
4. PR-16d..g: migrate the broker, then phase0, recon-planner and dispatch one per PR, deleting local parsers; per-IP aggregate bucket in the broker after R2-01 releases the breaker section.

**Success metric.** One source file defines every target-load ceiling, and grep finds no KOVO_* load env parsers elsewhere. The polite fixture shows Retry-After honored, the origin breaker opening on a 52x burst, and per-IP aggregate RPS at or below the cap across vhosts. The UI shows effective limits per run.

**Risks / invariants to preserve.** Touches hot shared files (broker, phase0, recon-planner, dispatch). One PR per lane is required by the one-writer rule. Changing effective local-lab rates can shift benchmark numbers, so stage 1 must be value-preserving and verified with a ledger row.

**Suggested lease.** `src/server/run-safety-budgets.ts`, `src/server/target-load-policy.ts (new)`, `tests/polite-target.test.ts (new)`, `local-lab/polite-target/ (new)`, `then per-lane: src/server/broker.ts (1840-1935), src/server/phase0-recon.ts (3810-3835), src/server/exec-recon-planner.ts (215-230), src/server/exec-dispatch.ts (1610-1870)`

---

## 17. cq-10 stage 1: typed persona tenant and privilege end to end (UI, API, bench), one resolver wrapping parseRoleLabel, and a fix for the live owner->member misclassification

`id: R2-17` · relation: carried_over_open · round-1 link: cq-10 (and cq-12 for the lexicon collapse) · impact 6/10 · leverage 6/10 · effort M-L · confidence high

**Depends on:** R2-12 / R2-09 (store.ts migration ordering)

**Problem.** Personas have only roleLabel. The UI suggests tenant-less labels ('User A') and has no tenant field, so only harness scripts write the '${role} (${tenant})' grammar. A persona created in the UI can never yield a cross-tenant BOLA confirmation, which makes authz recall a benchmark-only number. New R3 and patch-retest sites (verify-claims:955, patch-workflow:1828, v8-oracle-hydrate:969) route through parseRoleLabel and fail closed, costing recall. Five role lexicons disagree. exec-floor-lane privilegeOf maps 'owner (acme)' to member. patch-workflow defaults an unparsed role to member. canaryMarkers are unwired end to end.

**Verified evidence.**

- src/server/schema.ts:80-93 (no tenant_ref/privilege)
- src/components/project/PersonaFormModal.tsx:96,101,156,1157; scripts/benchmark-realistic.ts:681 (+ benchmark-reason:624, benchmark-realism:416,426, smoke-agentic:1456)
- src/server/exec-floor-lane.ts:977-985 vs src/server/oracle-invariants.ts:29-31,141-147 ('single source of truth' not honored)
- roleLabel refs 93->97, parseRole 42->43
- plans/claude_quality.md:615,659-660 round-1 lease names nonexistent paths (src/components/personas/, persona-identity.ts)

**Observed symptoms.** Real-user authz recall is unmeasured and likely near zero for UI-created personas. Each new guard's behavior depends on label shape.

**Systematic improvement.** Add persona tenant_ref and privilege columns (migration), API fields and PersonaFormModal fields at the correct path. The bench writes the typed fields. resolvePersonaIdentity() in oracle-invariants.ts wraps parseRoleLabel: typed fields first, label fallback with a counted event, fail closed when both are empty. Fix privilegeOf to use the resolver. Add an opaque-label ablation bench leg. Ratchet local re-implementations of tenant and privilege parsing (not parseRoleLabel calls) plus '[key=' prose tags. Leave the chain_steps typed columns for stage 2 (retry_of_step_id, prior_terminal_status) and the lexicon merge to cq-12.

**First PR-sized steps.**

1. PR-17a (src/server/store.ts migration after R2-09/R2-12, src/server/schema.ts personas, src/server/oracle-invariants.ts resolver).
2. PR-17b (src/components/project/PersonaFormModal.tsx + persona API route): tenant and privilege inputs.
3. PR-17c (scripts/benchmark-realistic.ts + the other 4 harness writers): write typed fields.
4. PR-17d (src/server/exec-floor-lane.ts 977-985, src/server/patch-workflow.ts 1828-1831): use the resolver.
5. Correct the cq-10 lease paths in plans/STREAM-BACKLOG.md.

**Success metric.** An opaque-label ablation cell (typed fields set, labels 'User A/B') matches label-shaped authz recall on dev seed 42. Counted label fallbacks reach zero on the bench. 'owner (acme)' resolves to owner.

**Risks / invariants to preserve.** Fail-closed on empty identity could regress harness recall unless the bench writes typed fields in the same batch. Wiring canaryMarkers raises recall but may raise FPs, so gate it on fp-archetypes and the parity corpus as a separate PR.

**Suggested lease.** `src/server/oracle-invariants.ts (29-31, 141-200)`, `src/components/project/PersonaFormModal.tsx`, `src/server/schema.ts (personas only)`, `scripts/benchmark-realistic.ts (persona construction ~681)`, `src/server/exec-floor-lane.ts (977-985)`, `src/server/patch-workflow.ts (1825-1835)`

---

## 18. One host-produced findings projection for every operator surface (headline, report, Markdown, SARIF, receipt bundle) with operator triage as an overlay and a backingKind

`id: R2-18` · relation: new (to the series); recurrence of earlier point patches 312b1aa and ac71d5a · round-1 link: cq-12 (class mapping) · impact 4/10 · leverage 6/10 · effort M · confidence high

**Depends on:** R2-14 (coverage category separation); R2-10 (shared finding-keys module)

**Problem.** Only report save filters out-of-scope, tainted, provenance-disallowed and evidence-less rows. The live headline, reused as the report title, does not. At least five 'confirmed' predicates exist (buildVerdict normFStatus also accepts 'verified', reportHighlights uses a bare status, isRuntimeConfirmedFinding, SARIF, and CONFIRMED_FINDING_PREDICATE_SQL, which is itself baselined as unwired), and there are 72 ad-hoc comparisons in 18 files. Operator triage (false_positive, accepted_risk, severity override) is stored but read by no count or export, and the override vocabulary uses 'info' while findingSeverities uses 'informational'. The receipt bundle marks floor and spec confirmations confirmed:false / legacy_unreceipted with no backing kind. Report exports mix the version-N snapshot with live gaps, and the stepper infers stage completion from a 500-exchange window.

**Verified evidence.**

- src/components/run/model.ts:57-62,449-450; src/components/run/views/report.tsx:176-178,319; src/server/store-runs.ts:3056-3104
- src/report-summary.ts:376-385,470-475; src/server/finding-codec.ts:67-69; src/server/sarif-export.ts:530-548; src/server/receipt-export.ts:922,958-966
- scripts/unwired-baseline.json:475 CONFIRMED_FINDING_PREDICATE_SQL
- src/server/finding-codec.ts:25-48 vs src/domain.ts:919; zero triage reads in report/export modules
- src/server/report-export.ts:246-257,722-731; src/components/run/format.ts:595-713

**Observed symptoms.** The report title can disagree with its own tile and with SARIF counts. Findings the operator marked false positive still appear as 'Fix first' in exports.

**Systematic improvement.** A pure, browser-safe projectRunFindings(rows, scopeCtx) -> FindingsView {reportable, confirmed, advisories, counts, backingKind, effectiveSeverity, disposition, exclusions with reasons}, used as the only producer for the headline, report save, report.tsx, Markdown, SARIF (false positives emitted as suppressions) and the receipt bundle (confirmed:false stays for unreceipted rows, with backingKind floor_spec/oob/receipt added). Triage affects operator views and exports only, never scoring or persisted confirmed state. Unify the severity vocabulary. Add a cross-surface conformance test and a baseline-and-ratchet lint over the 72 sites. Snapshot gaps at report save.

**First PR-sized steps.**

1. PR-18a (src/findings-view.ts new, tests/findings-view-conformance.test.ts new).
2. PR-18b (src/components/run/model.ts, src/components/run/views/report.tsx): consume the projection.
3. PR-18c (src/server/sarif-export.ts, src/server/receipt-export.ts, src/server/report-export.ts): consume the projection, add backingKind, snapshot gaps.
4. PR-18d (src/server/finding-codec.ts): 'info' -> 'informational' with a decode alias.

**Success metric.** The conformance test shows identical confirmed and reportable counts across headline, report, Markdown and SARIF for a fixture run. A false-positive-triaged finding appears as a SARIF suppression and is excluded from 'Fix first'. The benchmark scorer is unchanged (pinned test).

**Risks / invariants to preserve.** The scorer must stay independent so projection changes cannot move metrics. Relabelling unreceipted rows confirmed:true would weaken the offline-verifiable contract, so don't.

**Suggested lease.** `src/findings-view.ts (new)`, `src/components/run/model.ts`, `src/components/run/views/report.tsx`, `src/server/sarif-export.ts`, `src/server/receipt-export.ts`, `src/server/report-export.ts`, `src/server/finding-codec.ts`

---

## 19. Finish cq-6: delete the @deprecated budget constants that still drive live wall-clock, migrate only the quarantined tests that encode the budget contract, and wire or delete inert token telemetry

`id: R2-19` · relation: incomplete_round1_fix · round-1 link: cq-6 / cq-11 · impact 3/10 · leverage 4/10 · effort S · confidence high

**Depends on:** R2-07 (exec-dispatch.ts); R2-02 (per-case quarantine format)

**Problem.** AGENTIC_SPECIALIST_WALL_CLOCK_MS (80s) and AGENTIC_SPECIALIST_MAX_TURNS (9) are @deprecated, yet they still compute baseWallClockMs for single_step and multi_step. For multi_step, maxTurns rises to 20-34 while wall-clock stays clamped to 120-180s, so seconds per turn fall as turns grow. Round 1 told cq-6 to delete them, and they are still imported by agent-session.ts and execution.ts. Five tests are quarantined under the cq-6 owner; only v8-slot-rotation and gb-planner-wiring clearly encode the budget and rotation contract. Token telemetry is inert: no caller sets runId or onTelemetry, even though merge 151cf7a claims per-run telemetry.

**Verified evidence.**

- src/server/agent-prompts.ts:62-90; src/server/execution.ts:2738-2745,3491; src/server/exec-dispatch.ts:3247-3312
- plans/claude_quality.md:258-296 (item 6 first-PR steps 1-2)
- tests/QUARANTINE.json cq-6-agent-contract (5 files)
- src/server/agent-session.ts:3841-3853; src/server/token-telemetry.ts:274,306,319,400

**Observed symptoms.** Long chains get proportionally less wall-clock per turn and cap mid-repair. Wall-clock rotation and hop continuation are ungated.

**Systematic improvement.** Compute wall-clock inside resolveAssignmentBudget so seconds per turn never decrease as maxTurns grows, bounded by intentLeaseMs and run budgets, and delete the deprecated constants. Migrate v8-slot-rotation and gb-planner-wiring out of quarantine in the same PR. Pass runId and onTelemetry in agent-session providerOpts and add a run-summary reader, or delete token-telemetry.

**First PR-sized steps.**

1. PR-19a (src/server/agent-prompts.ts, src/server/exec-dispatch.ts 3247-3312 after R2-07, src/server/execution.ts 2738-2745): a single budget derivation.
2. PR-19b (tests/v8-slot-rotation.test.ts, tests/gb-planner-wiring.test.ts, tests/QUARANTINE.json entries).
3. PR-19c (src/server/agent-session.ts providerOpts slice ~3841-3853, src/server/token-telemetry.ts): wire or delete.

**Success metric.** grep finds zero imports of the deprecated constants. The two tests leave quarantine. The smoke tier shows wall-clock per turn non-decreasing in maxTurns, with spend recorded in the ledger.

**Risks / invariants to preserve.** A higher multi_step wall-clock raises spend, so bound it and measure on the smoke tier. agent-session.ts is a slice-only file.

**Suggested lease.** `src/server/agent-prompts.ts`, `src/server/exec-dispatch.ts (3240-3315)`, `src/server/execution.ts (2735-2750)`, `src/server/token-telemetry.ts`, `tests/v8-slot-rotation.test.ts`, `tests/gb-planner-wiring.test.ts`

---

## 20. cq-9 step 1: a fixture-contamination ratchet derived from benchmark blueprints, landed together with a novel-vocabulary cell

`id: R2-20` · relation: carried_over_open · round-1 link: cq-9 · impact 3/10 · leverage 4/10 · effort M · confidence high

**Depends on:** R2-05 (ledger for the novel cell); R2-06 (wordlist default OFF)

**Problem.** Fixture canary grammar (4 hits: deterministic-specs:1327, authz:181, xxe:121, cache:34), realistic-bench VFS paths used as traversal and XXE content oracles, and pool nouns in recon and engine regexes are all unchanged since a50d462. The pattern has not spread. The cache cross-actor body_repeat mode requires the fixture-grammar canary even when req.actorMarkers.owner exists. conventionalWordlistEnabled fails open when the env var is unset (R2-06 fixes the default). floor-heuristics.ts:42 has a second copy of the file-route vocabulary. The only contamination lint covers v8 names, and no novelVocab mode or floor-novel cell exists.

**Verified evidence.**

- src/server/probes/{cache.ts:34-40, authz.ts:181, xxe.ts:121,124, traversal.ts:77-84}; src/server/deterministic-specs.ts:1327
- benchmarks/realistic-bench/lib/canary.ts:13-15, lib/vfs.ts:86
- src/server/deterministic-engine.ts:3331; src/server/phase0-recon.ts:2466,2479; src/server/floor-heuristics.ts:42
- scripts/check-v8-contamination.ts:1-14; scripts/worker-gate.sh:45

**Observed symptoms.** The dev/held-out generalization gap is unmeasured. Two confirmation modes cannot fire on customer apps.

**Systematic improvement.** Generalize the lint to derive canary grammar, VFS paths and distinctive full-route strings from realistic-bench, reason-bench and multihop-saas, minus a curated generic lexicon. Run it in worker-gate with today's hits as a baseline that only falls, over all of src/server. Add the variant.ts novelVocab mode and a floor-novel ledger cell first, so later removals have measured costs. Then the cache mode uses actorMarkers.owner and fails closed without markers, and the VFS candidates are removed (expect an honest recall drop, re-baselined).

**First PR-sized steps.**

1. PR-20a (scripts/check-fixture-contamination.ts new, scripts/worker-gate.sh): ratchet lint.
2. PR-20b (benchmarks/realistic-bench/generator/variant.ts novelVocab; cell registered via the R2-05 ledger).
3. PR-20c (src/server/probes/cache.ts 34-40): owner marker replaces the grammar AND.

**Success metric.** The lint baseline count only decreases. The floor-novel cell is recorded in the ledger on every certification, with its delta to dev reported.

**Risks / invariants to preserve.** Pool nouns are generic API words, so key the lint on grammar, paths and full routes. Planted-marker credential proofs mutate the target and must go through approval leases. Never substitute entropy regexes, which raise FPs.

**Suggested lease.** `scripts/check-fixture-contamination.ts (new)`, `scripts/worker-gate.sh`, `benchmarks/realistic-bench/generator/variant.ts`, `src/server/probes/cache.ts`

---

## 21. Provider runtime policy and cost truth: explicit per-profile timeouts and compaction recomputed per failover, no silent Flash price defaults, abort-path cost, and cost per confirmation recorded in the ledger

`id: R2-21` · relation: new · round-1 link: cq-6 (budget sizing) · impact 4/10 · leverage 4/10 · effort M · confidence medium

**Depends on:** R2-13 (typed provider errors, fault-injection harness); R2-05 (ledger)

**Problem.** Watchdog tiers come from a model-name regex that hardcodes the default model family and are sized from pool[0] only. Five call sites hardcode first-event timeouts; semantic-audit requests reasoning affinity with a 45s cap that is below the 60s reasoning tier. Compaction reserve is derived from the primary profile's 1M window. Flash prices are defaulted in four places, so a new non-Flash profile silently under-counts against the hard USD budget. Mid-stream aborts record about 0 cost because usage frames arrive last. Stall and slow-turn counters are conflated in telemetry. costPerFinding exists in matrix JSON but not in the ledger.

**Verified evidence.**

- src/server/provider-stream.ts:13-46; src/server/exec-worker-runner.ts:884-920
- src/server/approval-judge.ts:696-698; src/server/semantic-audit.ts:650; src/server/dedupe.ts:826; src/server/patch-workflow.ts:318; src/server/provider.ts:1664
- src/server/agent-session.ts:3770,4236-4239
- src/domain.ts:1084-1096,1187-1189; src/server/schema.ts:36-38; src/server/provider.ts:494-545,1120-1136; src/server/store-runs.ts:2277-2310

**Observed symptoms.** Switching models silently changes stall, compaction and cost behavior. With a non-Flash profile the USD budget can overshoot by the price ratio.

**Systematic improvement.** A ProviderRuntimePolicy computed from the resolved profile's explicit fields and recomputed per failover candidate. One providerOptionsFor(run, role, purpose) used by the five call sites, which also injects runId and telemetry. Require explicit prices when creating a profile for a model other than the default, or fall back to a conservatively high rate; never disable the USD cap. Prefer provider-reported cost when present. Estimate abort-path output cost from streamed deltas, labeled as an estimate. Split stallAborts from slowTurns. Record costPerConfirmed and wastedUsd in ledger rows, with no gate yet.

**First PR-sized steps.**

1. PR-21a (src/server/provider-runtime-policy.ts new, src/server/provider-stream.ts): policy plus deletion of the model-name regex.
2. PR-21b (the five call sites): providerOptionsFor.
3. PR-21c (src/server/provider.ts cost path, src/server/model-settings.ts profile validation): pricing truth.
4. PR-21d (scripts/bench-ledger.ts row fields via the R2-05 owner).

**Success metric.** No hardcoded firstEventTimeoutMs outside the policy module. A non-Flash profile without explicit prices is rejected or priced conservatively. Abort-path spend is greater than 0 in the fault-injection test.

**Risks / invariants to preserve.** 'Null price means token-only' would silently disable the USD cap, so reject that option. A cost-per-confirmed gate would pressure the swarm to trade recall for cost, so record only.

**Suggested lease.** `src/server/provider-runtime-policy.ts (new)`, `src/server/provider-stream.ts`, `src/server/provider.ts (cost/usage sections)`, `src/server/model-settings.ts`, `src/server/semantic-audit.ts`, `src/server/dedupe.ts (826 only)`

---

## 22. De-duplicate the safety primitives copied by lease splits (chromium launch, citation walkers) and close the carried-over worker mount permission exposures (M-8/L-7)

`id: R2-22` · relation: carried_over_open (permissions predate the window) and new (lease-split duplication) · round-1 link: cq-4 / cq-11 (lease-era duplicates) · impact 3/10 · leverage 3/10 · effort M · confidence high

**Depends on:** R2-12 (evidence-citations module)

**Problem.** isInsecureNoSandboxEnabled is defined twice and there are three chromium arg builders. Their Playwright loaders differ in error handling, and one swallows every error with a bare catch. Each pair was written by two streams 9-16 minutes apart. The two retention citation walkers both fail open on query errors (fixed under R2-12). The worker token and context are 0o444, the socket 0o666, and the IPC dir 0o777 when the host UID is not 10001. These permissions still apply, and round-1 item 3's uid-10001/umask-0077 tier was never built. The phase0 per-origin closure is about 1850-2000 lines and decideApproval grew from 35 to 187 lines, with no growth ratchet.

**Verified evidence.**

- src/server/persona-auth.ts:810,840 vs src/server/browser-session-auth.ts:8,342,395 vs src/server/scoped-browser.ts:461-499
- git blame e93a68e 22:09 / 819dc8d 22:18
- src/server/verify-rpc.ts:465-496; src/server/worker-backend.ts:891-901; CLAUDE_AUDIT.md M-8/L-7
- src/server/phase0-recon.ts:4459-~6400; src/server/store-runs.ts:1942-2129

**Observed symptoms.** Future audits will find guards fixed in one copy and not the other. Other local users can read the per-run token.

**Systematic improvement.** Add src/server/chromium-launch.ts as the single builder and loader, rethrowing non-module-not-found errors. Use a shared gid with 0o640/0o660 modes and a 0o750 dir instead of world-readable modes, validated under a Docker uid-10001 / umask-0077 nightly tier. Add warn-first function-length and file-growth ratchets. Refactor phase0 into a Phase0HostScan class as its own later stream, gated on the --no-llm floor.

**First PR-sized steps.**

1. PR-22a (src/server/chromium-launch.ts new, persona-auth.ts, browser-session-auth.ts, scoped-browser.ts).
2. PR-22b (src/server/verify-rpc.ts 465-496, src/server/worker-backend.ts 891-901, tests/worker-mount-perms.test.ts new + nightly docker job).
3. PR-22c (scripts/check-function-growth.ts new, warn-only).

**Success metric.** One chromium builder exists, enforced by a duplicate exported-name lint. No world-readable or world-writable worker mount modes. The nightly uid-10001 tier is green.

**Risks / invariants to preserve.** Mode changes can bring back the EACCES regressions fixed in b0767c5/585450e/1a2e99c, so they must be validated in Docker. SO_PEERCRED is not available in stock Node.

**Suggested lease.** `src/server/chromium-launch.ts (new)`, `src/server/persona-auth.ts (800-850)`, `src/server/browser-session-auth.ts`, `src/server/scoped-browser.ts (460-500)`, `src/server/verify-rpc.ts (465-500)`, `src/server/worker-backend.ts (885-905)`

---

## 23. Fold cq-7 into the ledger and EffectiveConfig: persist the existing floor-preservation and agentic-lift metrics, record the floor duration policy, fix the 'exact --no-llm' docstring, then run the 2-arm A/B

`id: R2-23` · relation: carried_over_open (planned Wave-4 deferral, blocked on the ledger) · round-1 link: cq-7 · impact 2/10 · leverage 2/10 · effort S · confidence high

**Depends on:** R2-05; R2-06

**Problem.** Agentic runs cap the Phase-A floor at min(75s, 12% of wall), so the hard deadline is 195s, while --no-llm gets 240s plus a 120s margin (360s). The request cap is identical in default (non-split) mode. A third duration branch exists for staging_isolated. The engine's request-driven contract (time as an emergency brake) is contradicted on agentic runs, and the docstring claims 'exact --no-llm implementation'. deterministic_lane.metrics and certify-phase1 already compute floorConfirmed/agenticConfirmed, preservationRatio and agentic_incremental_lift, but these never reach a ledger row. The snapshot-reuse arm has no producer.

**Verified evidence.**

- src/server/run-actor.ts:815-817,924-936,1160-1244
- src/server/execution.ts:2521-2528,2577-2615,3263-3267
- src/server/exec-floor-lane.ts:999-1012; src/server/deterministic-engine.ts:76,85,5134-5136
- scripts/certify-phase1.ts:15-27,1516-1534; plans/claude_quality.md:612,667

**Observed symptoms.** The reported 'agentic increment' mixes two different floors, and its measured ratio is not persisted.

**Systematic improvement.** Record the resolved floor duration, request cap and environment override in the R2-06 effective_config event. Add preservationRatio, floorConfirmed and agenticConfirmed to buildLedgerRow (R2-05). Fix the docstring now. Run a 2-arm smoke A/B (75s vs 165s) once the ledger is populated, and flip run-actor.ts with a Contract-change trailer citing the rows. Drop the snapshot arm until a cross-run producer with scopeRevision and freshness guards exists.

**First PR-sized steps.**

1. PR-23a (src/server/execution.ts docstring 2521-2528, 2577-2580): correct the docs.
2. PR-23b (via the R2-05/R2-06 owners): ledger fields plus effective_config floor fields.
3. After the ledger has rows: a 2-arm A/B recorded as ledger rows, then a run-actor.ts flip or a documented keep.

**Success metric.** Every agentic ledger row carries preservationRatio and the floor policy. An A/B decision is recorded with row ids.

**Risks / invariants to preserve.** Raising the cap takes wall-clock from Phase B. Measure the agentic increment, not just floor recall.

**Suggested lease.** `src/server/execution.ts (docstring only)`, `src/server/run-actor.ts (815-940, flip PR only)`

---

## Verification notes

- Themes refuted outright: none.
- Dropped as duplicates of round 1 / R3: No product measurement backs any round-1 or R3 verifier merge (merged into T4 as evidence; restates the empty-ledger and regression-floor findings rather than a separate cause).

## Known gaps in this audit

Not verified or not examined in this round:
1. Actual benchmark impact. No benchmarks were run, the ledger is empty, and every recall or precision effect above is inferred from code. The R2-01 Judge change and the R2-06 wordlist default flip will both move numbers that need a recorded re-baseline.
2. Whether the roughly 20 failing quarantined kernel cases (H-13 SameSite after c9169d6, the v7-proofreceipt and t2-oracle-invariants C-7 triangle-minimum cases, specs-recall privileged delete, the floor-regress twin, movea H-5) are product regressions or stale fixtures. This needs per-case triage in R2-02.
3. End-to-end effect of the impact-prose relabel (XXE, SSRF, traversal and JWT classified as authorization) on gate verdicts. Only the classifier output was checked, with tsx.
4. Whether sast_runs, messages and lab_telemetry citing columns point into the evidence table that TTL prunes.
5. The 'main red ~50 minutes' duration and the median merge size.
6. The UI visual and geometry QA gate and the 'Systemic fixes over point patches' sections newly added to AGENTS.md. Neither was audited for enforcement.
7. Frontend correctness beyond findings and report derivation.
8. Docker worker runtime behavior: mount permission changes, the warm-pool image ID and the sdkVersion handshake. These need a Docker tier that was out of scope for this read-only audit.
9. Security-plane items fixed by the swarm-r3-* streams were not re-audited individually. Only recurrences of the same failure classes were reported: label-keyed host decisions, fixed in A but not B, and fail-open catches.
10. LOC and complexity trends beyond the cited god-file growth.
11. Scale and realism dimensions (2.5k-route, multi-host, form-only writes, WebSocket). The verdicts placed them out of scope for measurement validity, and they belong to cq-8 and detection streams.
12. Authz probes always sending JSON bodies regardless of discovered parameter location. This was verified as true but treated as a separate detection-gap stream, not ranked here.

## Expected metric discontinuity

Several items will move the reported numbers. R2-01 makes the stricter Judge raise HITL escalations in auto_review agentic runs. R2-06 flips the wordlist default OFF on the remaining paths. R2-05 and R2-06 add the ledger and config fingerprint, after which old and new numbers stop being comparable. Re-baseline once, explicitly, through the ledger, and do not chase the drop with new heuristics.

## Reviewer triage (to be filled)

| # | id | Verdict (accept / reject / defer) | Reason | Stream / owner | Lease (files) |
|---|---|---|---|---|---|
| 1 | `R2-01` |  |  |  |  |
| 2 | `R2-02` |  |  |  |  |
| 3 | `R2-03` |  |  |  |  |
| 4 | `R2-04` |  |  |  |  |
| 5 | `R2-05` |  |  |  |  |
| 6 | `R2-06` |  |  |  |  |
| 7 | `R2-07` |  |  |  |  |
| 8 | `R2-08` |  |  |  |  |
| 9 | `R2-09` |  |  |  |  |
| 10 | `R2-10` |  |  |  |  |
| 11 | `R2-11` |  |  |  |  |
| 12 | `R2-12` |  |  |  |  |
| 13 | `R2-13` |  |  |  |  |
| 14 | `R2-14` |  |  |  |  |
| 15 | `R2-15` |  |  |  |  |
| 16 | `R2-16` |  |  |  |  |
| 17 | `R2-17` |  |  |  |  |
| 18 | `R2-18` |  |  |  |  |
| 19 | `R2-19` |  |  |  |  |
| 20 | `R2-20` |  |  |  |  |
| 21 | `R2-21` |  |  |  |  |
| 22 | `R2-22` |  |  |  |  |
| 23 | `R2-23` |  |  |  |  |

### Parallel workstreams & execution log (to be filled)

_Disjoint file leases, merge order, serialization exceptions on hot files (`broker.ts`, `request-admission.ts`, `exec-recon-planner.ts`, `exec-dispatch.ts`, `floor-recipe-engine.ts`, `store.ts`/`schema.ts`), validation tier per stream, and per-stream merge SHA + gate result as they land._

