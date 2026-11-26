# Claude systemic quality audit — round 3

> Status: **READY FOR TRIAGE & EXECUTION by agy.** Author: Claude Code (Opus 5.5), 2026-11-26. Audited a pinned read-only worktree at `3a552f1` (agy's '22/22 round-2 complete' commit); plan merged on top of `3fe490d`. Prior rounds: [`claude_quality.md`](claude_quality.md), [`claude_quality_2.md`](claude_quality_2.md); security: [`CLAUDE_AUDIT_R4.md`](CLAUDE_AUDIT_R4.md).

> This round was read-only: no code was edited and no benchmarks were run. Line numbers are as of `3a552f1`, so re-`grep` a symbol before editing it.

## Headline

Round 2 is **merged, not done**. Every round-2 engine item is only partially effective. The main pattern is that a primitive lands but consumers outside the stream's file lease are never migrated.

The process around the fixes is the larger systemic problem:

- **Regressions:** 73–77% of the findings in security rounds R2–R4 are bypasses or regressions of the previous round's fixes.
- **No measurement:** product recall and precision have not been measured in 784 commits, and the ledger has 0 real rows.
- **Merge queue unused:** `merge-stream.sh` was never used (581 `ort` merges against 1 fast-forward in the `main` reflog).
- **CI red:** CI has been red on `main` since R2-03, with a tsc heap OOM and a contract-change failure.
- **Muted kernel tests:** 43 kernel test cases sit in quarantine with invented owners.

Round 3 therefore ranks **acceptance, measurement and review process** alongside the kernel and lifecycle design fixes. It also adds an *acceptance protocol*, so that "merged" stops counting as "done".

## Method

- 6 read-only auditors worked on a pinned worktree, one lens each:
  - round-2 measurement and gate efficacy
  - round-2 engine, safety and operator efficacy
  - fix-process meta (regressions across R1–R4)
  - complexity trajectory
  - run, assignment and resource lifecycle
  - proof-kernel design soundness
- They produced **44 issues**. 2 adversarial verifiers checked evidence on `3a552f1`, flagged cross-lens duplicates and critiqued the proposed fixes. Result: **31 confirmed, 13 partially confirmed, 0 refuted**, and the corrections are applied below.
- Coordinator spot-checks, all of which hold:
  - The `main` reflog shows 581 `ort` merges and 1 fast-forward.
  - `benchmarks/results/runs` holds 604 rows with fake `gitSha` (test leakage).
  - `benchmarks/baselines/floor.json` has `gitSha: null`.
  - `verify.yml` has failed on every `main` push since `eec50d9`.
  - `ledger.jsonl` has 0 rows.
- A ranking pass merged duplicates into the items below and scored them as (impact × leverage) / effort, weighted by confidence. Impact and leverage use a 1–10 scale.

## Fix-regression statistics (why process ranks high)

| Round | Crit/high findings | Regression or bypass of a prior fix | Note |
|---|---|---|---|
| R1 (CLAUDE_AUDIT.md @4f46973) vs SECURITY-REAUDIT-2026-11-22 | 47 | 3 | Counts critical and high findings only (148 at all severities). C-2 is the same PSL defect as reaudit item 4. H-3 is a new variant of item 1.2. H-4 was introduced by the 'Then #6' batch-approval fix. Of the 22 reaudit rows: 11 FIXED, 10 PARTIAL, 1 still OPEN (plans/CLAUDE_AUDIT.md:1256-1283). Already at this round, the claimed fixes were partial about half the time. |
| R2 (@98881b4) | 38 | 29 | 29 of the 38 new critical/high findings (76%) are new locations of round-1 items that the R1 fixes did not reach (CLAUDE_AUDIT_R2.md:1815-1886). On recheck, only 12 of the 47 R1 critical/high items were FIXED; 24 were PARTIAL and 11 OPEN (L62-70). |
| R3 (@09a5126) | 22 | 16 | From the Kind fields: 11 fix-bypass, 5 fix-regression (73%). R3-H-17 also bypasses a control added in that window, which makes 17/22 (77%). The fix-stream scorecard (L522-553) marks 17 of 28 R2-era merges as bypassable or regressed. |
| R4 (@09f9eeb) | 26 | 19 | 9 fix-bypass, 9 fix-regression, plus R4-H-5, which reopens the R2-H-7(c) closure (73%). 25 of 26 fall into the 10 recurring classes already seen in R1-R3 (L719-732). The R3 scorecard: 9 of 22 R3 fixes are regressed or bypassable, and 4 more are 'clean' but their class was reopened by another merge (L734-759). The same oracles have now been patched in four straight rounds: boolean differential (C-7, R3-C-4, R4-C-1), business_logic (C-6, R2-C-7, R3-C-2, R4-C-4) and v8 scope (C-4, R2-C-8, R3-C-5, R4-C-5). |
| Quality R1 to R2 (claude_quality_2.md) | 23 | 14 | 9 items are incomplete round-1 fixes and 5 are carried-over open items. None of the 13 round-1 items was fully effective: 7 partially effective, 1 ineffective, 5 never landed (L30-46). Two quality fixes caused security-round findings: cq-5 caused R4-H-13 and cq-13a caused R4-H-19. |
| Post-R4 batch 09f9eeb..3a552f1 (not yet audited) | 0 | 0 | Not an audit round. 45 merges plus 50 commits. The 15 R4 fix streams merged in 64 minutes (02:51-03:55). Four gate-repair streams followed (3f559de, 0b4d5a9, 8609517, ab54b50). One of them (8a94536) changed confirmation semantics in the kernel (see issue 4). |

## Key measurements at `3a552f1`

- **Kernel oracle × benign-archetype coverage:** 26 oracle families × 7 archetypes, of which about 8 cells are exercised. Verifier note: the exact grid is the finder's construction, but the sparse, single-oracle coverage is confirmed.
- **Complexity:** All on 3a552f1 unless noted. src/server: 181,594 lines (09a5126) -> 199,739 (78e1449) -> 221,620 (3a552f1). Round 2 diff on src/server: +27,126/-5,245 (5.2:1) over 81 files: 13 added, 68 modified, 0 deleted. Both rounds together added 17 src/server files and deleted none. All 47 non-merge src/server commits in round 2 are timestamped 2026-11-26 00:43 to 04:52, about 4 hours. Whole repo in round 2: +76,920/-8,777. tests: +35,133/-812. Files over 4K lines: 11 -> 13 -> 15 (store-runs and proof-receipt crossed in round 2). Files over 2K lines: 34 -> 38. Functions over 150 lines: 187 -> 214. Functions over 500 lines: 20 -> 26. Proof-kernel set (oracle-invariants, verify-claims, proof-receipt, exec-verify, composite-receipt/terminal, v8-oracle-*, floor-recipe-engine, verify-support, verify-prove-handlers, causal-proof-compiler, retest-health, replay-verifier): 23,420 -> 25,520 -> 31,544 lines (+23.6% in round 2). Top-level kernel functions whose names mention binding, control, reflection, echo or stamp: 28 -> 38 (11 added, 1 removed). Boolean-differential helpers: 7 -> 16 -> 17, spread over 4 files. Echo/reflection helpers: 4 -> 8, spread over 3 files. The 12 commits labelled unify/single/shared/dedup add +6,673 and delete -1,600 (4.2:1). Unwired ratchet: the baseline went 1181 -> 160 in fa2752e, which changed zero src/server lines; it is 146 now. The live check reports 148 unwired, 1056 'ownModuleOnly' and 2390 total value exports. Exact cross-file function-body clones: 16 -> 19. New test files: 48. Of these, 21 read src as text and 11 drive an entry point. Source-text regex asserts: 392 -> 425. QUARANTINE: 191 entries, and maxQuarantinedCases is also 191.

## Acceptance protocol (binding for round 3)

1. 1. DONE MEANS MEASURED ON MAIN. Three states: merged (code on main), verified (the item's success_metric check passes on main) and complete (verified, and the batch-close row is promoted). An item may be called complete only when its success_metric command or test passes on a main commit and that output is quoted in the batch-close commit. 'Merged' is never reported as 'done', and a batch summary such as '22/22 complete' is forbidden without the per-item checks.
2. 2. ONE PATH TO MAIN. Every landing, including docs, tests and ratchet-baseline edits, goes through scripts/merge-stream.sh, which fast-forwards main only on a merged-tree PASS and stamps a merge-gate note. The main-ref guard rejects anything else. Every pulse reports non-queue reflog entries, and any such entry is reverted and re-landed through the queue.
3. 3. CI GREEN OR NO MERGES. merge-stream and the pulse read the latest verify.yml run on main. While it is red, main-red.lock is set and only the stream that broke main may land its fix, through the queue. No sweep stream may 'realign' other streams' tests or kernel code to turn CI green.
4. 4. KERNEL DIFFS NEED INDEPENDENT REVIEW AND A BYPASS TEST. Any commit touching the kernel set (CONFIRMATION_KERNEL_FILE_RE, later the generated manifest) needs three things. (a) A per-commit Parity-case whose covers.files include the changed file, plus a TP and an FP case when it adds an acceptance path. (b) A Reviewed-by trailer from a different-model reviewer who read the raw diff and the oracle spec. (c) At least one reviewer-authored bypass-variant corpus case that rejects. Gate-repair commits may touch tests only.
5. 5. VERDICTS ARE NEVER SILENTLY FLIPPED OR MUTED. Changing any confirmed/verdict assertion in either direction, or editing an existing TP/FP fixture in a kernel suite, needs a Verdict-flip trailer and kernel-lane review. Kernel verdict assertions cannot be quarantined, quarantine expiries may never be extended, and kernel quarantine owners must be live STREAM-BACKLOG rows.
6. 6. A BATCH CLOSES ONLY ON A PROMOTED LEDGER ROW. Batch close requires promoted ledger rows for dev and fresh salted held-out, in both --no-llm and agentic modes, each with gitSha an ancestor of HEAD, dirty=false and an observed effective_config. regression-floor must pass against a real baseline. VERIFICATION/ROADMAP numbers are rendered from the ledger, and every claimed metric move cites its row fingerprint.
7. 7. WIRED MEANS REACHED FROM PRODUCTION. A new primitive, field, mode or check counts only if the reachability metric shows a production consumer, every new scripts/check-*.ts is registered in worker-gate.sh or CI, and every new ledger field has a non-test producer. A record-only or test-only primitive is reported as unwired debt, not as delivered.
8. 8. PROVENANCE AND ESCALATION. Every commit touching the kernel set or claiming an audit finding carries a resolvable Fixes: <ID>. When the pulse shows 2 or more prior fixes on the same (oracle family, function) across rounds, the next change needs an escalation ticket for the systemic move plus reviewer sign-off. This escalates; it never blocks an urgent critical fix.
9. 9. SAFETY INVARIANTS ARE NOT TRADEABLE. No item may loosen precision, target-safety or approval invariants to satisfy a gate, a size ratchet or a metric. Urgent security fixes in over-limit files proceed with a Split-ticket trailer, approval changes may only tighten, and lab targets and OOB subscriptions stay held on pause.

## Round-2 scorecard (on `3a552f1`)

| Item | Status | Note |
|---|---|---|
| R2-01 | **partially_effective** | The Judge core is fixed: a missing riskLevel means high, hostFloor is applied, and the admission catch fails closed. But the run-actor approval path omits mutationKind and hostFloor, its consumer drops the audit fields, the breaker exemption is still keyed on worker-declared probeClass (bounded to 3x), and an eventsAfter fallback remains. Continued in R3-03. |
| R2-02 | **partially_effective** | Per-case quarantine, the monotone cap and the hermetic env exist. But 51 kernel/critical cases have invented owners and expire together on 2026-12-10, only 2 kernel cases were retired, verdict-correct guards are muted by reason-prose asserts, and the hermetic env leaked 604 ledger rows. Continued in R3-06 and R3-02. |
| R2-03 | **ineffective** | merge-stream.sh was never used: 581 ort merges vs 1 fast-forward on main, and 37 direct merges after 2bf0258. CI has been red on every push since eec50d9 (trailer ratchet, then tsc OOM) with no observer. Gate-repair sweeps recurred. The unwired drop came mostly from the own-module filter. Continued in R3-01 and R3-09. |
| R2-04 | **partially_effective** | There is a shared retest-health module, but fixed vs inconclusive still comes from regex over oracle prose (fail-safe when unmatched). agent-script-proof defaults unknown failures to claim_not_reproduced, and legacy oracle_failed is still treated as dismissed (exec-verify.ts:3610). Continued in R3-14. |
| R2-05 | **partially_effective** | ScorecardReader, buildLedgerRow and per-run writing landed. Its own success metric is unmet: ledger.jsonl has 0 rows, floor.json is hand-authored (gitSha null, confirmedIds empty), the product scorer is opt-in and writes directly to the committed ledger, and regression-floor has no runner. Continued in R3-02. |
| R2-06 | **partially_effective** | Wordlist defaults OFF and the run.effective_config emit works. Observed-vs-declared enforcement runs only on multihop. The image identity is a mutable tag, and the source-hash label is always 'unknown'. Continued in R3-02. |
| R2-07 | **partially_effective** | Engine consumers derive from STEP_STATUS, and the reconciler prevents the stop->resume hang. Report metrics and glyphs use literal lists, and TERMINAL_PARENT_DISPOSITION restates the table by hand. model_failure.retryable contradicts R2-13. Continued in R3-18 and R3-14. |
| R2-08 | **partially_effective** | The finally-guarded restore and the fail-closed poll budget are real. The run-scoped lint only checks names and top-level Maps, and runs only through a test, so R2-13's class-field Maps leak undetected. cleanupRunState keeps direct resets. Continued in R3-09. |
| R2-09 | **ineffective** | Downgraded from the finder's partially_effective. The lease table is bounded, but the same operator action writes an unbounded run.approvedEndpointPatterns entry, which two consumers (authorizeStateChange and Judge Stage 1B) honour before any lease check. So TTL, maxUses and persona bounds do not hold for 'Approve similar', and undefined scopeRevision matches every revision. Revocation does remove the pattern. Continued in R3-03. |
| R2-10 | **partially_effective** | The veto is wired on the LLM path, but its predicate has no CWE-family check (the fallback has one), so cross-class merges inside 'injection-input' pass. Continued in R3-11. |
| R2-11 | **partially_effective** | The corpus grew to 40 cases and the Parity-case lint exists. But any existing ID satisfies it range-wide, 13337ae merged a kernel diff with no case, and all post-R2-11 additions are FP cases. The kernel regex misses the files where new oracles land. Continued in R3-04. |
| R2-12 | **partially_effective** | verifySchema, TS/SQL parity and fail-closed decoders landed. Its direct-write ratchet is wired into nothing and fails at HEAD (R2-18 added report-export.ts:397). storage-maintenance keeps a fail-open citation walker, and repair DDL duplicates migrations. Continued in R3-09. |
| R2-13 | **partially_effective** | A typed classifier and a run-level circuit exist. But the circuit re-classifies a truncated, redacted lastError, and provider_paused is not surfaced. It also added a third retry path that hard-codes wallClockExhausted:false and keeps undisposed per-run Maps, a regression bounded by the wake-loop wall-clock stop. Continued in R3-14 and R3-09. |
| R2-14 | **regressed** | The evidence requirement and monotone 'reported' work. But the store's new strictness diverges from the record_coverage tool and prompt contract, so repo-only white-box closures are rejected and workers burn turns, and the contract canary missed it. Equal-rank statuses still let a later no_issue_found overwrite a route's open gap. Continued in R3-15. |
| R2-15 | **partially_effective** | The ratchet and typed-first impact landed, but they froze 41 disagreements, including live mislabels (cross_tenant_read becomes CWE-200 misconfig-exposure, and the injection family lacks CWE-89). exec-verify keeps two drifting ladders. Continued in R3-11. |
| R2-16 | **partially_effective** | The Stage 1 module and broker wiring exist. The EffectiveTargetLoadPolicy snapshot is test-only (not in effective_config or the UI), and dispatch, phase0 and the planner keep their own parsers. Stage 2 is pending. Continued in R3-09 and R3-10. |
| R2-17 | **partially_effective** | Schema, UI, API and the resolver landed. Exchange metadata carries only the role label, about 19 kernel parseRoleLabel sites remain (including the plan-named verify-claims), and the ablation is a unit test, not the required bench cell. Continued in R3-19. |
| R2-18 | **partially_effective** | Report, Markdown, SARIF and receipt consume projectRunFindings. Project and home lists, the SQL predicate and the header count confirmed independently without triage. Consumers re-dedupe after projection. It also introduced the direct DB write that turned the R2-12 ratchet red. Continued in R3-18. |
| R2-19 | **partially_effective** | AGENTIC_SPECIALIST_* is deleted. Other @deprecated turn-budget exports remain, wall-clock constants sit outside run-safety-budgets, and token telemetry has only a test reader. Continued in R3-09. |
| R2-20 | **partially_effective** | The fixture-contamination ratchet runs in worker-gate. The novelVocab mode cannot be reached from any runner, and there is no floor-novel ledger cell. Continued in R3-09 and R3-02. |
| R2-21 | **partially_effective** | The costPerConfirmed and wastedUsd fields exist. wastedUsd has no producer, missing agentic cost is coerced to 0 (a fail-open 'free confirmation'), and there are zero real rows. Continued in R3-09 and R3-02. |
| R2-22 | **partially_effective** | Chromium launch options are deduped. WebSocket/WebRTC egress guards are still copied across persona-auth, scoped-browser and browser-session-auth with diverging semantics. Safety-primitive clone groups went 16 -> 19, and the size ratchet (PR-22c) is wired into nothing. Continued in R3-10. |
| R2-23 | **deferred** | Deferred to Wave 4 by triage, blocked on real ledger rows (R2-05/R2-06). Still blocked: ledger.jsonl has 0 rows. Unblocks when R3-02 promotes its first batch row. |

## Summary table

| # | id | Improvement | Relation | Impact | Leverage | Effort | Confidence | Depends on |
|---|---|---|---|---|---|---|---|---|
| 1 | `R3-01` | One gated path to main: merge-stream.sh as the only landing path, a main-ref guard, and CI that is green and watched | incomplete_round2_fix | 8 | 9 | S | high | — |
| 2 | `R3-02` | Make measurement a landing precondition: per-run ledger rows by default, validated row provenance, observed effective config, and a promoted row to close a batch | incomplete_round2_fix | 9 | 9 | M | high | R3-01 |
| 3 | `R3-03` | Make approval leases the only durable operator authorization, and build approval facts once for every Judge caller | incomplete_round2_fix | 8 | 7 | M | high | — |
| 4 | `R3-04` | Gate kernel changes by semantics: a complete kernel file set, per-commit case binding, and test tags instead of filename prefixes | incomplete_round2_fix | 7 | 8 | M | high | R3-01 |
| 5 | `R3-05` | An independent kernel review lane: a different-model reviewer reads the raw diff, authors a bypass case, and every verdict flip is recorded | recurring_class | 9 | 9 | M | high | R3-01; R3-04 |
| 6 | `R3-06` | Retire kernel quarantine debt honestly: verdict assertions never quarantinable, owners bound to live backlog rows, no expiry extensions, and a downward test-shape ratchet | incomplete_round2_fix | 8 | 8 | M | high | R3-05; R3-01 |
| 7 | `R3-07` | Give every assignment claim an owner: settle the source-first code audit on failure now, then one claimAssignment handle, a phase-agnostic reaper, and reported settlement failures | carried_over_open | 7 | 7 | M | high | — |
| 8 | `R3-08` | Security guards are required, branded inputs proven at the production entry: no optional guard parameters, and no test seams that double as safety switches | recurring_class | 8 | 8 | M | high | R3-09 |
| 9 | `R3-09` | Count a primitive as delivered only when production reaches it: a reachability-based unwired metric, a gate registry for every check script, and a producer for every ledger field | recurring_class | 7 | 9 | M | high | R3-01 |
| 10 | `R3-10` | Make growth and repeat patching visible and costly: one monotone size ratchet, Fixes: provenance with a cross-round repeat-patch tripwire, dual-path deletion debt, and a clone guard | recurring_class | 7 | 8 | M | high | R3-01; R3-09 |
| 11 | `R3-11` | One vuln-class identity for CWE, OWASP cell and dedupe: add the missing receipt-class families, a CWE-family veto in semantic dedupe, then a taxonomy derived from the oracle registry | incomplete_round2_fix | 6 | 8 | M | high | R3-13 (step 5 only) |
| 12 | `R3-12` | An executable statement of what must never confirm: an oracle x benign-archetype matrix in worker-gate, and FP coverage required per oracle | new | 8 | 9 | M | high | R3-13 (registry iteration; can start on the existing arrays) |
| 13 | `R3-13` | A typed OracleSpec registry as the single oracle identity and admission contract: one label-to-oracle resolver, CWE taken from the spec, and registerOracle as the only way in | recurring_class | 9 | 10 | L | high | R3-04; R3-05; R3-12; R3-02 |
| 14 | `R3-14` | Host decisions switch on typed codes stored where they are produced, and one retry governor honours the run's budgets | recurring_class | 6 | 7 | M | high | R3-09 |
| 15 | `R3-15` | Make 'No issue found' truthful: one record_coverage contract shared by tool schema, store and prompt, and per-route rows so an open gap cannot be overwritten | round2_regression | 6 | 6 | S | high | — |
| 16 | `R3-16` | Evidence custody by type: host-observed vs worker-selected provenance, a mandatory registry with no unsanitized fallback, and a per-run nonce ledger bound to run, oracle and exchange | recurring_class | 8 | 8 | L | high | R3-13; R3-05; R3-02 |
| 17 | `R3-17` | Make anti-reflection, control legitimacy, publicness and boolean-pair binding single kernel stages owned by concept, not per-file guards | recurring_class | 8 | 8 | L | high | R3-12; R3-13; R3-05 |
| 18 | `R3-18` | One derived RunActivity and one findings/step projection that every surface renders, with exhaustive switches so new statuses reach every consumer | carried_over_open | 7 | 7 | M | high | — |
| 19 | `R3-19` | Carry typed persona tenant and privilege in host-signed exchange metadata, and route every kernel tenant/role read through the resolver | incomplete_round2_fix | 7 | 7 | M | high | R3-02; R3-05 |
| 20 | `R3-20` | An authoritative persisted lifecycle: decide stopped/failed semantics, transition tables with co-transitions, a startup recovery contract that hands lab containers to the reaper, pause-aware resources, and an always-on liveness check | recurring_class | 7 | 7 | L | medium | R3-07; R3-18 |

## Ranking rationale

Items are ranked by (impact x leverage) / effort (S=1, M=2, L=3), weighted by confidence, with two adjustments. (1) Process and measurement fixes get a boost. The headline is that 73-77% of security-round critical/high findings in R2-R4 are regressions or bypasses of prior fixes, and that round 2 was declared '22/22 complete' while product metrics went unmeasured for 784 commits, the merge queue was never used (581 ort merges vs 1 fast-forward), CI stayed red, and 604 fake-SHA rows sat ready to be promoted. Without a single gated path to main (R3-01) and measurement as a landing precondition (R3-02), no later item can be verified, so these two lead and everything else depends on them. (2) Small fixes to precision, target-safety and approval invariants rank above their raw score because those invariants are non-negotiable and the fixes are cheap. The approval pattern bypass (R3-03) is third and the code-audit claim hotfix (R3-07) is seventh. Next come the kernel-change controls that attack the regression mechanism directly. R3-04 is a cheap S first step (extend CONFIRMATION_KERNEL_FILE_RE, bind Parity-case per commit). R3-05 adds an independent different-model review lane with reviewer-authored bypass cases. R3-06 un-mutes the kernel quarantine before its 2026-12-10 expiry cliff. R3-08 to R3-10 are cross-cutting process ratchets: required security inputs, reachability-based wiring, and size/repeat-patch/deletion-debt controls. R3-11 to R3-17 are precision architecture. R3-11 and R3-12 come first because their S steps (cross_tenant_read CWE families, a dedupe CWE-family veto, archetype generators) are cheap and precision-positive, and the matrix is the safety net that the L-effort registry, custody and concept-stage refactors (R3-13, R3-16, R3-17) need before they delete anything. Those three carry the highest long-run leverage but also the highest precision risk, so they are gated on R3-05, R3-12 and R3-02. Operator truthfulness and lifecycle items (R3-14, R3-15, R3-18 to R3-20) rank last. They are real and partly operator-visible, but the verifier refuted the headline lifecycle hang, and each is M/L effort with moderate leverage. Their cheap first steps (pass the wall-clock flag, register the Maps under R3-09, the coverage contract canary, isRunActive parked-approval handling, the stopped/failed decision) can still run in parallel early because their leases are disjoint. Duplicates were merged as the verifiers suggested: three check-unwired blindness issues into R3-09; the kernel regex, any-ID trailer and admission issues into R3-04 (gate) plus R3-13 (OracleSpec admission contract); the measurement and process quarantine issues into R3-06; the unused merge queue plus red CI into R3-01, with no-diff-review plus fixer-authored fixtures as R3-05; run-activity plus operator status predicates into R3-18; the guard-on-guard kernel and opt-in kernel stages into R3-17; and provenance plus nonce binding into R3-16. Every verifier correction was applied: 37 merges, not 36; 41 taxonomy entries; the refuted stop->resume hang; the latent composite fallback; the conservative hydrate merges; R4-H-3 is fixed at HEAD but its class is open; auth_bypass already has a publicness-equivalent control; the weak LOC-cap causation was dropped. Each verifier fix critique appears as an item risk.

---

## 1. One gated path to main: merge-stream.sh as the only landing path, a main-ref guard, and CI that is green and watched

`id: R3-01` · relation: incomplete_round2_fix · related: R2-03, R2-02, cq-3, R3-04, R3-05, R3-09 · impact 8/10 · leverage 9/10 · effort S · confidence high

**Depends on:** —

**Merged from:** The merge queue was never used: all 36 merges after R2-03 landed with a direct `git merge` in the main checkout, followed by cross-stream 'fix(worker-gate)' sweeps; The CI fast tier has never passed on main since R2-03: CI typecheck dies of heap OOM, and no one watches CI

**Problem.** R2-03 built merge-stream.sh and put the fast tier in CI, but nothing makes the queue the only path to main. The main reflog shows 581 ort merges and 1 fast-forward. After the R2-03 merge (2bf0258) all 37 merges were direct ort merges, plus 3 direct commits, and one of those commits edits a ratchet baseline. verify.yml has failed on every main push since eec50d9: first on contract-change trailers, then on a tsc heap OOM at about 2 GB. No script reads CI. Breakage that reached main was repaired by cross-stream 'fix(worker-gate)' sweeps, which changed kernel behaviour inside gate-repair commits.

**Verified evidence.**

- git reflog show main — 581 'Merge made by the ort strategy' entries and 1 fast-forward (coordinator-verified). After 2bf0258: 37 ort merges and 3 direct commits (283b98b edits a ratchet baseline). The finder's '36' is corrected to 37.
- scripts/merge-stream.sh:305-318 — Lands main only via `merge --ff-only $MERGED_SHA` in the main worktree, so any use would leave fast-forward reflog entries. AGENTS.md:29,33,56 make it mandatory.
- gh run list --workflow verify.yml — Runs for 3a552f1, 8877d5b and 984b808 all failed. The last success was eec50d9, before R2-03. Pushes are batched (3 pushes, about 2.5h red).
- gh run view 45824078785 / 45822283001; package.json scripts.check — 'Run npm run check' fails with a JS heap OOM near 2,040 MB. check is plain `tsc --noEmit` with no heap setting, and src/server is about 221K lines.
- gh run view 45801056457; .github/workflows/verify.yml:25-32 — 'Fast static ratchets' failed: contract-change FAIL with 4 contract edits missing per-ID trailers. The local merges landed anyway.
- grep 'gh run|gh pr checks' scripts AGENTS.md — 0 hits. Neither the merge loop nor the pulse observes CI.
- 8609517/8a94536, 3f559de/b473328, ab54b50/5357e88 — Gate-repair sweeps changed 5 production behaviours in 4 kernel/verify files and realigned 12 test files, including the kernel suite t2-oracle-invariants (401->403). Some realigns were legitimate updates for intended tightenings.

**Observed symptoms.** Main goes red between merges with no one noticing. Several fix-wg sweeps per batch re-baseline other streams' expectations. The local gate says 'tsc 0 err' while CI cannot typecheck. Gates that exist (contract-change, parity) never ran on the merged tree.

**Systematic improvement.** Make the queue the only way to land. merge-stream.sh stamps MERGED_SHA with a git note recording the gate digest and merged-tree SHA. A reference-transaction hook refuses main updates without that note; an override is possible but writes an audit line. Server-side branch protection requires verify.yml once it is green. Treat CI as a gate input: set an explicit tsc heap plus a monotone tsc memory/time budget, and have merge-stream and the pulse refuse to merge while the latest main CI run is red (they set main-red.lock automatically). The pulse prints ACTION for every non-queue reflog entry.

**First PR-sized steps.**

1. (S) .github/workflows/verify.yml: set NODE_OPTIONS=--max-old-space-size=6144 for `npm run check` and publish the --extendedDiagnostics memory figure. Land the 4 missing contract-change trailers as a reviewed baseline-advance through merge-stream, not a bulk trailer edit.
2. (S) scripts/merge-stream.sh: write the git note `merge-gate: PASS <gate-digest> <merged-tree-sha>` before the ff. Query `gh run list --branch main --limit 1` and set main-red.lock on failure.
3. (S) New scripts/install-main-guard.sh plus .githooks/reference-transaction: refuse refs/heads/main updates without the note. KOVO_MAIN_GUARD_OVERRIDE=1 appends an audit event.
4. (S) scripts/parallel-pulse.sh: print 'ACTION NON-QUEUE MERGE' for each main reflog entry since the last pulse that is not a noted fast-forward, and 'CI RED' when the latest verify.yml run failed.
5. (M) New scripts/check-tsc-budget.ts: monotone peak-RSS and wall-time ratchet for tsc. Evaluate tsconfig project references (server/client/scripts) if the budget keeps climbing.

**Success metric (must be mechanically verified on `main` before marking done).** Mechanically checked by parallel-pulse over the batch range: 0 main reflog entries since guard install that are not fast-forwards carrying a merge-gate note. `gh run list --workflow verify.yml --branch main --limit 10`: all success. check-tsc-budget passes in CI.

**Risks / invariants to preserve.** ['A local hook can be bypassed. It makes bypass explicit, not impossible, so pair it with server-side branch protection as soon as CI is green.', 'The heap bump is a stopgap. Without the tsc budget ratchet the OOM comes back as src/server grows.', "merge-stream's merged-tree gate must stay under 60s or the swarm will route around it again.", 'Do not clear the red trailer ratchet by bulk-adding trailers. Review the 4 untrailered contract edits under R3-05.', 'Gate-repair sweeps must not fix a red main by editing kernel suites or kernel code (R3-05, R3-06).']

**Suggested lease.** `scripts/merge-stream.sh (owner; HOT, R3-05 hands its review hook to this owner afterwards)`, `.github/workflows/verify.yml`, `scripts/install-main-guard.sh (new)`, `.githooks/reference-transaction (new)`, `scripts/parallel-pulse.sh (HOT, R3-10 adds the touch counter after this merges)`, `scripts/check-tsc-budget.ts (new)`, `AGENTS.md merge section only (HOT, shared with R3-05/R3-10 by section)`

---

## 2. Make measurement a landing precondition: per-run ledger rows by default, validated row provenance, observed effective config, and a promoted row to close a batch

`id: R3-02` · relation: incomplete_round2_fix · related: R2-05, R2-06, R2-20, R2-21, R2-23, cq-2, cq-7, R3-01, R3-09 · impact 9/10 · leverage 9/10 · effort M · confidence high

**Depends on:** R3-01

**Merged from:** Product recall/precision has not been measured in 784 commits; the ledger has no real rows and nothing requires a measurement before 'complete' is declared; Test runs leak 604 fabricated, certifying VALID rows into the real per-run ledger dir, and promotion would ingest them; Effective config and worker image identity are still declared, not observed, on the product scorers

**Problem.** Product recall and precision have not been measured in 784 commits (including merges) since Queue #14 @4010d05, and the only salted held-out number uses a burned seed. ledger.jsonl is 0 bytes. floor.json was written by hand (gitSha null, confirmedIds empty). The product scorer writes rows only with an opt-in --ledger flag, straight to the committed ledger, and nothing runs regression-floor. Meanwhile tests leaked 604 fixture rows with fake SHAs into the main checkout's per-run dir, and promoteLedgerRows would ingest them. Effective config is cross-checked only on multihop. Round 2 was declared '22/22 complete' while R2-05's own success metric was unmet.

**Verified evidence.**

- benchmarks/results/ledger.jsonl @3a552f1; git log --format=%B 78e1449..3a552f1 — Ledger is 0 bytes (coordinator-verified). 0 Ledger-row/Measured trailers. 3a552f1's subject claims 22/22 complete.
- scripts/benchmark-realistic.ts:578-582,3799-3841; scripts/benchmark-multihop.ts:706-708,4127 — appendLedgerRow runs only inside `if (args.ledgerPath)` and defaults to the committed ledger. Neither script calls appendPerRunLedgerRow.
- VERIFICATION-v5.md:66,135; benchmarks/realistic-bench/BURNED_SEEDS — Newest product numbers are Queue #14 @4010d05 (36/59 dev, 29/58 held-out). 784 commits since, merges included. Held-out seed 1000042 is burned and EXPOSED_SEEDS.json is absent.
- benchmarks/baselines/floor.json (4f0ee88); scripts/regression-floor.sh:184-192 — gitSha null and confirmedIds [] for both suites (worktree-verified), so the lost-TP check is vacuous. held-out-saas is 20/20, but the latest ROADMAP entry (ROADMAP:1038, c3da71f) records 19/20 with hos-07 open. No runner calls regression-floor.sh.
- /home/omarchy/guardian/benchmarks/results/runs/*.jsonl; tests/v8-q34-certify-v8.test.ts:703; tests/v8-certify.test.ts:986 — 604 rows (coordinator-verified) with gitSha abc123def4… (488) or deadbeef12… (116). All VALID, 360 certifying, 241 certifying and dirty. They are gitignored local files, not committed. Tests call main() without a runs dir.
- scripts/bench-ledger.ts:30,760-772,856-905; scripts/runtime-profile.ts:76-82 — The per-run dir is cwd-relative. promoteLedgerRows checks status, certifying and fingerprint only: no gitSha existence or ancestry check, no dirty check. The hermetic profile isolates data, tmp and xdg dirs only.
- scripts/bench-ledger.ts:305-332; scripts/benchmark-agentic-matrix.ts:1095-1102; worker/Dockerfile:137-140 — The observed-vs-declared check runs only `if (observed)`, and only multihop passes it. The agentic matrix hardcodes wordlistOn:false. KOVO_WORKER_SOURCE_HASH defaults to 'unknown' and no build path sets it.

**Observed symptoms.** Nobody can say whether the R2+R4 batch (about 27K inserted src/server lines) raised or lowered recall or precision on dev or held-out. Status docs show numbers from 784 commits ago on a burned seed. A routine promote would publish fixture metrics as product evidence. Deferred items that need rows (R2-23, the R2-20 novel cell, R2-21 cost) can never start.

**Systematic improvement.** Measurement becomes part of landing, not an optional tool. Every Execution scorer writes per-run rows by default through buildLedgerRow. Rows are validated at write and at promote: gitSha must resolve and be an ancestor of HEAD, and certifying rows cannot be dirty. Under the test profile, rows land in a tmp ledger root. Execution-backed rows must carry the observed run.effective_config and the resolved image identity. One batch-boundary command runs dev and fresh salted held-out, --no-llm and agentic, plus regression-floor against a real baseline. It promotes certifying rows and renders the VERIFICATION/ROADMAP tables from the ledger. A batch is closed only by a promoted row.

**First PR-sized steps.**

1. (S) scripts/bench-ledger.ts: validateLedgerRow/promoteLedgerRows require `git cat-file -e <gitSha>`, ancestry of HEAD and a non-null gitSha, and reject certifying&&dirty. Add a test that a fake-SHA row is refused. The operator purges the main checkout's benchmarks/results/runs.
2. (S) scripts/runtime-profile.ts: set KOVO_LEDGER_ROOT to the per-file tmp dir, and have bench-ledger resolve its default dir from it. scripts/run-fast-tests.sh: snapshot `git status --porcelain --ignored benchmarks/results` before and after, and fail on drift.
3. (S) scripts/regression-floor.sh: refuse a baseline with gitSha null or empty confirmedIds. Regenerate floor.json with --write-baseline from a real run.
4. (S) package.json worker:build plus new scripts/worker-source-hash.sh: pass --build-arg KOVO_WORKER_SOURCE_HASH (git tree hash of worker/). Certification refuses 'unknown'.
5. (M) scripts/benchmark-realistic.ts, scripts/benchmark-multihop.ts, scripts/benchmark-agentic-matrix.ts: always appendPerRunLedgerRow through buildLedgerRow; --ledger only promotes. For Execution-backed scorers only, buildLedgerRow (scripts/score-primitives.ts) requires the observed run.effective_config and marks the row INVALID without it.
6. (M) New scripts/batch-boundary.sh: dev and fresh salted held-out (drawUnburnedHeldoutSeeds within a seed budget), --no-llm and agentic legs, regression-floor, `promoteLedgerRows --require-certifying`, then render-verification-tables. This unblocks the R2-23 A/B.

**Success metric (must be mechanically verified on `main` before marking done).** Checked on main at batch close: ledger.jsonl contains promoted rows for dev and fresh held-out in both --no-llm and agentic modes, each with gitSha an ancestor of HEAD, dirty=false and observed effectiveConfig. floor.json has a non-null gitSha and non-empty confirmedIds. `bash scripts/regression-floor.sh` passes. The fake-SHA rejection test and the run-fast-tests drift check are green in worker-gate. The VERIFICATION tables match the ledger render (diff check).

**Risks / invariants to preserve.** ['Per the verifier, gate on batch close and claim-complete, not on every kernel merge. Agentic legs cost money and wall time.', 'Each fresh salted held-out draw burns seeds. Define a seed budget and rotation policy before automating it. Never print or commit the held-out salt.', 'Expect metric discontinuities from wordlist OFF and the R4 precision tightenings. Record them in the ledger; never tune a gate to restore an old number.', 'Require observation only for Execution-backed scorers. benchmark-realistic-matrix.ts drives the deterministic harness and emits no run.effective_config.', 'Promote nothing from the leaked runs dir.', 'Cost 0 is legitimate for --no-llm rows. Only missing agentic telemetry becomes null (shared with R3-09).']

**Suggested lease.** `Stream A (ledger integrity): scripts/bench-ledger.ts, scripts/runtime-profile.ts, scripts/regression-floor.sh, benchmarks/baselines/floor.json, scripts/run-fast-tests.sh drift block only (HOT, shared with R3-06; serialize or split by section)`, `Stream B (scorer defaults): scripts/benchmark-realistic.ts, scripts/benchmark-multihop.ts, scripts/benchmark-agentic-matrix.ts, scripts/score-primitives.ts buildLedgerRow (HOT, R3-09 owns the cost section), scripts/batch-boundary.sh (new), package.json worker:build, scripts/worker-source-hash.sh (new)`

---

## 3. Make approval leases the only durable operator authorization, and build approval facts once for every Judge caller

`id: R3-03` · relation: incomplete_round2_fix · related: R2-09, R2-01, R4-H-1, R3-18 · impact 8/10 · leverage 7/10 · effort M · confidence high

**Depends on:** —

**Merged from:** Operator 'approve similar/prefix' writes a bounded lease AND an unbounded run-level pattern; the unbounded pattern is checked first, so R2-09's bounds are bypassed. Approval inputs are also assembled differently per call site

**Problem.** The operator 'Approve similar/prefix' action writes a bounded lease and also an unbounded run.approvedEndpointPatterns entry that has no TTL, maxUses or persona. Two consumers match the pattern before any lease check: authorizeStateChange and evaluateTier3Approval Stage 1B. So an expired or used-up lease keeps authorizing, for any persona, and a pattern with undefined scopeRevision counts as current under every scope revision. Separately, the run-actor approval path calls the Judge without mutationKind, isStructuralMutation or hostFloor, and persists only riskLevel, reason and decidedBy.

**Verified evidence.**

- src/server/store-runs.ts:2380-2398, 2452-2464 — The pattern is stored with no TTL, maxUses or persona. The same action also grants a lease (default TTL 30 min, src/domain.ts:40), which creates two authorization records.
- src/server/approval-judge.ts:525-567 — authorizeStateChange returns via 'operator_pattern' before the one-shot ledger consume. There is no expiry, use or persona check.
- src/server/approval-judge.ts:1150-1213 — Stage 1B is a second unbounded pattern consumer on the worker path. evaluateLeaseEligibility checks risk eligibility only (worktree-verified). The finder missed this consumer.
- src/server/execution.ts:1399-1412; src/server/run-actor.ts:1808,2069; src/server/store-runs.ts:1191 — `p.scopeRevision === undefined ||` treats legacy patterns as current under every revision.
- src/server/run-actor.ts:2068-2112; src/server/request-admission.ts:1712-1765 — The worker path omits isStructuralMutation, mutationKind and hostFloor, and hard-codes a deny's decidedBy to 'auto-review:judge'. Only admission computes classifyRequestMutation and the host floor. originalJudgeDecision and failSafe have no consumer.
- src/server/store-runs.ts:3932-3942 (correction) — Revoking a lease does remove the matching pattern, so the gap is expiry, maxUses and persona. JSON-RPC is still floored from the body. Only mutationKind-dependent classes (GraphQL mutation, structural) drop to a low floor.

**Observed symptoms.** A route or prefix approval keeps authorizing state-changing probes after its lease expires or runs out of uses, and for any persona. An approval from an earlier scope revision authorizes under a new scope. Audit rows cannot show that a Judge verdict was normalized or failed safe.

**Systematic improvement.** approval_leases becomes the single authority. approvedEndpointPatterns becomes a projection of live leases, and both consumers go through leaseAuthorizes (persona, expiry, uses). An undefined scopeRevision is treated as stale. Admission builds one ApprovalRequestFacts (mutation class, host floor, override, compressed body) and passes it to every evaluateTier3Approval and authorizeStateChange caller. The full Judge audit is persisted. Operators get an 'extend lease' action so run-long approvals stay ergonomic.

**First PR-sized steps.**

1. (S) src/server/approval-judge.ts: authorizeStateChange and Stage 1B require leaseAuthorizes for every pattern match. New tests/approval-lease-authority.test.ts: an expired lease, an exhausted lease or a foreign persona with a surviving pattern each yields approved:false on both consumers.
2. (S) Treat an undefined scopeRevision as stale at execution.ts:1400, run-actor.ts:1808/2069 and store-runs.ts:1191.
3. (S) src/server/run-actor.ts:2068-2112: thread classifyRequestMutation and computeHostApprovalRiskFloor into evaluateTier3Approval. Persist originalJudgeDecision, originalRiskLevel, hostFloor and failSafeReason, and stop hard-coding decidedBy.
4. (S) Static guard test: only the lease module reads approvedEndpointPatterns.
5. (M) Add an operator 'extend lease' command and UI. header.tsx renders live leases, bulk-approve (store-runs.ts:2405-2437) matches on leases, and approvedEndpointPatterns is derived from leases.

**Success metric (must be mechanically verified on `main` before marking done).** tests/approval-lease-authority.test.ts is green in worker-gate (expired, exhausted, foreign-persona and stale-revision cases are each refused by both consumers). The static guard reports 0 readers of approvedEndpointPatterns outside the lease module. A persisted auto-approval row test asserts hostFloor and originalJudgeDecision are present.

**Risks / invariants to preserve.** ['Verifier critique: do not delete run-level approval patterns until an operator lease-extend affordance exists. Leases default to 30 min with capped uses, so long runs would produce storms of re-approval cards. header.tsx:108/563 and bulk-approve depend on patterns.', 'Treating stale revisions as unapproved is fail-closed: legacy runs get approval cards, never unsafe approvals.', 'Threading ApprovalRequestFacts only tightens the gate. No step may broaden an approval.']

**Suggested lease.** `src/server/approval-judge.ts (500-570, 1140-1220)`, `src/server/run-actor.ts (1800-1810, 2060-2125) HOT`, `src/server/execution.ts (1395-1415) HOT`, `src/server/store-runs.ts (1185-1195, 2370-2470, 3930-3945) HOT`, `src/components/run/header.tsx approved-pattern section (HOT with R3-18; split by section; UI QA gate applies)`, `tests/approval-lease-authority.test.ts (new)`

---

## 4. Gate kernel changes by semantics: a complete kernel file set, per-commit case binding, and test tags instead of filename prefixes

`id: R3-04` · relation: incomplete_round2_fix · related: R2-11, R2-03, cq-3, cq-4, R4-C-6, R4-H-5, R3-05, R3-13 · impact 7/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R3-01

**Merged from:** No admission gate for new oracles: registration is a plain array, and the kernel-change lint misses the files where new oracles land; Gate scope is filename and round-prefix allowlists that go stale as kernel code moves. LOC caps push logic into ungated files, and the Parity-case trailer accepts any existing ID; The parity-corpus gate is satisfied by citing any existing case ID, so acceptance-expanding kernel changes land with no TP/FP case of their own

**Problem.** The only kernel gate fires for a 10-file regex, CONFIRMATION_KERNEL_FILE_RE. It omits terminal-oracle-registry, verify-prove-handlers, verify-rpc, agent-script-proof, host-fact-log, causal-proof-compiler and composite-autodag, which is where signed_url_mint (R4-C-6) and the auto-DAG (R4-H-5) landed. A Parity-case trailer naming any existing ID satisfies the whole range. All 6 corpus additions after R2-11 are FP cases, and acceptance-expanding diffs cite unrelated cases. 13 of 14 R4 regression suites match neither contract-test regex, so their assertions can be edited without a trailer.

**Verified evidence.**

- scripts/check-contract-change.ts:95-98 — Worktree-verified: CONFIRMATION_KERNEL_FILE_RE lists replay-verifier, verify-claims, proof-receipt, floor-recipe*, composite-receipt/terminal, oracle-invariants, exec-verify, v8-oracle-*, verify-support. EXTENDED_CONTRACT_TEST_RE is r2-|r3-|security.
- scripts/check-contract-change.ts:477-509 — validParityCaseIds is `knownIds.has(id)`, evaluated range-wide with no file-to-case or class mapping.
- fafeb3c; 8609517/8a94536 — Both cite only r4-h5-h6-rbac-fp for unrelated kernel changes. 8a94536 adds a roleDifferential acceptance path (host-readback-gated, per the verifier) and an MFA classification from title prose.
- 13337ae — An exec-verify.ts kernel diff merged 1m45s after the R2-11 merge, with no corpus change and no trailer.
- regex check over tests/r4-*.test.ts — 13 of 14 match neither EXTENDED_CONTRACT_TEST_RE nor KERNEL_TEST_RE. Only r4-oracle-invariants is protected.
- git log --diff-filter=A 78e1449..3a552f1 -- tests/parity/corpus — The 6 post-R2-11 additions are all FP. The corpus holds 15 TP, 21 FP and 4 retest cases.
- src/server/verify-prove-handlers.ts:1635; src/server/terminal-oracle-registry.ts:53-73 — handleProveSignedUrlMint and oracle registration sit outside the gated set.

**Observed symptoms.** Gates report PASS on exactly the diffs that later produce critical findings. The Parity-case trailer has become boilerplate. Correction: the finder's claim that LOC caps push kernel code into ungated files is weak (3a8d850 was a feature, and 608b92f did not move kernel code), so that claim is dropped.

**Systematic improvement.** Derive gate scope from semantics. The kernel set becomes a generated call-graph manifest (every function reachable from verifyReceipt, evaluateClaims, V8 dispatch or assess* that can return a confirmed verdict), with a staleness test. Parity-case is scoped per commit, and the cited case must declare covers.files including a changed kernel file. A declared loosening must add both a TP and an FP case. Tests are protected by `// @kernel` and `// @fixes <ID>` tags rather than filename prefixes.

**First PR-sized steps.**

1. (S) scripts/check-contract-change.ts: extend CONFIRMATION_KERNEL_FILE_RE with terminal-oracle-registry, verify-prove-handlers, verify-rpc, agent-script-proof, host-fact-log, causal-proof-compiler and composite-autodag. Add a staleness test that fails when a src/server file exporting assess*/verify*Receipt/evaluate*Oracle is not matched.
2. (S) tests/parity/corpus/*.json: add `covers: {files[], classes[]}` and backfill it on the 40 cases. evaluateParityGate requires, per commit, a cited or added case whose covers.files intersects that commit's changed kernel files.
3. (S) New tests/check-contract-change-history.test.ts: replaying the gate on 13337ae, fafeb3c and 8a94536 must fail.
4. (M) Replace EXTENDED_CONTRACT_TEST_RE with a tag scan and backfill tags on the r3-*/r4-* suites (scripts/test-tiers.ts tag reader).
5. (M) scripts/gen-kernel-manifest.ts: ts.Program call-graph walk, checked in, with a staleness test. check-contract-change consumes the manifest instead of the regex.
6. (M) A 'Kernel-change: loosening' trailer requires one TP and one FP case covering the file, plus R3-05 review.

**Success metric (must be mechanically verified on `main` before marking done).** Unit test over isConfirmationKernelFile: the 7 named files are gated, and the staleness test is green. The history-replay test flags 13337ae, fafeb3c and 8a94536. 14/14 r4 suites carry @kernel tags and are protected. Every kernel commit on main after rollout has a per-commit covering Parity-case (check-contract-change over the batch range: 0 violations).

**Risks / invariants to preserve.** ['A gate only works if it runs on the merged tree. With CI red and merge-stream unused it is moot, so land R3-01 first or run it in worker-gate.sh.', 'Classifying acceptance-expanding diffs automatically is hard. Start with a declared trailer plus the reviewer check.', 'A stricter gate must not make an urgent security fix impossible. Allow an operator-signed override trailer that is audited and reviewed post-merge.', 'check-contract-change.ts is a hot file (R3-05 and R3-10 want hooks). This item is its sole owner, and the others add separate scripts.']

**Suggested lease.** `scripts/check-contract-change.ts (SOLE OWNER, HOT)`, `tests/parity/corpus/*.json covers field (HOT with R3-05 provenance fields and R3-06 verdict cases; serialize corpus schema change first)`, `scripts/gen-kernel-manifest.ts (new)`, `scripts/test-tiers.ts tag section (HOT with R3-06; split by section)`, `tests/check-contract-change-history.test.ts (new)`

---

## 5. An independent kernel review lane: a different-model reviewer reads the raw diff, authors a bypass case, and every verdict flip is recorded

`id: R3-05` · relation: recurring_class · related: R4-C-1, R4-C-4, R4-C-5, R4-H-2, R4-C-6, R4-H-5, R3-01, R3-04, R3-06, R3-12 · impact 9/10 · leverage 9/10 · effort M · confidence high

**Depends on:** R3-01; R3-04

**Merged from:** Merge velocity with no diff review. The only 'reviewer' is the same agent family and sees summaries only, and gate-repair streams change kernel semantics; Fix-author positive fixtures encode the false positive, and fix tests replay only the auditor's named variants. There is no independent ground truth and no adversarial bypass test per kernel fix

**Problem.** 73-77% of critical/high findings in security rounds R2-R4 are regressions or bypasses of prior fixes. The fixer writes the rule, the TP fixture and the negatives. TP fixtures have encoded the FP itself (R3-C-2's accumulator, R3-C-5's cross-persona replay asserted as confirmed), and the negative tests mirror the auditor's named guard list word for word. No one reads a kernel diff before merge. The consult pastes a summary into a same-family agy pane, merges land about every 4 minutes, and gate-repair streams change confirmation semantics (8a94536) with self-written trailers as the only control.

**Verified evidence.**

- git show 0e8c6b0:tests/r3-oracle-invariants.test.ts L185,215-224 — The R3-C-2 fix's 'genuine' business_logic TP is an unbounded host-declared counter, which is exactly the R4-C-4 false positive.
- git diff 4a49d16^1 4a49d16 -- tests/r3-v8-hydrate.test.ts — The R3-C-5 fix's own test asserted that a cross-persona signed-link replay confirms. R4 flipped it to false.
- git diff 9cbe3f9^1 9cbe3f9 -- tests/r3-oracle-invariants.test.ts — The R4-C-1 fix (+1265/-210) edited existing TP fixtures (probe status 404->200, 2 pairs) to pass the narrower rule. Recall impact was not measured.
- plans/CLAUDE_AUDIT_R3.md:576; plans/CLAUDE_AUDIT_R4.md:781 vs tests/r4-oracle-invariants.test.ts:167,223,249 — Test names copy the auditor's guard columns (length-cap, charset, integer-coercion). The next round's bypass was a near variant outside that list.
- AGENTS.md:14,27,33; .opencode/skills/hillclimb-consult/scripts/consult.sh:11-37 — The reviewer gets a tmux-pasted summary with no diff, and 'ACTION MERGE NOW' fires at about 15 min.
- git log --merges 09a5126..09f9eeb — 72 merges from 20:47 to 01:09 (about 3.6 min per merge). d2e31d8 (signed_url_mint, later R4-C-6) and d3dd1e5 (autodag, later R4-H-5/H-6) merged in that window. The 15 R4 fix merges span 02:37-03:55.
- git show 8a94536 -- src/server/oracle-invariants.ts — A 'fix(worker-gate)' commit adds a roleDifferential=true path (gated on a host readback diff) and an MFA classification from title prose, citing an unrelated Parity-case.

**Observed symptoms.** Two of the three regressed R3 critical fixes shipped with their own false positive asserted as a TP. New oracles and loosening changes reach main with nobody checking binding or negative controls, and each audit finds classes reopened by merges that were not security fixes.

**Systematic improvement.** A kernel lane. A diff touching the kernel set (R3-04 manifest) cannot fast-forward without a `Reviewed-by: <reviewer-id> <case-id>` trailer. The reviewer is a different model family, receives the raw diff plus the oracle's binding spec (the summaries-only rule is amended for this lane), and must author at least one bypass-variant corpus case, which must reject. Any true<->false flip of a confirmed or verdict assertion, or any edit to an existing TP/FP fixture in a kernel suite, needs a `Verdict-flip: <case> <reason>` trailer. Parity-corpus TP cases record provenance, and the stream that changes an oracle cannot author its synthetic TP. Gate-repair streams may edit tests only. Kernel feature streams queue behind an open security batch on the same oracle family.

**First PR-sized steps.**

1. (S) AGENTS.md: kernel-lane section. 'MERGE NOW' does not apply to kernel-set branches. The lane reviewer gets the raw diff and spec (no secrets, no raw probe strings). The hourly consult lists the kernel diffs merged.
2. (S) New scripts/check-verdict-flip.ts: detect flips of confirmed/verdict assertions and edits to existing kernel-suite fixtures, and require a Verdict-flip trailer. Register it in worker-gate through R3-09.
3. (S) Lint: commits titled fix(worker-gate)/test(worker-gate) may touch only tests/ unless they carry Kernel-change and a Reviewed-by trailer.
4. (M) New scripts/check-kernel-review.ts, called by merge-stream.sh before the ff (hand-off to the R3-01 owner): requires Reviewed-by with a different-family reviewer id and a newly added corpus case authored by the reviewer that rejects.
5. (M) tests/parity/corpus provenance fields (source: benchmark|transcript|synthetic; author_stream). tests/path-parity.test.ts rejects synthetic TP cases authored by the stream that changed the oracle.

**Success metric (must be mechanically verified on `main` before marking done).** check-kernel-review.ts over the batch range reports 0 kernel-set commits on main without Reviewed-by, a reviewer-authored rejecting case, and Verdict-flip trailers for any flips. Tracked outcome: the share of regression/bypass findings in the next security round falls below 50% (from 73-77%).

**Risks / invariants to preserve.** ['A bypass-hunter per diff is costly. Limit it to diffs touching confirmation predicates.', "'Every TP from a labelled corpus' is impractical for unit tests. Apply the provenance rule to parity-corpus cases only.", 'An AST loosening detector is imprecise. Start with a declared trailer plus the reviewer.', 'Serializing kernel feature streams slows velocity. That is an accepted cost, because it targets the reopen pattern directly.', 'Do not hard-block urgent critical fixes. Allow an operator-signed expedited path whose review is completed within 24h.', 'The reviewer brief must follow AGENTS.md: no secrets and no concrete test payload strings, only the diff and spec.']

**Suggested lease.** `AGENTS.md kernel-lane section (HOT, by section with R3-01/R3-10)`, `scripts/check-kernel-review.ts (new)`, `scripts/check-verdict-flip.ts (new)`, `tests/path-parity.test.ts provenance section (HOT with R3-12/R3-13; serialize)`, `scripts/merge-stream.sh hook line (handoff after R3-01)`

---

## 6. Retire kernel quarantine debt honestly: verdict assertions never quarantinable, owners bound to live backlog rows, no expiry extensions, and a downward test-shape ratchet

`id: R3-06` · relation: incomplete_round2_fix · related: R2-02, cq-3, R3-05, R3-04 · impact 8/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R3-05; R3-01

**Merged from:** Per-case quarantine relabeled the debt without retiring it: 51 kernel and critical cases have invented owners and expire on one cliff date; Prior-round kernel negative tests are muted by quarantine because they assert reason prose rather than verdicts, and gate-repair streams rewrite fixtures to fit new behaviour; Test growth outpaces code and freezes structure: source-text greps, LOC pins and a quarantine cap equal to the count

**Problem.** R2-02 converted the quarantine to 191 per-case entries but retired almost nothing. 43 KERNEL_TEST_RE cases and 8 provider-redaction cases have synthesized 'triage-kernel-*' owners with no backlog row, and all 51 expire on 2026-12-10, 14 days from now. The sampled kernel cases split two ways. Some are verdict-correct FP guards that fail only on reason-prose asserts (C-7 negative, H-5), so sound guards are muted. Others fail on the verdict itself (expected confirmed, got false), which hides TP losses. The cap equals the count, so there is no pressure to shrink, and new guards lean on source-text greps that make refactoring expensive.

**Verified evidence.**

- tests/QUARANTINE.json — 191 entries across 84 files. 51 kernel/critical entries expire 2026-12-10. 185/191 share the reason 'Pre-existing failure on main'. maxQuarantinedCases is 191, equal to the count.
- scripts/test-tiers.ts:53; scripts/run-fast-tests.sh:353 — GENERIC_TRIAGE_OWNER_RE is the only owner check. There is no STREAM-BACKLOG lookup.
- plans/STREAM-BACKLOG.md (last commit 6ef7259) — 0 matches for triage-kernel or quarantine, and no triage branches exist.
- git log 78e1449..3a552f1 -- tests/QUARANTINE.json — 3 commits (198 -> 197 -> 191). 2 kernel cases retired in total. The provider-stream redaction suites (5+3) are still quarantined.
- node --test --test-name-pattern 'C-7|H-5: replay-verifier' on t2-oracle-invariants / t2-receipt-kernel @3a552f1 — 4/4 fail. 2 fail only on reason prose with the rejection intact. 2 fail on the verdict, i.e. muted TP losses or obsolete fixtures (verifier correction).
- 5249b9e; b473328/5357e88 — Bulk-seeded between R3 and R4, then converted per case without triage. Realign commits edited TP fixtures (v8-patch-retest, v8-q28-ablation-seal) under Contract-change trailers only.
- tests/r2-17-persona-typed.test.ts:382-409; tests/r4-host-compute.test.ts:86-115 — Source-text assert.match guards on implementation shape. 48 new test files in round 2.

**Observed symptoms.** The gate stays green while the oldest kernel soundness tests are switched off. On 2026-12-10 all 51 entries expire at once, which invites a bulk extension. Refactors break dozens of source-text tests, and that makes accretion cheaper than consolidation.

**Systematic improvement.** Split verdict assertions from explanation assertions. Kernel verdict and FP-reject assertions can never be quarantined; reason-prose assertions can, with an expiry. Each remaining kernel entry is classified as reason-only, an FP guard failing on its verdict, or a TP loss, and is resolved by a Verdict-flip record (via R3-05) or a fix, never a silent fixture flip. Owners must match ready/active STREAM-BACKLOG rows, and expiries can never increase. Source-text guards are ratcheted down in favour of AST rules and entry-point tests.

**First PR-sized steps.**

1. (S) New scripts/triage-quarantine.ts (read-only): classify each kernel/critical entry as reason-only, verdict FP-guard or verdict TP-loss, and write the class into its QUARANTINE.json entry.
2. (S) scripts/run-fast-tests.sh: fail if any entry's expires value increased versus git history (an extension needs a new entry ID plus an operator trailer). Re-stagger kernel expiries without extending any.
3. (S) scripts/run-fast-tests.sh: a kernel/critical ownerStream must match a ready/active row in plans/STREAM-BACKLOG.md. Add one triage row per kernel file (14) with leases.
4. (M) Split kernel suites so verdict asserts are separate tests, and make KERNEL verdict tests unquarantinable. Port the verdict halves of C-7, H-5, seam3 M12-M18 and q25 into tests/parity/corpus.
5. (M) Resolve each TP-verdict failure as either a Verdict-flip record (deliberate tightening, reviewed in R3-05) or a lost-TP fix. Un-quarantine the provider-redaction suites before 2026-12-10.
6. (S) New scripts/check-test-shape.ts: count readFileSync(src/**) plus assert.match in tests and ratchet it down. Lower maxQuarantinedCases each batch, in line with triage capacity.

**Success metric (must be mechanically verified on `main` before marking done).** run-fast-tests enforces and prints: 0 quarantined KERNEL_TEST_RE verdict assertions, and the total kernel entry count strictly decreases per batch. 0 kernel/critical entries have an owner without a live STREAM-BACKLOG row. 0 expiry increases in git history since rollout. The provider-redaction suites are out of quarantine before 2026-12-10. The check-test-shape count does not increase.

**Risks / invariants to preserve.** ['Per the verifier, blanket un-quarantining of verdict asserts turns the gate red on lost-TP cases. Triage first.', 'Dispatching 14 triage streams without a verdict-preservation rule invites flipping fixtures to make tests green. Require Verdict-flip records.', 'The 2026-12-10 cliff invites a bulk extension, which is explicitly forbidden.', 'Some realign edits were legitimate updates for intended tightenings. Record them; do not revert them blindly.', 'The quarantine step-down must follow triage capacity, or it forces bulk fixture edits.']

**Suggested lease.** `tests/QUARANTINE.json`, `scripts/run-fast-tests.sh quarantine block (HOT with R3-02 drift block; serialize)`, `scripts/test-tiers.ts owner section (HOT with R3-04 tags; by section)`, `plans/STREAM-BACKLOG.md rows only`, `scripts/triage-quarantine.ts (new)`, `scripts/check-test-shape.ts (new)`, `tests/parity/corpus new verdict cases (after the R3-04 schema change)`, `per-file kernel suites under 14 triage-kernel-<file> leases`

---

## 7. Give every assignment claim an owner: settle the source-first code audit on failure now, then one claimAssignment handle, a phase-agnostic reaper, and reported settlement failures

`id: R3-07` · relation: carried_over_open · related: cq-13, R4 recurring class 7, R3-20, R3-18 · impact 7/10 · leverage 7/10 · effort M · confidence high

**Depends on:** —

**Merged from:** Assignment claims and leases have no owner: 7 hand-rolled claim sites, lease expiry enforced only for verification, and in-memory job entries that leak when a flow throws before its try; Silent catch {} around lifecycle settlement hides failed transitions from the operator

**Problem.** runSourceFirstCodeAudit marks the assignment running, sets this.active and opens a session before its try block. The try has only a finally, and the caller swallows the failure in an empty catch. An openSession throw leaks the this.active entry and the abort listener. Any throw leaves the row 'running' until run-terminal settlement, which keeps isRunTrackedActive true and produces RunDeleteBusyError. Seven claim sites hand-roll 10-15 minute leases, and only verification has a lease watchdog. Empty catches around settlement, requeue, eviction and the kill-switch hide failed transitions from the operator.

**Verified evidence.**

- src/server/execution.ts:2233-2246,2260,2444-2448 — The claim, active.set and openSession all happen before the try. The try/finally has no catch that fails the worker.
- src/server/exec-recon-planner.ts:4501-4509 — An empty catch surrounds runSourceFirstCodeAudit.
- src/server/execution.ts:794-806; src/server/run-actor.ts:1556-1576 — cleanupRunState does not purge this.active. isExecutionRunTrackedActive is true for any active job of the run.
- src/server/execution.ts:3998-4005 — The H-27 lease watchdog sits inside driveVerification only.
- src/server/exec-floor-lane.ts:499; src/server/execution.ts:2236,3665,4041,4141; src/server/exec-recon-planner.ts:4135; src/server/store-runs.ts:2317 — Hard-coded 10/15-minute leases at 7 sites, none in run-safety-budgets.ts.
- src/server/execution.ts:3088-3091,901-903,981,1886-1895; src/server/run-actor.ts:2426 — Requeue, warm-pool eviction, kill-switch pause and parked-worker reconciliation failures are all swallowed.

**Observed symptoms.** After a failure, a 'Source-First Code Audit' task shows as running for the whole run. Delete and stop report the run as busy until the server restarts. Stuck rows carry no diagnostic event. Correction: a throw inside the try is cleaned from this.active by the finally, so only an openSession throw leaks the entry. The claim that this disables the backstop is unverified.

**Systematic improvement.** Land the hotfix immediately. Then add store.claimAssignment(), which returns a ClaimHandle (Disposable) bound to its RunActor task. TaskSupervisor settles it on resolve, reject or abort with a typed outcome and applies the paired step co-transition, and this.active becomes a view over live handles. A phase-agnostic reaper reclaims 'running' rows that have no live handle. Lease durations move into run-safety-budgets.ts. Settlement paths use settleOrReport(), which emits lifecycle.settlement_failed unless a known-race classifier (run deleted, already terminal) applies.

**First PR-sized steps.**

1. (S) Hotfix in src/server/execution.ts: move lines 2244-2260 inside the try, and add a catch that marks the assignment failed and emits code_audit.failed. Replace the empty catch at exec-recon-planner.ts:4507. Add a fast test that injects an openSession throw and asserts the row is settled, this.active is empty and isRunTrackedActive is false.
2. (S) src/server/run-disposers.ts: settleOrReport(runId, kind, fn) with a known-race classifier. Convert the 5 cited sites.
3. (S) New scripts/check-empty-catch.ts, its own script (check-unwired is already overloaded): a ratchet on empty catches in execution.ts, run-actor.ts and exec-*.ts that only goes down. Register it via R3-09.
4. (M) store-runs.ts: claimAssignment/ClaimHandle. Migrate the 7 claim sites, and move lease durations into run-safety-budgets.ts with truncation telemetry.
5. (M) A phase-agnostic reaper in the wake loop, keyed on 'running row with no live handle' and not on lease time alone.

**Success metric (must be mechanically verified on `main` before marking done).** The openSession-throw test is green in worker-gate. Static guard: 0 status:'running' writes outside claimAssignment, and 0 lease-duration literals outside run-safety-budgets.ts. check-empty-catch count in lifecycle files is below the 3a552f1 baseline and non-increasing. The source-first audit task in agentic smoke ends in a terminal state on an injected failure.

**Risks / invariants to preserve.** ['The reaper must not reclaim workers parked in waiting_approval or legitimately long sessions. Key it on a missing live handle.', 'Without the race classifier, settlement_failed events become noise.', 'Ship the hotfix as its own small PR so it is not held behind the handle migration.']

**Suggested lease.** `src/server/execution.ts (2225-2450, 3990-4010) HOT: R3-09 owns 1960-2036 and R3-20 owns start/wake sections`, `src/server/exec-recon-planner.ts (4490-4515)`, `src/server/run-disposers.ts`, `src/server/store-runs.ts claim API section (HOT)`, `src/server/run-safety-budgets.ts (HOT with R3-17; by section)`, `scripts/check-empty-catch.ts (new)`

---

## 8. Security guards are required, branded inputs proven at the production entry: no optional guard parameters, and no test seams that double as safety switches

`id: R3-08` · relation: recurring_class · related: R4-H-3, R4-H-4, R4-H-16, R4-H-17, R4-C-1, R4 recurring class 6, R3-09 · impact 8/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R3-09

**Merged from:** Security fixes land as optional inputs with fail-open defaults, and their tests call the internal function instead of the production caller. 'Wired' means imported, not enforced

**Problem.** Fixes add a guard as an optional parameter with a permissive default, then test it by calling the internal function directly. About 4-5 of the 9 failed R3 fixes were opt-in, a missed caller or a missed plane. At HEAD the R4-H-3 production caller now passes its guards, but the class remains. browser-session-auth guards are still optional with fail-open early returns, and allowUnscopedRefreshForTest, or an injected launchBrowser without requireScopePolicy, skips the scope fail-closed. The contract canary's cross-guard is a hard-coded list of 31 names checked in fixed character windows, so it verifies that a call appears, not that it gates the outcome.

**Verified evidence.**

- git show 819dc8d:tests/r3-browser-session.test.ts L470-503 — The R3-H-3 test calls refreshBrowserSession directly with the guard arguments. The production caller did not pass them, which became R4-H-3.
- src/server/browser-session-auth.ts:289-291,1189-1191,2406-2411 — `modifiedPaths?` is optional with `if (!modifiedPaths) return false`. The scope fail-closed is skipped via allowUnscopedRefreshForTest, an injected launchBrowser without requireScopePolicy, or allowLocalLab.
- src/server/persona-auth.ts:2613-2629 (correction) — The production caller now passes scopePolicy, modifiedPaths, verifyPathModifiedByRun and requireScopePolicy:true. R4-H-3 is fixed, but the class is open.
- plans/CLAUDE_AUDIT_R4.md:741,744,745,752 (verifier-corrected line numbers) — Scorecard rows: R3-C-4 'opt-in only', R3-H-2 incomplete, R3-H-3 unwired, R3-H-12 missed planes. R3-H-10 is needle quality, not an optional input.
- tests/sys-contract-canary.test.ts:825,946,955 — FORBIDDEN_UNWIRED_SYMBOLS has 31 names. Source slices use fixed windows (+5000/+4500), so a rename defeats them.

**Observed symptoms.** Fixes pass their own suites and the unwired ratchet while the live path is unchanged, or only one of two planes is protected.

**Systematic improvement.** Security inputs become required branded types that only host code can build (SecurityContext / ScopePolicy tokens). A lint over a registry of security option names rejects optional fields and fail-open early returns. Test seams become separate test-only constructors that production imports cannot reach. Each guard fix ships a production-entry test that drives the public entry (Execution, VerifyRpcServer, PersonaAuthManager, the provider stream) and asserts through a spy that the guard ran and changed the outcome. The canary name list is replaced by reachability from production entries, reusing the R3-09 walker.

**First PR-sized steps.**

1. (S) New scripts/check-security-optional.ts (TS AST). Registry: scopePolicy, modifiedPaths, verifyPathModifiedByRun, requireScopePolicy, host-stamp/challenge inputs and needle inputs. Flag `?:` and `if (!x) return false` early-outs, with a monotone baseline. Register it via R3-09.
2. (S) src/server/browser-session-auth.ts: make the refresher options required, and replace allowUnscopedRefreshForTest with an explicit test-only factory that src/server production modules cannot import.
3. (M) Production-entry spy tests (tests/security-entry-*.test.ts) for each R3/R4 guard fix.
4. (M) Replace the canary's FORBIDDEN_UNWIRED_SYMBOLS windows with a check that every registry symbol is reachable from a production entry via call edges.

**Success metric (must be mechanically verified on `main` before marking done).** check-security-optional runs in worker-gate, and its count goes from the baseline to 0 optional or fail-open registry fields by the end of the batch. grep finds no allowUnscopedRefreshForTest in src/server. Every registry guard has at least one production-entry test (count check in the gate).

**Risks / invariants to preserve.** ['A caller-closure check via the TS language service is heavy (M+). Drive it from the security registry only.', 'Required options will break test harnesses. Provide the test factory in the same PR.', 'No step may change a target-safety default to permissive. allowLocalLab must stay explicit and lab-only for local benchmarks.', 'tests/sys-contract-canary.test.ts is also edited by R3-15. Split by section.']

**Suggested lease.** `scripts/check-security-optional.ts (new)`, `src/server/browser-session-auth.ts (HOT with the R3-10 clone consolidation at 1857; serialize)`, `tests/sys-contract-canary.test.ts cross-guard section (HOT with R3-15)`, `tests/security-entry-*.test.ts (new)`

---

## 9. Count a primitive as delivered only when production reaches it: a reachability-based unwired metric, a gate registry for every check script, and a producer for every ledger field

`id: R3-09` · relation: recurring_class · related: R2-03, R2-08, R2-12, R2-16, R2-19, R2-20, R2-21, R4-C-6, cq-11, R3-02, R3-08 · impact 7/10 · leverage 9/10 · effort M · confidence high

**Depends on:** R3-01

**Merged from:** The R4-C-6 pattern recurs: round-2 primitives and gates shipped with only producer or test wiring, and check-unwired cannot see it; Record-only measurement primitives land unwired or with fail-open defaults (novelVocab, wastedUsd, costPerConfirmed=0), and the unwired ratchet cannot see it; The unwired-export ratchet 1181 -> 148 is mostly reclassification, not deletion, and its filter is not reachability

**Problem.** Round-2 streams shipped primitives with only producer or test wiring and still logged 'check-unwired PASS', because check-unwired counts syntactic export use. The 1181->160 baseline drop came from an own-module filter in a commit that changed no src/server lines. It hides 1056 own-module-only exports with no ratchet, and only 14 real removals followed. Three check scripts are wired into nothing, and one of them (check-direct-db-writes) fails at HEAD. Ledger fields and benchmark modes (novelVocab, wastedUsd, cost) have no producer or coerce a missing value to 0.

**Verified evidence.**

- scripts/check-unwired.ts:9-14,679; `node scripts/check-unwired.ts --json` — The scope is value exports. usedInternallyInModule = moduleHasProdConsumer && sameFileCallers.has(sym). Live counts: unwired 148, ownModuleOnly 1056, total 2390.
- git show --stat fa2752e; git log -- scripts/unwired-baseline.json — The baseline went 1181 -> 160 with 0 src/server lines changed. Later real removals: 160 -> 159 -> 156 -> 150 -> 146.
- scripts/check-direct-db-writes.ts, check-function-growth.ts, check-run-scoped-state.ts — Worktree-verified: none is referenced by worker-gate.sh, verify.yml or package.json. check-direct-db-writes fails at report-export.ts:397, which was introduced by 1c6bae4 (R2-18).
- src/server/broker.ts:3043; src/server/execution.ts:2840 — resolveEffectiveLoadPolicy's only caller is tests/polite-target.test.ts:170. getRunTokenTelemetry is test-only. The R2-16 snapshot and the R2-19 telemetry have no consumer.
- scripts/check-run-scoped-state.ts:84; src/server/exec-worker-runner.ts:507-508 — The lint scans top-level variable statements only. The class-field Maps providerRetryCountsByRun and providerRetriesTotalByRun are never disposed, while providerStallRetriesByRun uses runState.mapView.
- benchmarks/realistic-bench/run.ts:60; scripts/bench-ledger.ts:796; scripts/score-primitives.ts:251,329-332 — novelVocab is never passed by any runner. wastedUsd is always null. A missing cost becomes 0 through `?? 0`, so costPerConfirmed is 0 (legitimate only for --no-llm rows).
- src/server/exec-dispatch.ts:3833; scripts/unwired-baseline.json:78 — R2-03 PR-3e said to delete resolveProviderStallNoTokenMs. It is still exported and baselined.

**Observed symptoms.** Merge logs say 'MERGED/PASS' while the operator-visible or measured effect is absent: no effective load limits per run, no token or cost truth, and a direct-write ratchet that is red with nobody noticing. The R2 '22/22 complete' overstated what was delivered.

**Systematic improvement.** check-unwired switches to value-reference reachability from declared entrypoints (server routes, CLI, worker, Execution). It reports reachable, test-only and unreachable counts and ratchets unreachable+test-only. A gate-registry test requires every scripts/check-*.ts to run in worker-gate or CI, or to sit on a ticketed allowlist with an expiry. A producer test requires every LedgerRow field and runner option to have a non-test producer. Missing agentic cost becomes null, never 0. The run-scoped-state lint covers class-field Maps keyed by runId or assignmentId. worker-gate.sh has one owner, and every new check script registers through this item.

**First PR-sized steps.**

1. (S) src/server/exec-worker-runner.ts:507-508: register the two Maps via runState.mapView. Extend check-run-scoped-state to class-field Maps used with .set(runId|assignmentId).
2. (S) Move the report-export.ts:397 write into a store repository method, THEN wire check-direct-db-writes and check-run-scoped-state into scripts/worker-gate.sh (the order matters).
3. (S) New tests/gate-registry.test.ts: every scripts/check-*.ts is referenced by worker-gate.sh or verify.yml, or appears on a ticketed allowlist with an expiry.
4. (S) scripts/score-primitives.ts: absent agentic cost telemetry gives null, and computeCostPerConfirmed(null) gives null. --no-llm 0 stays 0.
5. (M) scripts/check-unwired.ts: reachability walk, warn-only for one batch, then ratchet unreachable+test-only. Delete resolveProviderStallNoTokenMs.
6. (M) New tests/ledger-field-producers.test.ts. Emit EffectiveTargetLoadPolicy and the token-telemetry summary into run.effective_config or the ledger row, or delete them. Add a --novel-vocab realistic-bench cell that writes a split='novel' row.

**Success metric (must be mechanically verified on `main` before marking done).** gate-registry test green with 0 ungated check scripts. check-direct-db-writes and check-run-scoped-state pass inside worker-gate, and the lint flags a class-field Map fixture. The reachability metric is baselined and non-increasing, with its count printed in the pulse. ledger-field-producers test green (0 fields without a producer).

**Risks / invariants to preserve.** ['Wiring check-direct-db-writes before fixing report-export would block every merge.', 'Detecting event kinds with no consumer is fuzzy. Make it a report before it becomes a failing gate.', 'Implement reachability once, for all three source issues and for R3-08.', 'Do not delete exports that belong to an RPC/SDK/tool contract without updating prompts and skills in the same batch (sys-contract-canary).']

**Suggested lease.** `scripts/check-unwired.ts`, `scripts/unwired-baseline.json`, `scripts/worker-gate.sh (SOLE OWNER of gate-step additions, HOT: R3-05/R3-06/R3-07/R3-08/R3-10/R3-12 hand over script names)`, `scripts/check-run-scoped-state.ts`, `src/server/exec-worker-runner.ts (500-510 only; HOT with R3-14 at 940-1170)`, `src/server/report-export.ts (390-400)`, `scripts/score-primitives.ts cost section (HOT with R3-02; serialize)`, `src/server/execution.ts effective_config emit (1960-2036; HOT)`, `tests/gate-registry.test.ts (new)`, `tests/ledger-field-producers.test.ts (new)`

---

## 10. Make growth and repeat patching visible and costly: one monotone size ratchet, Fixes: provenance with a cross-round repeat-patch tripwire, dual-path deletion debt, and a clone guard

`id: R3-10` · relation: recurring_class · related: R2-22, AGENTS.md 'Escalate repeat patches', AGENTS.md 'One authoritative path', R4 recurring classes 1-3, R3-13, R3-17 · impact 7/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R3-01; R3-09

**Merged from:** Size caps exist only for previously split files and are gamed to the last line; the growth ratchet is warn-only and unwired, so god-files grow freely; 'Unify' and 'single source' fixes add 4.2x more code than they delete; no file was retired in two rounds; Files and functions larger than one agent context produce fix-after-fix chains on the same subsystem within hours; Exact clones of safety primitives survived and grew after the R2-22 dedup stream; the duplicate lint checks exported names only; Fixes accrete as point patches on the same oracles round after round. The AGENTS.md 'escalate repeat patches' rule is per batch with no tripwire, there are no Fixes: links, and no oracle admission contract

**Problem.** The proof-kernel set grew 25,520 -> 31,544 lines (+23.6%) in round 2, and src/server grew 199,739 -> 221,620 lines in about 4 hours of commits. 'Unify/single source' commits added +6,673/-1,600, and 17 files were added and 0 deleted across both rounds. LOC caps exist only for previously split files. They are gamed to cap-1, one was quarantined, and uncapped siblings absorb the growth. check-function-growth exists but runs nowhere. AGENTS.md's 'second patch escalates' rule is scoped per batch and there are 0 Fixes: trailers, so the same oracles have been patched in four straight rounds without tripping anything. Clones of safety primitives survived R2-22.

**Verified evidence.**

- git show <rev>:src/server/oracle-invariants.ts | wc -l at 4f46973/98881b4/09a5126/09f9eeb/3a552f1 — 2988 / 3291 / 4244 / 4921 / 6303 lines. proof-receipt.ts went 1759 -> 5055.
- git show --numstat be05f71 cd42d1b 7f9fb74 f135333 1c6bae4 fe56922; git diff --name-status 09a5126..3a552f1 -- src/server — +903/-198, +837/-249, +1196/-120, +757/-276, +454/-64, +851/-144. 17 files added, 0 deleted.
- src/server/composite-receipt.ts (749) vs tests/v8-composite-receipt.test.ts:99; tests/arch-p1-verify-rpc-split.test.ts:50 — composite-receipt sits at 749 against a <=750 cap. verify-claims (2293) and verify-rpc (2283) are within 17 lines of their 2300 cap. verify-support is uncapped and grew 921 -> 2211 (verifier correction). The agent-session cap is quarantined (QUARANTINE.json:14-17).
- scripts/check-function-growth.ts:56-57 — Worktree-verified: not in worker-gate.sh, verify.yml or package.json. Its only reference is tests/r2-22-dedup-perms.test.ts.
- AGENTS.md:69; git log --format=%B 09f9eeb..3a552f1 — The rule says 'second point patch in a batch'. 0 Fixes:/Closes: trailers. CLAUDE_AUDIT_R4.md:719-732: boolean differential, business_logic and v8 scope have each been patched in four rounds.
- AST body-hash: floor-recipe-engine.ts:2991, request-admission.ts:575, scoped-browser.ts:1673; exec-recon-planner.ts:310 / worker-backend.ts:1334; browser-session-auth.ts:1857 / scoped-browser.ts:834 — Destructive-content decode wrappers appear 3 times (over a shared containsDestructivePayload core, so lower risk), and isSensitiveRepoEntry and constantTimeStringEqual are each duplicated.
- src/server/broker.ts:1991-1997; src/server/target-load-policy.ts:9,71 — A compatibility wrapper is kept only for a test, and 'Stage 1 strictly value-preserving' leaves broker bucket logic as a dual path.

**Observed symptoms.** Capped files sit at cap-1 while uncapped god-files grow, and files over 4K lines went 11 -> 13 -> 15. Each 'single source' lands next to the code it should have replaced. The same subsystem gets a second patch within hours, and the next audit finds the class reopened.

**Systematic improvement.** One monotone size ratchet in worker-gate and CI replaces the scattered LOC asserts. An over-limit file or function may grow only with a `Split-ticket:` trailer. `Fixes: <ID>` trailers become mandatory on kernel-set commits. The pulse counts prior fixes per (oracle family, function) across all history plus distinct streams per function span per batch, and escalates (ticket plus reviewer sign-off) at 2 or more. Unify/consolidate streams record their remaining dual paths as deletion-debt entries with an owner and expiry, and the pulse reports net LOC per merged stream. A clone guard with a removal-only baseline plus one safety-primitives module removes copied safety predicates.

**First PR-sized steps.**

1. (S) scripts/check-function-growth.ts: --baseline/--write-baseline (shrink-only) into scripts/size-baseline.json, with a Split-ticket trailer allowance. Register it in worker-gate (via R3-09) and verify.yml.
2. (S) New scripts/check-fix-provenance.ts: kernel-set commits and finding-claiming commits need a `Fixes: <ID>` that resolves in plans/*.md.
3. (S) New scripts/check-clones.ts: AST body-hash, at least 6 lines, cross-file, removal-only baseline. Consolidate isSensitiveRepoEntry and constantTimeStringEqual into src/server/safety-primitives.ts, keeping the stricter semantics.
4. (S) Remove the LOC asserts from the arch-*/v8-* tests and drop the arch-c1:42 quarantine entry once the ratchet owns size.
5. (M) scripts/parallel-pulse.sh: repeat-patch tripwire (Fixes: history plus per-function stream touches) that prints ESCALATE. Amend AGENTS.md rule 6 to 'across rounds'.
6. (M) A deletion-debt table in plans/STREAM-BACKLOG.md that the pulse reads. Retire broker.ts externalApexBucketKey and the broker bucket logic into target-load-policy (Stage 2).

**Success metric (must be mechanically verified on `main` before marking done).** The size ratchet runs in worker-gate and CI with 0 unticketed growth of over-limit files or functions per batch. The count of files over 4000 lines does not rise above 15 (3a552f1). check-fix-provenance over the batch range shows 100% of kernel-set commits with a resolvable Fixes:. Clone groups stay at or below baseline, with 0 safety-primitive clone groups. The pulse prints net src/server LOC per merged stream.

**Risks / invariants to preserve.** ['Do not hard-block urgent security fixes in god-files such as oracle-invariants. Over-limit growth is allowed with a Split-ticket trailer.', "A net-LOC rule keyed on 'unify' commit subjects is gameable and could pressure deletion of safety checks. Some net-positive unify commits are legitimate enforcement (be05f71 for R4-H-1). Use explicit deletion-debt entries, not a LOC rule.", 'The repeat-patch tripwire escalates. It never blocks an urgent critical fix.', 'Clone consolidation must keep the stricter semantics.']

**Suggested lease.** `Stream A (ratchets): scripts/check-function-growth.ts, scripts/size-baseline.json (new), scripts/check-fix-provenance.ts (new), scripts/check-clones.ts (new), arch-*/v8-* LOC asserts`, `Stream B (consolidation): src/server/safety-primitives.ts (new), src/server/exec-recon-planner.ts:310, src/server/worker-backend.ts:1334, src/server/browser-session-auth.ts:1857 (HOT with R3-08), src/server/scoped-browser.ts:834, src/server/broker.ts bucket section`, `Stream C (pulse/docs): scripts/parallel-pulse.sh (HOT, after R3-01), AGENTS.md rule 6 (HOT, by section), plans/STREAM-BACKLOG.md deletion-debt table`

---

## 11. One vuln-class identity for CWE, OWASP cell and dedupe: add the missing receipt-class families, a CWE-family veto in semantic dedupe, then a taxonomy derived from the oracle registry

`id: R3-11` · relation: incomplete_round2_fix · related: R2-15, R2-10, R2-14, R3-13, R3-15 · impact 6/10 · leverage 8/10 · effort M · confidence high

**Depends on:** R3-13 (step 5 only)

**Merged from:** No single vuln-class identity: R2-15 baselined 42 live cross-table disagreements, R2-14 added a new class table that disagrees on 12 classes, and R2-10's dedupe veto has no class or CWE-family check

**Problem.** R2-15 froze 41 live cross-table disagreements in a ratchet instead of unifying the tables. exec-verify's two regex ladders miss cross_tenant_read/write, url_redirect, price_tampering and workflow_bypass, which fall through to CWE-200 misconfig-exposure, and the binding step then overrides the spec CWE with that default. R2-14's coverage table puts XSS and XXE in different OWASP cells than finding binding does. R2-10's LLM dedupe veto never compares CWE family, so two distinct injection classes on the same endpoint and parameter can be merged before verification.

**Verified evidence.**

- tests/taxonomy-conformance.test.ts:65-107 — 41 baselined disagreements (not 42), 12 of them owasp-vs-exec-verify. They include cross_tenant_read -> misconfig-exposure and CWE-89 missing from the injection family.
- src/server/exec-verify.ts:286-353 — Verifier ran it: cweFamilyForReceiptClass returns CWE-200/misconfig-exposure for cross_tenant_read, cross_tenant_write, url_redirect, price_tampering and workflow_bypass.
- src/server/exec-verify.ts:463-485 — When a receipt family exists and the spec CWE is outside it, the family's default CWE and category replace it.
- src/server/coverage-category.ts:97-98,124-129 — xxe maps to injection-input and xss to cors-client-side (3a24069, R2-14).
- src/server/dedupe.ts:603-724 vs 740-750; src/server/exec-verify.ts:294-309 — The veto predicate allows a merge on a surface match with no CWE comparison, while the fallback requires sameCwe. All injection classes share category injection-input.
- src/server/proof-receipt.ts:575-583; src/server/oracle-invariants.ts:765-778 — Two more class tables, each treating cross_tenant_read as authorization.

**Observed symptoms.** Confirmed cross-tenant reads can be reported as CWE-200 misconfiguration. Coverage cells and finding categories disagree for XSS and XXE, which undermines 'No issue found'. On agentic runs, a second injection class on the same parameter can be dropped before verification.

**Systematic improvement.** Land the precision-positive S fixes now: complete the receipt-class families, add a CWE-family veto to sameFindingPredicate, and replace the CWE-200 fallthrough with a visible 'unclassified' gap. Then generate one vuln taxonomy (class -> canonical CWE, CWE family, OWASP cell, impact class, severity, remediation) jointly with the R3-13 OracleSpec registry, so it does not become a third table. Derive cweFamilyForReceiptClass, agentProofAttribution, IMPACT_CLASS_BY_VULN, the coverage map and severity from it.

**First PR-sized steps.**

1. (S) src/server/exec-verify.ts cweFamilyForReceiptClass: add cross_tenant_read/write (authorization family), url_redirect, price_tampering, workflow_bypass, and an injection family that includes CWE-89 and CWE-943. Remove those entries from the ratchet.
2. (S) src/server/dedupe.ts evaluateSameFindingPredicate: reject when both CWEs are known and their families do not intersect. Add a test with two injection classes on the same parameter.
3. (S) An unknown receipt class maps to 'unclassified', kept visible as a gap, instead of CWE-200. Add a test that enumerates every receipt class and checks none falls through to CWE-200.
4. (M) Align coverage-category's xss/xxe entries with finding binding by deriving both from one table.
5. (L) src/vuln-taxonomy.ts generated with the R3-13 registry; delete the parallel ladders.

**Success metric (must be mechanically verified on `main` before marking done).** KNOWN_TAXONOMY_DISAGREEMENTS decreases strictly per batch, and the live-mislabel entries (cross_tenant_*, the CWE-89 family, the xss/xxe cells) reach 0 this batch. The dedupe cross-family veto test is green. The receipt-class enumeration test shows 0 CWE-200 fallthroughs.

**Risks / invariants to preserve.** ["'Unclassified' must keep the finding visible, never drop it.", 'The dedupe veto may surface more near-duplicates. That is acceptable (precision over noise); measure it through the ledger.', 'CWE changes alter report output, so pin them with fixtures and expect per-class metric discontinuities.', 'Build the taxonomy with the OracleSpec registry, not beside it.', 'exec-verify.ts is in the kernel set, so the R3-05 review lane applies.']

**Suggested lease.** `src/server/exec-verify.ts (215-485, 1246-1460) HOT: R3-19 owns 1770-1895`, `src/server/dedupe.ts (590-760)`, `src/server/coverage-category.ts (90-130) HOT: R3-15 owns 300-430`, `tests/taxonomy-conformance.test.ts`, `tests/dedupe-veto.test.ts`

---

## 12. An executable statement of what must never confirm: an oracle x benign-archetype matrix in worker-gate, and FP coverage required per oracle

`id: R3-12` · relation: new · related: R2-11, fp-archetypes Tier 0, R4-C-1, R4-C-4, R4-C-6, R3-05, R3-13 · impact 8/10 · leverage 9/10 · effort M · confidence high

**Depends on:** R3-13 (registry iteration; can start on the existing arrays)

**Merged from:** No kernel-wide oracle x benign-archetype matrix: 33 one-oracle benign fixtures cover about 8 of 182 cells

**Problem.** Benign fixtures are one-off regressions, each bound to one oracle: 21 FP corpus cases plus 12 fp-archetypes, covering roughly 8 of about 182 oracle x archetype cells. Many oracles have no benign fixture at all, including timing, oob, redirect, webhook, conserved_balance, signed_url_mint and the v8 families. The R2-11 completeness rule counts TP cases and works per rule, and the v8 families are outside MANIFEST_RECEIPT_RULES. fp-archetypes call assessors directly and bypass verifyReceipt and the stamps. Every round finds a benign behaviour that some untested oracle confirms.

**Verified evidence.**

- tests/path-parity.test.ts:383-394,923-938 — Rule coverage counts any case, TP or FP. MANIFEST_RECEIPT_RULES has 10 rules and no v8 families.
- tests/parity/corpus/*.json — 40 files: 15 TP, 21 FP, 4 retest. No FP for timing, oob, redirect, webhook, conserved_balance, boolean (the coercion case routes to status_differential) or signed_url_mint.
- benchmarks/realism-suite/traps/fp-archetypes.json — 12 archetypes, each with one assessor (authorization x5, business_logic x3, mfa, bfla, mass_assignment, csrf).
- scripts/smoke-agentic.ts:474-520 — evaluateArchetype calls impact assessors directly, not the terminal registry.
- tests/parity/corpus/r4-c1-c3-c4-fp.json; tests/parity/corpus/r4-c2-h7-fp.json — Each file is named after several findings but holds one case. The accumulator (R4-C-4) and validator x boolean/status (R4-C-1) shapes are not fixtures.

**Observed symptoms.** The kernel has no executable statement of what must never confirm, so each audit discovers the next benign archetype by hand. Correction: '8 of 182 cells' depends on the finder's grid, but the structural sparsity is confirmed.

**Systematic improvement.** Add tests/kernel-archetype-matrix.test.ts to worker-gate, under 5s. Parametric synthetic HostFactLog generators build benign targets that are correct by construction: public endpoint, validator, sanitizer, accumulator, idempotent update, share link, integer coercion, then echo, cache hit, pagination and 4xx validator. Each registered oracle is driven through evaluateTerminalOracle with hand-written strongest-claim builders plus a lateral same-CWE label sweep, with arm-assignment enumeration added later. Every cell must dismiss, or carry a ticketed, expiring exemption. The completeness rule requires at least one FP case per oracle, v8 families included.

**First PR-sized steps.**

1. (S) tests/fixtures/benign-archetypes/*.ts: generators for public endpoint, validator, sanitizer and accumulator, seeded from existing FP fixture shapes and described by class, not payload strings.
2. (M) tests/kernel-archetype-matrix.test.ts: run them through evaluateTerminalOracle for all SINGLE_HOP_ORACLE_RULES and REGISTERED_V8_ORACLE_FAMILIES, record the grid baseline, and register it in worker-gate via R3-09.
3. (S) tests/path-parity.test.ts: completeness requires at least one FP case per rule and per v8 family. TP cases no longer count.
4. (M) Add the remaining archetypes and arm-assignment enumeration only, not full WorkerSelected combinatorics.
5. (S) Print the oracle x archetype grid in CI output.

**Success metric (must be mechanically verified on `main` before marking done).** The matrix test runs in worker-gate in under 5s. Grid coverage is printed and never decreases. Non-exempt cells show 0 confirms. The path-parity assertion shows every registered oracle (including v8) has at least one FP case. Every exemption carries a ticket and an expiry.

**Risks / invariants to preserve.** ['Enumerating the strongest worker claim is combinatorial and will not fit in 5s. Start with hand-written builders per oracle.', 'Any confirm found while baselining is a real FP. Fix it through the R3-05 lane; do not exempt it.', 'Generators use only synthetic host-observed exchanges and never touch live targets.']

**Suggested lease.** `tests/kernel-archetype-matrix.test.ts (new)`, `tests/fixtures/benign-archetypes/*.ts (new)`, `tests/path-parity.test.ts completeness section (HOT with R3-05/R3-13; serialize)`, `benchmarks/realism-suite/traps/fp-archetypes.json`

---

## 13. A typed OracleSpec registry as the single oracle identity and admission contract: one label-to-oracle resolver, CWE taken from the spec, and registerOracle as the only way in

`id: R3-13` · relation: recurring_class · related: R4 recurring classes 1/2, R4-C-1, R4-C-6, R2 H-12 TERMINAL_CLASS_CONTRACT, R3-04, R3-11, R3-12, R3-16, R3-17 · impact 9/10 · leverage 10/10 · effort L · confidence high

**Depends on:** R3-04; R3-05; R3-12; R3-02

**Merged from:** No oracle identity: the worker's label picks the oracle and its evidence bar, and at least four independent label classifiers disagree; Kernel size and dual entry paths: about 30k LOC across 12 files, and at least 7 confirmation entry points held together by a parity test; Fixes accrete as point patches on the same oracles round after round. The AGENTS.md 'escalate repeat patches' rule is per batch with no tripwire, there are no Fixes: links, and no oracle admission contract

**Problem.** There is no first-class oracle. The worker's vulnClass, impactClass or claim kind is regex-mapped to a rule by four maps that disagree, so the same CWE routes to different rules and evidence bars depending on the label, and the worker also names the arms. Oracles are registered as two string arrays that tests check only for set equality, so a new oracle such as signed_url_mint needs no declared inputs, controls, binding or benign fixture. Confirmation is reachable through at least 4 parity-tested entry points plus verify-claims' 15-kind DSL with its own evaluators, so every hardening has to be applied to every path.

**Verified evidence.**

- src/server/proof-receipt.ts:558-633 — receiptRuleFor and IMPACT_CLASS_BY_VULN work over a free-form vulnClass string.
- src/server/v8-oracle-hydrate.ts:1447-1468; src/server/oracle-invariants.ts:5717-5760,5797-5826 — TERMINAL_CLASS_CONTRACT, IMPACT_CLASS_LABELS/CWES and classifyBoundaryClaim are three more taxonomies.
- label-routing probe on 3a552f1 (verifier reproduced) — Injection-family labels route to boolean, status_differential and impact:injection. timing and signed_url_mint have a null terminal contract. csrf, race, mfa and path_traversal disagree across maps.
- src/server/proof-receipt.ts:4440-4456 — A structural_diff claim becomes an injection receipt, and its arms come from the control/variant IDs the claim cites.
- src/server/terminal-oracle-registry.ts:53-73; tests/host-fact-log-oracle-registry.test.ts:160-162; tests/capability-manifest.test.ts:498-499 — Two literal arrays, checked for set equality only.
- tests/path-parity.test.ts:222-240 — 4 entry points. Permutations only demote a label; none moves it laterally to a same-CWE sibling rule.
- src/server/verify-claims.ts:1260-1600 — Independent timing, oob, structural_diff and race evaluators. The file is at 2293 of its 2300 cap.

**Observed symptoms.** Each round closes the bar on one rule, and the next round finds a sibling label that routes to a weaker or unbound rule. The reported CWE follows the worker's framing, not the evidence. Correction: that a specific sibling is actually weaker for a given CWE is plausible, not demonstrated; the lateral test will show it.

**Systematic improvement.** Define OracleSpec {id, cwes, claimKinds, inputs+provenance, controls, binding kind, reflection, publicness, archetypeExemptions} and freeze a registry of the current oracles. labelToOracle() resolves every label, claim kind, CWE and composite terminal to the canonical spec for its CWE family. The reported CWE comes from spec.cwes. registerOracle(spec) is the only entry point, and an admission test requires a complete spec plus at least one TP and one FP case naming the spec id. verify-claims kinds become hypothesis syntax that compiles to (spec id, citations) and calls one kernel.evaluate. Kernel LOC and entry-point count are tracked as this item's acceptance metric.

**First PR-sized steps.**

1. (S) src/server/oracle-spec.ts: the OracleSpec type and a frozen, descriptive registry of the current oracles. No behaviour change.
2. (S) Agreement test: receiptRuleFor, resolveTerminalContract and classifyBoundaryClaim against the registry for every label they know. The current drift becomes a failing list that only shrinks.
3. (S) tests/path-parity.test.ts: a 'lateral' PermutationKind that relabels each FP case across its same-CWE sibling labels; each must still be dismissed.
4. (M) labelToOracle(): resolve to the canonical (strongest) spec per CWE family, or require all candidate specs sharing the CWE to agree. Take the reported CWE from spec.cwes.
5. (M) registerOracle(spec) becomes the only way in. tests/oracle-admission.test.ts: input provenance declared, at least 1 legitimate negative control, binding kind (nonce | persona-tenant | canary | none+ticket), reflection and publicness policy, at least 1 TP and 1 FP case naming the spec.
6. (L) Route verify-claims' timing/oob/structural_diff kinds through the registry and delete the duplicate evaluators. Delete the receiptRuleFor regexes and TERMINAL_CLASS_CONTRACT once the agreement test is green and the ledger shows no TP loss.

**Success metric (must be mechanically verified on `main` before marking done).** The agreement-test drift list reaches 0. The lateral permutation is green for every FP case. The admission test passes for 100% of registered oracles. A static guard shows exactly 1 label-to-rule table in src/server. The pulse tracks the number of confirmation entry points not routed through kernel.evaluate, and it reaches 0.

**Risks / invariants to preserve.** ['Verifier critique: labelToOracle must not confirm via the weakest candidate. Returning a candidate set and confirming through any passing spec widens the FP surface. Use the canonical/strongest spec per family, or require agreement.', 'Deleting the tables carries recall risk. Stage it behind the agreement test and a promoted ledger row (R3-02).', 'Steps 4-6 are kernel diffs and require R3-05 review and R3-12 matrix coverage.', 'Allow non-nonce binding kinds (persona/tenant evidence, canaries). A mandatory nonce for every spec is wrong.']

**Suggested lease.** `src/server/oracle-spec.ts (new)`, `src/server/terminal-oracle-registry.ts (53-73) HOT with R3-16 (143-174)`, `src/server/proof-receipt.ts (558-633, 4430-4460) HOT kernel`, `src/server/v8-oracle-hydrate.ts (1440-1470) HOT with R3-19`, `src/server/oracle-invariants.ts (5710-5830) HOT kernel`, `src/server/verify-claims.ts (645-690, 1260-1600) HOT with R3-19 (950-970)`, `tests/oracle-admission.test.ts (new)`, `tests/path-parity.test.ts permutation section (HOT; serialize)`

---

## 14. Host decisions switch on typed codes stored where they are produced, and one retry governor honours the run's budgets

`id: R3-14` · relation: recurring_class · related: R2-04, R2-13, R2-07, R2-08, R2-01, R3-09, R3-15 · impact 6/10 · leverage 7/10 · effort M · confidence high

**Depends on:** R3-09

**Merged from:** Typed outcomes are turned back into prose and re-classified by regex downstream (retest fixed/inconclusive, provider circuit, coverage evidence); Retry engines multiplied instead of unifying: R2-13 added a third bounded-retry path with its own caps, maps and wall-clock bypass, beside the cq-5 requeue and the stall retry

**Problem.** retest-health chooses between fixed-eligible and oracle_disagreement by regexes over the oracle's English reason, and agent-script-proof defaults unknown failures to claim_not_reproduced. The R2-13 provider circuit re-classifies a redacted, 300-char-truncated lastError instead of a stored typed kind, so a truncated quota or auth outage may not trip provider_paused. R2-13 also added a third retry path that hard-codes wallClockExhausted:false and keeps per-run Maps with no disposer, while STEP_STATUS.model_failure.retryable is false.

**Verified evidence.**

- src/server/retest-health.ts:489-512; src/server/agent-script-proof.ts:671-679 — Per-recipe regexes over verification.reason. The agent-script default is 'claim_not_reproduced', partly gated at :938.
- src/server/provider.ts:777-781; src/server/model-settings.ts:600 — classifyProviderFailure(profile.lastError), where lastError = redact(msg).slice(0,300).
- src/server/run-actor.ts:2483 — classifyWorkerErrorToStepStatus(assigned.outcome) is a string-to-status classifier in the reconciler.
- src/server/exec-worker-runner.ts:1116 — Worktree-verified: wallClockExhausted: false is hard-coded in the R2-13 retry decision. evaluateTransientProviderRetry (exec-dispatch.ts:1171) would honour a real value.
- src/step-status.ts:149-151; src/server/exec-recon-planner.ts:2247 — model_failure is marked retryable:false, yet R2-13 retries transient model failures. The cq-5 requeue path has its own map and its own maxDurationMs check.
- src/server/exec-recon-planner.ts:7234 (correction) — The wake-loop stop still ends the run at wall-clock, so the bypass costs extra retries near the deadline, not unbounded runtime. An unmatched retest reason is fail-safe (it lands on inconclusive).

**Observed symptoms.** Rewording an oracle message can flip a retest from 'Verified fixed' to inconclusive. A redacted or truncated outage message can miss the provider circuit and fall into the model_failure cascade. Retries run near the deadline, and per-run state leaks in long-lived servers.

**Systematic improvement.** Rule: a host decision switches only on a typed code stored at the point of production. Oracles emit a typed failureCode, and retest-health switches on it, defaulting unknown codes to inconclusive. ProviderFailure {kind, status, hard} is persisted on the profile and the worker outcome, and the circuit and reconciler read those fields. One RetryGovernor (key, cap, request/wall-clock/USD budgets, disposer-registered) serves the R2-13, cq-5 and stall paths, and STEP_STATUS.retryable means 'eligible through the governor'. A lint scoped to the named decision modules bans regex over reason, lastError and summary.

**First PR-sized steps.**

1. (S) src/server/exec-worker-runner.ts:1116: pass the real wall-clock exhaustion check. R3-09 step 1 registers the Maps. Add a test that an exhausted wall clock produces no retry.
2. (S) src/server/model-settings.ts plus provider.ts: persist failureKind next to lastError and read it in evaluateRoleProviderCircuit. Add a test where a truncated, redacted auth outage still trips provider_paused.
3. (S) src/server/agent-script-proof.ts: default to an inconclusive reason. Add parity cases where the oracle wording changes but the verdict does not.
4. (M) A typed failureCode for the boolean_or_timing, persisted_mutation and conserved_balance oracles, switched on in retest-health. Add the decision-module regex lint.
5. (M) Extract the RetryGovernor and migrate the cq-5 and stall paths one at a time.

**Success metric (must be mechanically verified on `main` before marking done).** The wall-clock retry test and the truncated-outage circuit test are green in worker-gate. The wording-change parity cases keep their verdicts. The decision-module regex lint reports 0 hits. A static check shows retry paths with their own caps == 1.

**Risks / invariants to preserve.** ['Retest changes must stay fail-safe: an unknown code is inconclusive, never fixed.', 'Persisting failureKind is a schema change, and the store.ts migration has a single owner. Sequence it.', 'Scope the lint to decision modules so it does not hit display code.', 'agent-script-proof.ts is a kernel-adjacent file (R3-04 extends the gate to it), so the R3-05 review applies.']

**Suggested lease.** `src/server/exec-worker-runner.ts (940-1170) HOT: R3-09 owns 500-510`, `src/server/retest-health.ts`, `src/server/agent-script-proof.ts (650-680, 930-940)`, `src/server/provider.ts (760-800)`, `src/server/model-settings.ts (595-625)`, `src/step-status.ts (HOT with R3-18; by entry)`, `src/server/exec-recon-planner.ts (2190-2350)`, `migration owner for the failureKind column`

---

## 15. Make 'No issue found' truthful: one record_coverage contract shared by tool schema, store and prompt, and per-route rows so an open gap cannot be overwritten

`id: R3-15` · relation: round2_regression · related: R2-14, R3-11, R3-14 · impact 6/10 · leverage 6/10 · effort S · confidence high

**Depends on:** —

**Merged from:** R2-14 'No issue found' strictness diverges from the tool contract, and per-route evidence still collapses into one last-writer-wins status per category

**Problem.** R2-14 made the store throw COVERAGE_EVIDENCE_REQUIRED for ruled_out and no_issue_found without a run-owned exchange id. The tool schema and prompt still document repo file:line citations and leave exchangeIds optional, so repo-only white-box closures are rejected and workers burn turns; sys-contract-canary missed the drift. The row key is per category and every probed status has rank 2, so a later no_issue_found on route A overwrites a needs_follow_up gap on route B.

**Verified evidence.**

- src/server/store-findings.ts:1998-2005,2008,2042-2048 — Verified run-owned exchangeIds are required. Correction: enforcingControl is scanned for exchange-id tokens, so a white-box ruled_out persists only if it also cites a run exchange.
- src/server/agent-session.ts:2909,2918,2925 (slice) — The prompt accepts 'file:line in /repos', and exchangeIds is opt().
- src/server/coverage-category.ts:302-314 — ruled_out, no_issue_found, needs_follow_up and not_applicable all have rank 2.
- src/server/schema.ts:433; src/server/store-findings.ts:2151 — Unique index on (runId, goalRevision, origin, category). Demotion is blocked only by a lower rank, so equal-rank writes overwrite.
- src/server/coverage-category.ts:341-425; src/server/exec-recon-planner.ts:4970-4995 — Route and exchange evidence is written to prose trailers capped at 6 routes and 8 exchanges and parsed back. Mitigation: parsed ids are re-verified against run-owned broker exchanges.

**Observed symptoms.** A category shows 'No issue found' while a route-scoped follow-up gap remains. White-box closures are rejected and workers spend turns on rejections.

**Systematic improvement.** One RecordCoverageContract (required fields per status) generates the tool JSON schema, the store validation and the prompt text, and sys-contract-canary pins it. Either accept host-verified repo citations as evidence or remove file:line from the docs. Coverage moves to per-route rows with route and exchange_id columns, and the category cell is derived from them. Ranking needs_follow_up above closures is an interim step only.

**First PR-sized steps.**

1. (S) tests/sys-contract-canary.test.ts: assert that the record_coverage schema's required fields equal the store's required evidence per status. Update the docs in agent-session.ts and assignment-brief.ts in the same batch.
2. (S) Interim: rank needs_follow_up above no_issue_found and ruled_out in coverageStatusRank, with a two-route test.
3. (M) Per-route coverage rows (migration through the store.ts migration owner), with the category cell derived from rows. Columns replace the trailers.

**Success metric (must be mechanically verified on `main` before marking done).** The contract-canary assertion is green in worker-gate. Two-route test: the category never shows 'No issue found' while any route has needs_follow_up. COVERAGE_EVIDENCE_REQUIRED rejections per agentic smoke run, counted from run events in the ledger row, == 0.

**Risks / invariants to preserve.** ['Verifier critique: the rank change makes gaps sticky, so a legitimate later closure of the same route can never clear it. Per-route rows are the real fix; the rank change is interim.', "Repo citations count as evidence only when they are host-verified against the run's snapshot. Worker prose must never close coverage.", 'The migration needs sequencing with the single migration owner.']

**Suggested lease.** `src/server/coverage-category.ts (300-430) HOT: R3-11 owns 90-130`, `src/server/store-findings.ts (1995-2160)`, `src/server/agent-session.ts (2900-2935, slice only)`, `src/server/assignment-brief.ts`, `tests/sys-contract-canary.test.ts record_coverage section (HOT with R3-08)`, `src/server/schema.ts plus migration (single owner)`

---

## 16. Evidence custody by type: host-observed vs worker-selected provenance, a mandatory registry with no unsanitized fallback, and a per-run nonce ledger bound to run, oracle and exchange

`id: R3-16` · relation: recurring_class · related: R4 recurring class 1, R4-C-1, R4-C-2, R4-C-4, R4-C-5, R4-H-5, R3-13, R3-17 · impact 8/10 · leverage 8/10 · effort L · confidence high

**Depends on:** R3-13; R3-05; R3-02

**Merged from:** No total evidence-provenance type: host-observed, host-minted and worker-designated bytes share untagged optional fields, and custody is a per-caller denylist; Host-minted bindings are bespoke per oracle, held in a process-global LRU, and not bound to run, oracle, exchange or target, so most oracles have no input binding

**Problem.** Receipt and step types mix host-recorded, host-minted and worker-designated fields as untagged optionals. Custody is a 4-field denylist, so balanceField/capField, expectControlDenied, proofPatterns and vulnClass survive, and verifyReceipt reads worker scalars directly. Host-minted stamps sit in a process-global, 512-entry FIFO singleton and are checked only for membership and value equality, not run, oracle, exchange or origin. Timing accepts transcript-level or any-arm challenges, and redirect accepts any registry-minted host: siblings of the R4-C-2 shape. Every critical finding so far is a worker-influenced field that an oracle treated as host fact.

**Verified evidence.**

- src/server/terminal-oracle-registry.ts:143-174 — Custody is a destructuring denylist. balanceField, capField, expectControlDenied, proofPatterns, injectedAtMs and vulnClass survive it.
- src/server/proof-receipt.ts:46-74,1497-1506 — The receipt schema carries worker scalars, and verifyReceipt builds ImpactInput from requiredRole, resourceTenant, expectControlDenied and proofPatterns.
- src/server/host-fact-log.ts:751-759 — resolveCanonicalArm keeps any explicit arm, and arm provenance is not recorded.
- src/server/proof-receipt.ts:152-157,390-422 — Module-singleton maps capped at 512. verifyBooleanPair checks membership plus value equality, with no run or exchange binding.
- src/server/proof-receipt.ts:1180-1189,1334-1337; src/server/verify-prove-handlers.ts:599,654,757,1347 — The timing challenge can come from the transcript or any arm. Redirect accepts any minted host. Prove handlers mint with no runId.
- src/server/composite-receipt.ts:545-556; src/server/terminal-oracle-registry.ts:590 (correction) — The fallback evaluator calls verifyReceipt without the custody sanitizer. It is latent in production, because the registry registers at import.

**Observed symptoms.** Each fix adds a local guard to one oracle while sibling oracles keep reading the same kind of field. Corrections: the v8 hydrate merges accept worker values only in the weakening direction, so they are not a forge path. Authz/tenant oracles bind through persona/tenant evidence and canaries. Within-run cross-exchange reuse is a more realistic risk than cross-run transfer.

**Systematic improvement.** Do the cheap custody pieces first: make the registry mandatory, delete the fallback evaluator, and turn the denylist into an allowlist of host-derived fields. Then add a per-run nonce ledger: an HMAC-stamped nonce bound to {runId, oracleId, armRole, origin/method/route/param, exchangeId}, persisted for cited stamps so retests re-verify. Finally add branded provenance types (HostObserved, HostMinted, WorkerSelected, WorkerAsserted). Oracle evaluators take a HostEvidence view, so the compiler enforces custody, and the host assigns arm and evidenceRole at send time.

**First PR-sized steps.**

1. (S) src/server/composite-receipt.ts plus terminal-oracle-registry.ts: delete fallbackOracleEvaluator and throw when the registry is unregistered.
2. (S) Convert the sanitizeSingleHopReceiptForHostCustody denylist into an allowlist of host-derived fields, with a test that enumerates receipt fields.
3. (M) src/server/nonce-ledger.ts behind the HostMintedOracle interface. Migrate timing and redirect first and delete their transcript-level fallbacks.
4. (S) Fast guard test: a stamp minted for run A, oracle X or exchange E1 is rejected when cited by run B, oracle Y or exchange E2.
5. (L) src/server/evidence-provenance.ts branded types, verifyReceipt(HostEvidence, OracleSpec), and host-assigned arms in the prove.* handlers.

**Success metric (must be mechanically verified on `main` before marking done).** The cross-binding guard test is green in worker-gate. The custody allowlist test shows 0 worker scalars readable by oracle bodies, enforced at compile time once HostEvidence lands. A static check finds no fallback evaluator. A restart test shows retest re-verification succeeds from the persisted ledger. The R3-12 matrix shows 0 confirms, and the promoted ledger row shows no lost TPs against the prior row.

**Risks / invariants to preserve.** ['Verifier critique: a mandatory nonce binding for every spec is wrong, because authz and economic oracles bind through persona/tenant evidence. Allow multiple binding kinds.', 'Moving arm assignment to the host needs prove.* coverage for every flow, or agent-script recall drops. Measure it via R3-02.', 'Persisting stamps on hot probe paths adds DB write load. Persist cited stamps only, or batch the writes.', 'The HMAC run key must never reach the worker.', 'All steps are kernel diffs, so the R3-05 lane applies.']

**Suggested lease.** `src/server/nonce-ledger.ts (new)`, `src/server/evidence-provenance.ts (new)`, `src/server/proof-receipt.ts (150-540, 1175-1190, 1330-1340) HOT kernel`, `src/server/verify-prove-handlers.ts mint sites`, `src/server/terminal-oracle-registry.ts (143-174, 590) HOT with R3-13; serialize`, `src/server/composite-receipt.ts (540-560)`, `src/server/host-fact-log.ts (745-760) HOT with R3-19`

---

## 17. Make anti-reflection, control legitimacy, publicness and boolean-pair binding single kernel stages owned by concept, not per-file guards

`id: R3-17` · relation: recurring_class · related: R4 recurring classes 2/3, R4-C-1, R4-C-3, R4-C-6, R4-H-7, R3-H-4, R3-13, R3-16 · impact 8/10 · leverage 8/10 · effort L · confidence high

**Depends on:** R3-12; R3-13; R3-05

**Merged from:** Anti-reflection, negative-control legitimacy and publicness are opt-in guards inside individual oracles, not kernel stages; Proof kernel grows guard-on-guard: one finding class becomes N per-file helpers because leases are per file, not per concept

**Problem.** File leases turned one cross-file soundness finding (R4-C-1 boolean-pair binding) into three per-file validator layers, and boolean helpers roughly doubled across two rounds (11 -> 20 -> 22 by the verifier's count). Anti-reflection has two competing shared carrier normalizers, a signed-URL wrapper and several oracle-local echo predicates. The self-sabotaged-control guard exists twice and applies only to auth boundary claims. assessPublicness is called only inside authorization, so disclosure, the v8 dual-tenant/crypto-scope families and signed_url_mint never ask whether a resource is public by design.

**Verified evidence.**

- src/server/oracle-invariants.ts:3928; src/server/proof-receipt.ts:3476; src/server/verify-support.ts:647 — verifyBooleanTriangleBinding, verifyStampedBooleanPairRound and verifyBooleanArmBaseParity. Correction: these sit at different stages and partly share canonicalPredicateSkeleton. The real duplication is the equal-length and same-multiset checks.
- src/server/oracle-invariants.ts:5136 vs src/server/proof-receipt.ts:3635 — impactStepToBooleanArm and stepToBooleanArm are a verbatim 13-line clone.
- src/server/oracle-invariants.ts:4150,4564,4587,4597,4726,4815; src/server/proof-receipt.ts:3151,3281,3827; src/server/verify-support.ts:1394,1519 — Two carrier normalizers, a signed-URL wrapper and several echo predicates across 3 files.
- src/server/proof-receipt.ts:2367-2407; src/server/verify-claims.ts:1073-1074 — The R4-H-7 self-sabotage guard is duplicated, and only auth boundary claims use it.
- src/server/oracle-invariants.ts:1817,1920; src/server/proof-receipt.ts:2486-2500 (correction) — These are the only assessPublicness callers. auth_bypass does gate publicness, through a 401/403 same-route control. The gap holds for disclosure, v8 families and signed_url_mint.
- git show --stat 51f6e46 — WS-1 alone changed oracle-invariants.ts by +1265/-210 for 3 finding IDs.

**Observed symptoms.** Each round one oracle gets the hardened normalizer, control check or publicness check, and the next audit finds an oracle without it. Precision depends on which of N layers a confirmation path reaches.

**Systematic improvement.** Spec-driven kernel stages run before any oracle body executes. (a) Reflection: one fail-closed carrier normalizer replaces the two current ones and the oracle-local predicates. (b) Controls: one assertLegitimateControl primitive, driven by the spec's {role, differsOnlyIn, mustBe}. (c) Publicness: a 'must_be_non_public' stage for every spec that asserts a confidentiality or authentication boundary. Boolean-pair logic moves into a proof-kernel/boolean-differential.ts concept module, and leases are assigned per concept module so a cross-file finding goes to one stream.

**First PR-sized steps.**

1. (S) Delete the impactStepToBooleanArm clone and call one shared stepToBooleanArm.
2. (M) Merge normalizeRequestCarrier and normalizeCarrierForAntiReflection into one normalizer with a malformed-input rejection mode. Route the echo predicates through it, and add a static guard against new echo predicates outside the module.
3. (M) Extract assertLegitimateControl() from the R4-H-7 logic and call it from every spec that declares a denied control. v8 temporal families legitimately differ in time.
4. (M) A publicness stage for disclosure, the v8 dual-tenant/crypto families and signed_url_mint, with a request budget in run-safety-budgets.ts and prod_readonly respected.
5. (L) proof-kernel/boolean-differential.ts. Keep verifyBooleanArmBaseParity as a call into it (handler-side defense in depth); do not delete it.

**Success metric (must be mechanically verified on `main` before marking done).** Static guards: exactly 1 carrier normalizer and 0 echo predicates outside the reflection module. Registry tests: the assertLegitimateControl call count equals the number of specs with denied controls, and the publicness stage runs for every boundary spec. The boolean helper count does not increase. The R3-12 matrix shows 0 confirms, and the parity corpus is green under all permutations.

**Risks / invariants to preserve.** ['Per the verifier this carries high precision risk. Grow the parity corpus and the R3-12 matrix first; 15 TP / 21 FP is too thin to guard this refactor.', 'Do not delete the handler-side boolean pre-check.', 'A publicness replay sends extra target requests. It needs a run-safety-budgets entry and must respect prod_readonly.', 'Name-pattern AST guards are crude and renaming defeats them. Prefer registry-driven checks.', 'R3-05 kernel-lane review is mandatory.']

**Suggested lease.** `src/server/proof-kernel/ (new)`, `src/server/oracle-invariants.ts (1810-1925, 3920-3935, 4140-4830, 5130-5145) HOT kernel; serialize with R3-13/R3-16`, `src/server/proof-receipt.ts (2360-2410, 3140-3830) HOT`, `src/server/verify-support.ts (640-660, 1390-1535)`, `src/server/verify-claims.ts (1070-1080)`, `src/server/run-safety-budgets.ts publicness budget (HOT with R3-07)`

---

## 18. One derived RunActivity and one findings/step projection that every surface renders, with exhaustive switches so new statuses reach every consumer

`id: R3-18` · relation: carried_over_open · related: R2-18, R2-07, cq-5 -> R4-H-13, cq-13a -> R4-H-19, operator isRunActive bug, R3-03, R3-20 · impact 7/10 · leverage 7/10 · effort M · confidence high

**Depends on:** —

**Merged from:** 'Is this run active/live/stuck' is computed in 10+ independent places with different status sets. Raw rows and the UI projection disagree, and the reported isRunActive bug is still present at 3a552f1; Operator surfaces outside each stream's lease still use local status predicates: findings counts bypass findings-view, and step metrics and glyphs bypass STEP_STATUS; Quality and feature fixes change shared types or semantics on the producer side only. Lease plans leave out consumers, so the security rounds pick up the stranded consumers

**Problem.** Whether a run is active, live or stuck is computed in 10+ places with different status sets. isRunActive counts parked waiting_approval rows regardless of run status, so a paused run reads as active and blocks delete; this operator bug is still present at 3a552f1. Project and home confirmed counts use SQL without the operator triage overlay. Report consumers re-dedupe after projection. Report step metrics and glyphs use literal lists that drop the cq-5 statuses. The underlying mechanism is that streams migrate the producers in their lease and strand the consumers outside it.

**Verified evidence.**

- src/server/store-runs.ts:975-995,3192-3198 — isRunActive counts running+waiting_approval assignments regardless of run status, and pause deliberately keeps parked waiting_approval rows.
- src/server/store-projects.ts:131,149,312,340; src/server/store.ts:2205-2214; src/server/finding-codec.ts:74-75 — Duplicate confirmed-count SQL and isActive predicates. CONFIRMED_FINDING_PREDICATE_SQL ignores triage, which findings-view.ts:140 applies.
- src/components/run/header.tsx:155-156; src/components/run/views/workflow-layout.ts:62; src/components/run/views/workflow.tsx:28-30; src/components/project/ProjectRunsTab.tsx:47-52; src/components/project/ProjectOverviewTab.tsx:239; src/server/qa-anomalies.ts:79-80 — Each surface has its own predicate. workflow.tsx casts 'waiting' onto an assignment status.
- src/server/store-runs.ts:3718-3722; src/components/run/glyphs.tsx:38-75 — Literal step lists. No glyph for turn_capped, model_failure or infra_failed, although STEP_STATUS declares one.
- src/server/report-export.ts:568-587; src/server/sarif-export.ts:559-566 — Dedupe and status re-filtering after projectRunFindings.
- tests/qa-lifecycle-invariants.test.ts:505-513 — KNOWN_PREEXISTING_DRIFT_RATCHET allowlists the partial terminal lists.
- plans/claude_quality_2.md:30-46; plans/CLAUDE_AUDIT_R4.md:546,676 — 0 of 13 round-1 items fully effective. Producer-only migrations stranded consumers (cq-5 -> R4-H-13, cq-13a -> R4-H-19).

**Observed symptoms.** Project tabs, the home page and the run headline disagree on active runs and confirmed counts, including findings the operator marked false positive. Capped or failed steps vanish from the report gaps. Corrections: 'completed run shows active' needs rows written after settlement, but the paused case is solid. workflow-layout isLive is an assignment-level predicate.

**Systematic improvement.** Add one server-side deriveRunActivity() -> {lifecycle, hasLiveWork, hasParkedApprovals, blockingReasons[]}, shipped on RunDetail and ProjectDetail; the UI renders it and never recomputes. projectRunFindings becomes terminal (dedupe and collapse move inside it) and gets a triage-aware SQL twin pinned by a parity test. Step partitions and glyphs derive from STEP_STATUS. Consumer closure: exhaustive switches with assertNever on status/verdict/outcome unions, a pulse report of importers of changed exported types outside the stream's diff, and a drift test that covers src/components and src/routes with an empty allowlist.

**First PR-sized steps.**

1. (S) src/server/store-runs.ts isRunActive: stop counting parked approvals as active work, and surface them through blockingReasons so delete still requires explicit confirmation. Add a paused-run-with-parked-approval test.
2. (S) Build report step metrics from the step-status partitions, and drive glyphs.tsx from STEP_STATUS[s].glyph.
3. (S) New scripts/check-exhaustive.ts: assertNever lint for the STEP_STATUS, verdict, outcome and run-status unions.
4. (M) deriveRunActivity in src/server/run-status.ts. Replace the predicates in store-projects, store.ts, header.tsx, workflow*.tsx and the Project tabs.
5. (M) One triage-aware confirmed SQL predicate plus a TS/SQL parity test. Move dedupe into projectRunFindings, pinned by a collapsible-duplicate fixture first.
6. (S) Extend qa-lifecycle-invariants to src/components, src/routes and WorkerStatus, and empty the ratchet allowlist.

**Success metric (must be mechanically verified on `main` before marking done).** The qa-lifecycle drift ratchet allowlist is empty, and the static scan finds 0 run/finding/step status-set literals outside run-status.ts, findings-view.ts and step-status.ts. The TS/SQL parity test is green. The paused-run test is green. check-exhaustive is green in worker-gate. The AGENTS.md UI gate's Playwright geometry assertions pass for the changed components.

**Risks / invariants to preserve.** ["Excluding parked approvals from 'active' must not let delete silently discard a parked operator approval. Express it as a blocking reason.", 'Moving dedupe into the projection changes report counts. Pin the fixture first and expect a discontinuity.', 'Changes under src/components trigger the AGENTS.md UI QA gate (build, screenshots at 1280x720 and 1440x900, geometry assertions).']

**Suggested lease.** `src/server/run-status.ts (owner; R3-20 edits after this merges)`, `src/server/store-projects.ts`, `src/server/store.ts (2200-2235)`, `src/server/store-runs.ts (970-1000, 3710-3725) HOT`, `src/server/finding-codec.ts (70-80)`, `src/findings-view.ts`, `src/server/report-export.ts (560-590) and src/server/sarif-export.ts (555-570)`, `src/components/run/glyphs.tsx`, `src/components/run/header.tsx activity section (HOT with R3-03)`, `src/components/project/*`, `src/components/run/views/workflow*.ts(x)`, `tests/qa-lifecycle-invariants.test.ts`, `scripts/check-exhaustive.ts (new)`

---

## 19. Carry typed persona tenant and privilege in host-signed exchange metadata, and route every kernel tenant/role read through the resolver

`id: R3-19` · relation: incomplete_round2_fix · related: R2-17, cq-10, R3-13, R3-16 · impact 7/10 · leverage 7/10 · effort M · confidence high

**Depends on:** R3-02; R3-05

**Merged from:** Typed persona identity (R2-17) stops at the resolver; the confirmation kernel and agentic verify path still read tenant and role from label grammar

**Problem.** R2-17 wired resolvePersonaIdentity into the floor lanes, but host-signed exchange metadata still carries only the free-text role label, never tenantRef or privilege. About 19 parseRoleLabel call sites across 8 kernel/verify files read tenant and role from label grammar, including the verify-claims site the plan named. The fallback counter sees only resolver calls, and the 'opaque-label ablation' is a unit test, not the bench cell that R2-17's success metric required.

**Verified evidence.**

- src/server/verify-rpc.ts:680; src/server/persona-vault.ts:189-191 — requestMeta stamps only actorRoleLabel. ResolvedPersona already has tenantRef and privilege.
- src/server/verify-claims.ts:961 — Tenant is parsed from the signed label or the handle. plans/claude_quality_2.md:702 named this site.
- src/server/exec-verify.ts:1779,1889 — parseRoleLabel(...).tenant || 'default_tenant'. Whether this feeds a confirmation decision is not verified.
- src/server/v8-oracle-hydrate.ts:247,763,771,871 — Kernel role and tenant are hydrated from labels.
- parseRoleLabel( call sites outside oracle-invariants.ts — About 19: verify-rpc 5, v8-oracle-hydrate 5, exec-verify 2, host-fact-log 2, composite-receipt 2, verify-claims 1, agent-script-proof 1, floor-recipe-engine 1.
- src/server/floor-recipe-engine.ts:172-176; tests/r2-17-persona-typed.test.ts:207-259 — A legacy-mock shim lets the label override typed privilege. The ablation tests resolvePersonaIdentity only.

**Observed symptoms.** With UI-created personas whose labels have no tenant grammar, cross-tenant proofs on kovo_verify, agent-script and composite paths probably resolve to a null or default tenant and fail closed or mis-bind (likely, not demonstrated). Authz recall remains a label-grammar benchmark artifact, while the counted fallbacks report 0.

**Systematic improvement.** Add actorTenant and actorPrivilege, set from ResolvedPersona, to host-signed exchange metadata at verify-rpc, the broker and patch-workflow stamping. Every kernel tenant/role read goes through resolvePersonaIdentity over that metadata. The label fallback stays inside the resolver and is counted at kernel sites. A ratchet bans new direct parseRoleLabel calls, and acceptance is an opaque-label cell run through real Execution.

**First PR-sized steps.**

1. (S) Grep ratchet test: parseRoleLabel( call sites outside oracle-invariants.ts may only decrease (baseline about 19).
2. (S) Add actorTenant and actorPrivilege to the verify-rpc requestMeta (line 680) and to the host-fact-log recordExchange meta (additive).
3. (M) Replace parseRoleLabel at verify-claims.ts:961 and exec-verify.ts:1779/1889 with resolvePersonaIdentity over typed meta, remove the 'default_tenant' collapse, and count fallbacks at kernel sites.
4. (M) Add an opaque-label cell to scripts/benchmark-realistic.ts (product Execution) for dev and held-out, recorded as a ledger row.

**Success metric (must be mechanically verified on `main` before marking done).** parseRoleLabel call sites outside oracle-invariants reach 0 (from about 19). In the promoted ledger rows, opaque-label recall is within noise of the label-grammar cell with 0 kernel fallbacks. The R3-12 authz cells show 0 new confirms.

**Risks / invariants to preserve.** ['Per the verifier, removing the label fallback where the typed tenant is null makes sites that work today fail closed and cost recall. Keep the counted fallback inside the resolver.', 'Typed metadata must be host-signed and never accepted from the worker.', 'These sites are kernel files, so the R3-05 lane applies.']

**Suggested lease.** `src/server/verify-rpc.ts (660-690)`, `src/server/verify-claims.ts (950-970)`, `src/server/exec-verify.ts (1770-1895) HOT with R3-11`, `src/server/v8-oracle-hydrate.ts (240-260, 760-880) HOT with R3-13 (1440-1470)`, `src/server/host-fact-log.ts recordExchange meta (HOT with R3-16)`, `tests/r2-17-persona-typed.test.ts`, `scripts/benchmark-realistic.ts opaque-label cell (HOT with R3-02; serialize)`

---

## 20. An authoritative persisted lifecycle: decide stopped/failed semantics, transition tables with co-transitions, a startup recovery contract that hands lab containers to the reaper, pause-aware resources, and an always-on liveness check

`id: R3-20` · relation: recurring_class · related: R4 recurring class 7, R4-H-12, R4-H-13, R2-07, cq-13, R3-07, R3-18 · impact 7/10 · leverage 7/10 · effort L · confidence medium

**Depends on:** R3-07; R3-18

**Merged from:** No authoritative persisted lifecycle machine: 'terminal' run statuses can be resumed, terminal settlement covers assignments only, and stop→resume strands chain steps in 'running', which the liveness backstop counts as live work; Crash-recovery contract is partial and split: Store.recover() covers only running and paused runs, deletes the lab-container registry before anything reaps it, and the web server never runs lab startup recovery; Run resources only have a dispose hook, with no suspend/resume policy, so pausing leaves warm pools, lab targets and subscriptions running; QA lifecycle moves are opt-in or aimed at the wrong invariant: the anomaly detector is env-gated and only runs from an unscripted dogfood tool, and the 'lifecycle' test checks RunStatus spelling, not liveness

**Problem.** Four lifecycle models disagree. Resume accepts stopped and failed (and the UI offers it), while TTL purge and storage maintenance treat those statuses as terminal, so evidence of a resumable run is eligible for purge. Settlement covers assignments only, so resume after stop cancels the in-flight investigation step instead of requeueing it. Store.recover() runs inside the Store constructor, covers only running/paused runs, and deletes lab_containers rows that nothing on the web path reaps. Pause leaves warm pools and subscriptions alive because resources are dispose-only. The anomaly detector is env-gated and runs only from an unscripted dogfood tool.

**Verified evidence.**

- src/server/store-runs.ts:4027-4048; src/server/run-status.ts:44-48; src/server/artifact-ttl.ts:217-221; src/components/run/header.tsx:170-171 — Resume accepts paused, budget_paused, stopped and failed, while the terminal set used by TTL purge includes stopped and failed.
- src/server/store-runs.ts:3141-3158,3180-3207; src/server/run-actor.ts:2470-2492 (correction) — Settlement and setStatus touch assignments only. The R2-07 reconciler cancels stranded running steps, which refutes the finder's hang; the real effect is lost work.
- src/server/store-runs.ts:358-374,412-427; src/server/store.ts:1643 — recover() runs in the constructor over running/paused only and DELETEs lab_containers, returning the rows only in its report.
- scripts/cli.ts:615; src/server.ts:6-11; src/server/execution.ts:1016-1036 — The CLI is the only recoverAll caller. Web start only runs reclaimInactive for worker containers, so lab target containers leak after a crash.
- src/server/run-context.ts:167; src/server/execution.ts:895-906,1824-1842 — registerResource takes only a dispose fn. Warm-pool, lab and OOB resources are disposed only at terminal states.
- src/server/qa-anomalies.ts:129,397-410; scripts/qa-dogfood.ts:1455 — The detector is gated on KOVO_QA_ANOMALIES, only checks terminal runs, and has a single caller with no npm script.

**Observed symptoms.** Operators see Resume on runs the server treats as final, and evidence of such runs can be purged. Resume silently drops in-flight investigation work. Lab containers leak after a restart. Paused runs keep containers alive. Liveness bugs are found by hand in real use.

**Systematic improvement.** First make the product decision on stopped/failed: either terminal (remove Resume) or 'ended-resumable' (TTL purge skips them until a finalized flag is set). Then add src/server/lifecycle.ts with total transition tables and co-transitions for run, assignment, step, approval, lease and board member. Writes route through it in warn mode with telemetry before it is enforced. A startup reconciler in AppRuntime, called by every Store-opening entry point, applies the contract and hands reclaimed lab containers to ensureStartupRecovery. Resources declare holdIn states and suspend/resume hooks. A seeded lifecycle fuzz test in worker-gate and an emit-only checkRunLiveness in the wake loop keep the invariants honest.

**First PR-sized steps.**

1. (S) Record the stopped/failed decision, and align run-status.ts, artifact-ttl isRunEligible, storage-maintenance and the header.tsx Resume button.
2. (S) On resume, requeue stranded investigation steps instead of canceling them. Test: stop then resume with a running step leaves the step ready.
3. (M) Move recover() into AppRuntime.startupRecover(), called from the CLI, serve.ts, tests and bench scripts. Pass reclaimedContainers to labRunner.ensureStartupRecovery, cover all RunStatus values, and add tests/crash-recovery-contract.test.ts (a seeded crash-DB matrix).
4. (M) tests/lifecycle-fuzz.test.ts (seeded, about 500 sequences, under 5s) asserting liveness and terminal closure. checkRunLiveness in the wake loop emits run.invariant_violation (emit-only).
5. (M) registerResource({holdIn, suspend, resume, dispose}): the warm pool suspends on pause, while lab targets and OOB are held by default.
6. (L) src/server/lifecycle.ts transition tables, warn mode then enforced, with a static guard against raw status writes.

**Success metric (must be mechanically verified on `main` before marking done).** lifecycle-fuzz is in worker-gate with 0 invariant violations. The crash-recovery contract test is green across the seeded matrix. A test proves artifact-ttl never selects a run the UI offers to resume. Warm-pool containers for paused runs == 0 (test). run.invariant_violation events per agentic smoke run == 0. After enforcement, raw status writes outside lifecycle.ts == 0.

**Risks / invariants to preserve.** ["Per the verifier, total transition tables plus a write ban is L effort and risks R4's 'new strictness wedges normal behaviour'. Run warn mode with telemetry first.", 'Auto-repair from the wake loop is risky. Start emit-only, and add repairs one at a time, each with a test.', 'Lab targets stay held on pause. Stopping them loses seeded state, and resume would then probe a fresh target with stale facts. Hold OOB subscriptions while canaries are pending.', 'Moving recover() out of the constructor only moves the gap unless every Store-opening entry point calls startupRecover.', "The paused-run requeue-to-queued behaviour may be intentional. Write it into the contract rather than 'fixing' it.", "The finder's proposed backstop change is redundant with the existing reconciler, so drop it."]

**Suggested lease.** `src/server/lifecycle.ts (new)`, `src/server/store-runs.ts (355-450, 3140-3210, 4020-4050) HOT`, `src/server/run-status.ts (after R3-18)`, `src/server/artifact-ttl.ts`, `src/server/storage-maintenance.ts (500-510)`, `src/server/app-runtime.ts`, `src/server/store.ts (1640-1645)`, `src/server/run-context.ts`, `src/server/run-actor.ts transition section (HOT)`, `src/server/execution.ts (890-910, 1016-1036, 1790-1845) HOT`, `src/server/qa-anomalies.ts`, `tests/lifecycle-fuzz.test.ts (new)`, `tests/crash-recovery-contract.test.ts (new)`

---

## Known gaps in this audit

Not examined this round: (1) The post-R4 batch 09f9eeb..3a552f1 (45 merges plus 50 commits) has had no security audit, including the kernel semantics change in 8a94536 and the R4 fix streams themselves. Whether each R4-C/H fix holds was not re-verified, only the process around them. (2) No product measurement was run, so this ranking has no current recall or precision baseline. Impact estimates for precision items are structural, not measured. (3) Not inspected: performance and event-loop DoS classes (R4-H-14..H-16, the regex/scan budgets), repo-sync and checkout transforms (R4-H-18), OOB retention (R4-H-20), the worker container sandbox and mount permissions (M-8/L-7), and credential/redaction-plane correctness beyond the quarantine status of its suites. (4) UI visual and geometry QA for the components named in R3-03 and R3-18 was not exercised. (5) Held-out seed budget, seed rotation policy and benchmark generator realism (novel vocabulary) were not evaluated beyond the wiring gap. (6) Provider runtime policy and cost truth beyond the ledger fields (failover timeouts, price defaults). (7) Several finder metrics were not re-derived by the verifiers: the 21/11 source-text vs entry-point split among new tests, clone groups 16->19, '45 kernel cases at R2-02 landing', whether exec-verify's 'default_tenant' feeds a confirmation decision, whether the code-audit assignment phase disables the investigation backstop, and whether a same-CWE sibling rule is actually weaker. (8) Schema migrations and store.ts migration ownership were not audited, though R3-14, R3-15 and R3-20 depend on that owner. (9) The swarm tooling itself (agy, the /swarm pulse implementation, consult skill behaviour) was examined only through its outputs (reflog, CI history, trailers).

## Reviewer triage (filled 2026-11-26 by agy on `main` @ `4d26a13`)

| # | id | Verdict (accept / reject / defer) | Reason | Stream / owner | Lease (files) |
|---|---|---|---|---|---|
| 1 | `R3-01` | **ACCEPT (P0, Wave 0 — LANDS FIRST)** | Live proof on `3fe490d`: 3 Move-3 regressions (`arch-o1o2-prompt-sdk` 5578>5500, `v8-capability-ledger` 947>900, `fix-stall-wallclock` 4!=3) + CI `verify.yml` `tsc` heap OOM broke `main`. Fix those 3 regressions + CI heap + `merge-stream.sh` git note & CI check + `.githooks/reference-transaction` + `parallel-pulse.sh` + `check-tsc-budget.ts` first so every subsequent landing uses `merge-stream.sh` on a green CI. | `r3-01-main-green` | `src/server/agent-prompts.ts`, `src/server/capability-ledger.ts`, `src/server/exec-worker-runner.ts` (1-strike guard fix only), `.github/workflows/verify.yml`, `scripts/merge-stream.sh`, `scripts/install-main-guard.sh` (new), `.githooks/reference-transaction` (new), `scripts/parallel-pulse.sh`, `scripts/check-tsc-budget.ts` (new), `AGENTS.md` (merge section) |
| 2 | `R3-02` | **ACCEPT (P0 measurement, Wave 1, split A/B)** | 0 rows in `ledger.jsonl`, 604 leaked fake-SHA test rows in `benchmarks/results/runs/`, `floor.json` `gitSha: null`. Stream A lands ledger provenance validation + `KOVO_LEDGER_ROOT` hermetic isolation + drift check + `worker-source-hash.sh` + `regression-floor.sh` guard; Stream B wires default per-run rows + observed `effective_config` + `batch-boundary.sh` and promotes real dev + fresh salted held-out rows (`--no-llm` & agentic) to close the batch. | `r3-02a-ledger-guard`, `r3-02b-scorer-batch` | A: `scripts/bench-ledger.ts`, `scripts/runtime-profile.ts`, `scripts/regression-floor.sh`, `scripts/run-fast-tests.sh` (drift block), `scripts/worker-source-hash.sh` (new), `package.json` (`worker:build`), `benchmarks/baselines/floor.json`, `tests/r3-02-ledger-guard.test.ts`; B: `scripts/benchmark-{realistic,multihop,agentic-matrix}.ts`, `scripts/score-primitives.ts` (`buildLedgerRow`), `scripts/batch-boundary.sh` (new) |
| 3 | `R3-03` | **ACCEPT (P0 safety, Wave 1)** | Unbounded `run.approvedEndpointPatterns` checked before leases bypasses R2-09 TTL/`maxUses`/persona bounds; `run-actor.ts` omits `mutationKind`/`hostFloor`. Enforce `leaseAuthorizes` on BOTH `authorizeStateChange` & Stage 1B, fail-closed `undefined` `scopeRevision`, thread `ApprovalRequestFacts` + persist Judge audit fields, add operator `extend lease` command & UI (`header.tsx` with Playwright UI QA gate), then project `approvedEndpointPatterns` from live leases. | `r3-03-lease-auth` | `src/server/approval-judge.ts`, `src/server/run-actor.ts`, `src/server/execution.ts`, `src/server/store-runs.ts`, `src/components/run/header.tsx` (lease/pattern section), `tests/approval-lease-authority.test.ts` (new) |
| 4 | `R3-04` | **ACCEPT (P0 kernel gate, Wave 1b after `R3-01`)** | `CONFIRMATION_KERNEL_FILE_RE` misses 7 kernel files, range-wide `Parity-case` accepts any existing ID, and 13/14 R4 suites lack protection. Extend regex + export staleness test, add `covers: {files, classes}` to all 40 corpus files with per-commit binding, history-replay test on `13337ae`/`fafeb3c`/`8a94536`, `@kernel`/`@fixes` tags in `test-tiers.ts`, and `scripts/gen-kernel-manifest.ts`. | `r3-04-kernel-gate` | `scripts/check-contract-change.ts` (SOLE OWNER), `tests/parity/corpus/*.json` (`covers`), `scripts/gen-kernel-manifest.ts` (new), `scripts/test-tiers.ts` (tags), `tests/check-contract-change-history.test.ts` (new), `tests/r3-*.test.ts` & `tests/r4-*.test.ts` (`@kernel` tags) |
| 5 | `R3-05` | **ACCEPT (P0 anti-regression, Wave 2 after `R3-01` & `R3-04`)** | 73–77% repeat bypass/regression rate requires independent different-model review (Claude Code `%30` or OpenCode `glm-5.3` — never same model family as diff author) reading raw diff + spec + authoring a rejecting bypass case. Add `check-verdict-flip.ts`, `fix(worker-gate)` tests-only lint, `check-kernel-review.ts` (hooked into `merge-stream.sh` via R3-01 handoff), corpus provenance (`source`, `author_stream`), and `AGENTS.md` kernel-lane rules. | `r3-05-kernel-lane` | `AGENTS.md` (kernel-lane section), `scripts/check-verdict-flip.ts` (new), `scripts/check-kernel-review.ts` (new), `tests/path-parity.test.ts` (provenance), `scripts/merge-stream.sh` (review hook after R3-01) |
| 6 | `R3-06` | **ACCEPT (P1 quarantine debt, Wave 2 after `R3-01` & `R3-05`)** | 51 kernel/critical entries share invented owners & `2026-12-10` expiry cliff; must retire BEFORE cliff with zero expiry extensions. Add `triage-quarantine.ts`, forbid expiry increases + bind owners to live `STREAM-BACKLOG.md` rows in `run-fast-tests.sh`, split verdict vs prose assertions (kernel verdict asserts unquarantinable), un-quarantine provider-redaction suites, add `check-test-shape.ts`. | `r3-06-quarantine` | `tests/QUARANTINE.json`, `scripts/run-fast-tests.sh` (quarantine block, after R3-02a), `scripts/test-tiers.ts` (owner check, after R3-04), `plans/STREAM-BACKLOG.md`, `scripts/triage-quarantine.ts` (new), `scripts/check-test-shape.ts` (new) |
| 7 | `R3-07` | **ACCEPT (P0 hotfix + Wave 2 lifecycle)** | `runSourceFirstCodeAudit` leaks `this.active` and leaves assignment `running` on `openSession` throw; 7 hand-rolled claim sites & empty settlement catches. Ship S hotfix + `settleOrReport` + `check-empty-catch.ts` right after `R3-03` releases `execution.ts`/`store-runs.ts`, then `claimAssignment`/`ClaimHandle` + phase-agnostic reaper + lease budgets in `run-safety-budgets.ts`. | `r3-07-claim-owner` | `src/server/execution.ts` (after R3-03), `src/server/exec-recon-planner.ts` (`4490-4515`), `src/server/run-disposers.ts`, `src/server/store-runs.ts` (claim API, after R3-03), `src/server/run-safety-budgets.ts`, `scripts/check-empty-catch.ts` (new) |
| 8 | `R3-08` | **ACCEPT (P1 security wiring, Wave 2 after `R3-09`)** | Close the optional-security-guard class permanently: `check-security-optional.ts` AST lint over security registry, make `browser-session-auth.ts` refresher options required & replace `allowUnscopedRefreshForTest` with test-only factory unreachable from `src/server/`, add production-entry spy tests, replace canary fixed windows with R3-09 reachability walker. | `r3-08-sec-inputs` | `scripts/check-security-optional.ts` (new), `src/server/browser-session-auth.ts` (serialized with R3-10), `tests/sys-contract-canary.test.ts` (after R3-15), `tests/security-entry-*.test.ts` (new) |
| 9 | `R3-09` | **ACCEPT (P1 wiring truth, Wave 1b after `R3-01`)** | Fixes R2's #1 systemic flaw (primitives landing unwired/test-only, 3 check scripts not in `worker-gate.sh`, `check-direct-db-writes` red at `report-export.ts:397`, missing agentic cost coerced to `0`). Register `exec-worker-runner.ts:507-508` Maps, fix `report-export.ts:397`, wire `check-direct-db-writes` + `check-run-scoped-state` into `worker-gate.sh` (SOLE OWNER), add `gate-registry.test.ts`, fix `score-primitives.ts` null agentic cost, reachability walk in `check-unwired.ts`, wire `EffectiveTargetLoadPolicy`, token-telemetry summary & `--novel-vocab` cell + `ledger-field-producers.test.ts`. | `r3-09-reach-gate` | `scripts/worker-gate.sh` (SOLE OWNER), `scripts/check-unwired.ts`, `scripts/unwired-baseline.json`, `scripts/check-run-scoped-state.ts`, `src/server/exec-worker-runner.ts` (`500-510`, after R3-01), `src/server/report-export.ts` (`390-400`), `scripts/score-primitives.ts` (cost section, serialized with R3-02b), `src/server/execution.ts` (`effective_config`, serialized), `tests/gate-registry.test.ts` (new), `tests/ledger-field-producers.test.ts` (new) |
| 10 | `R3-10` | **ACCEPT (P1 complexity & repeat-patch, Wave 2 after `R3-01` & `R3-09`)** | Monotone `scripts/size-baseline.json` ratchet in `check-function-growth.ts` (allowing `Split-ticket:` for urgent security fixes), `check-fix-provenance.ts` (`Fixes: <ID>`), `check-clones.ts` + `src/server/safety-primitives.ts`, repeat-patch tripwire in `parallel-pulse.sh`, deletion-debt table in `STREAM-BACKLOG.md` + `broker.ts` Stage-2 bucket retirement. | `r3-10-size-clones` | `scripts/check-function-growth.ts`, `scripts/size-baseline.json` (new), `scripts/check-fix-provenance.ts` (new), `scripts/check-clones.ts` (new), `src/server/safety-primitives.ts` (new), `src/server/{exec-recon-planner,worker-backend,browser-session-auth,scoped-browser,broker}.ts` (clone/bucket slices, serialized), `scripts/parallel-pulse.sh` (after R3-01), `AGENTS.md` (rule 6) |
| 11 | `R3-11` | **ACCEPT (P1 precision, Wave 2 after `R3-05`)** | Live mislabels (`cross_tenant_read` -> CWE-200, missing CWE-89/943 in injection family, `xss`/`xxe` OWASP drift, missing CWE-family veto in `dedupe.ts`). Land S steps through `R3-05` kernel lane (`exec-verify.ts`, `dedupe.ts`, `coverage-category.ts` `90-130`), then step 5 (`src/vuln-taxonomy.ts`) with `R3-13`. | `r3-11-vuln-id` | `src/server/exec-verify.ts` (`215-485, 1246-1460`), `src/server/dedupe.ts` (`590-760`), `src/server/coverage-category.ts` (`90-130`, after R3-15), `tests/taxonomy-conformance.test.ts`, `tests/dedupe-veto.test.ts` |
| 12 | `R3-12` | **ACCEPT (P1 precision safety net, Wave 2 after `R3-01` & `R3-09`)** | Executable oracle × benign-archetype matrix (`tests/kernel-archetype-matrix.test.ts`, <5s in `worker-gate.sh`, 0 non-exempt confirms) + FP-only completeness across all single-hop rules & V8 families in `path-parity.test.ts`. Starts immediately on existing arrays as the safety net before Wave 3 kernel refactors (`R3-13`/`R3-16`/`R3-17`). | `r3-12-fp-matrix` | `tests/kernel-archetype-matrix.test.ts` (new), `tests/fixtures/benign-archetypes/*.ts` (new), `tests/path-parity.test.ts` (completeness, serialized), `benchmarks/realism-suite/traps/fp-archetypes.json` |
| 13 | `R3-13` | **ACCEPT, staged (P1 kernel architecture, Wave 3 after `R3-02`, `R3-04`, `R3-05`, `R3-12`)** | Highest long-run precision leverage: typed `OracleSpec` registry (`src/server/oracle-spec.ts`), agreement test, lateral same-CWE permutation, canonical/strongest `labelToOracle()` (never weakest!), `registerOracle()` admission test, migrate `verify-claims.ts` evaluators. Strictly gated behind R3-05 kernel lane, R3-12 matrix & R3-02 ledger. | `r3-13-oracle-spec` | `src/server/oracle-spec.ts` (new), `src/server/terminal-oracle-registry.ts` (`53-73`), `src/server/proof-receipt.ts` (`558-633, 4430-4460`), `src/server/v8-oracle-hydrate.ts` (`1440-1470`), `src/server/oracle-invariants.ts` (`5710-5830`), `src/server/verify-claims.ts` (`645-690, 1260-1600`), `tests/oracle-admission.test.ts` (new) |
| 14 | `R3-14` | **ACCEPT (P1 reliability, Wave 2 after `R3-09`)** | Stop re-classifying truncated/English prose: real `wallClockExhausted` at `exec-worker-runner.ts:1116`, persist `failureKind` next to `lastError` (migration sequenced), fail-safe default in `agent-script-proof.ts` (via R3-05 lane), typed oracle `failureCode` + decision-module regex lint, single `RetryGovernor`. | `r3-14-typed-retry` | `src/server/exec-worker-runner.ts` (`940-1170`, after R3-09), `src/server/retest-health.ts`, `src/server/agent-script-proof.ts` (`650-680, 930-940`), `src/server/provider.ts` (`760-800`), `src/server/model-settings.ts` (`595-625`), `src/step-status.ts`, `src/server/exec-recon-planner.ts` (`2190-2350`) |
| 15 | `R3-15` | **ACCEPT (P0 round-2 regression, Wave 1)** | R2-14 strictness diverged from `record_coverage` tool schema/prompt (burning white-box turns) & equal-rank statuses let `no_issue_found` overwrite `needs_follow_up`. Unify `RecordCoverageContract` across tool schema, store & prompt + pin in `sys-contract-canary.test.ts`, interim rank fix + 2-route test, then per-route coverage rows via single migration owner. | `r3-15-coverage-truth` | `src/server/coverage-category.ts` (`300-430`), `src/server/store-findings.ts` (`1995-2160`), `src/server/agent-session.ts` (`2900-2935`, slice only), `src/server/assignment-brief.ts`, `tests/sys-contract-canary.test.ts` (`record_coverage` section), `tests/r3-15-coverage-truth.test.ts` (new) |
| 16 | `R3-16` | **ACCEPT, staged (P1 kernel custody, Wave 3 after `R3-02`, `R3-05`, `R3-13`)** | Delete `fallbackOracleEvaluator`, convert custody denylist to allowlist, per-run `nonce-ledger.ts` bound to `{runId, oracleId, armRole, target, exchangeId}` (supporting non-nonce binding kinds for authz/economic), then branded `evidence-provenance.ts` types. Gated on R3-05, R3-12 & R3-02. | `r3-16-custody-nonce` | `src/server/nonce-ledger.ts` (new), `src/server/evidence-provenance.ts` (new), `src/server/proof-receipt.ts` (after R3-13), `src/server/verify-prove-handlers.ts`, `src/server/terminal-oracle-registry.ts` (after R3-13), `src/server/composite-receipt.ts` (`540-560`), `src/server/host-fact-log.ts` |
| 17 | `R3-17` | **ACCEPT, staged (P1 kernel stages, Wave 3 after `R3-05`, `R3-12`, `R3-13`)** | Delete `impactStepToBooleanArm` clone, unify carrier normalizer, extract `assertLegitimateControl()`, add budgeted/`prod_readonly`-respecting publicness stage, extract `proof-kernel/boolean-differential.ts` (keeping handler pre-check). Gated on R3-05, R3-12 & R3-13. | `r3-17-kernel-stages` | `src/server/proof-kernel/` (new), `src/server/oracle-invariants.ts` (after R3-13), `src/server/proof-receipt.ts` (after R3-16), `src/server/verify-support.ts`, `src/server/verify-claims.ts` (`1070-1080`), `src/server/run-safety-budgets.ts` (after R3-07) |
| 18 | `R3-18` | **ACCEPT (P1 operator truth, Wave 2 after `R3-03`)** | Fixes live `isRunActive` paused-run bug (`blockingReasons` preserves delete confirmation), drives report metrics & `glyphs.tsx` from `STEP_STATUS`, adds `check-exhaustive.ts`, single `deriveRunActivity()` across server/UI, triage-aware confirmed SQL twin + TS/SQL parity + dedupe inside `projectRunFindings`, empties `qa-lifecycle-invariants` allowlist (with Playwright UI QA gate). | `r3-18-run-activity` | `src/server/run-status.ts`, `src/server/store-projects.ts`, `src/server/store.ts` (`2200-2235`), `src/server/store-runs.ts` (`970-1000, 3710-3725`, after R3-03), `src/server/finding-codec.ts`, `src/findings-view.ts`, `src/server/{report,sarif}-export.ts` (after R3-09), `src/components/run/{glyphs,header,views/workflow*}.tsx`, `src/components/project/*`, `tests/qa-lifecycle-invariants.test.ts`, `scripts/check-exhaustive.ts` (new) |
| 19 | `R3-19` | **ACCEPT (P1 authz realism, Wave 2b/3 after `R3-02` & `R3-05`)** | Complete R2-17 across the confirmation kernel: `parseRoleLabel(` grep ratchet (19 -> 0 outside `oracle-invariants.ts`), host-signed `actorTenant` & `actorPrivilege` on `verify-rpc`/`host-fact-log`/`broker`/`patch-workflow`, route kernel reads through `resolvePersonaIdentity` (keeping counted fallback), real Execution opaque-label bench cell in `benchmark-realistic.ts`. | `r3-19-typed-kernel` | `src/server/verify-rpc.ts` (`660-690`), `src/server/verify-claims.ts` (`950-970`, serialized with R3-13), `src/server/exec-verify.ts` (`1770-1895`, after R3-11), `src/server/v8-oracle-hydrate.ts` (`240-260, 760-880`), `src/server/host-fact-log.ts` (serialized with R3-16), `tests/r2-17-persona-typed.test.ts`, `scripts/benchmark-realistic.ts` (after R3-02b) |
| 20 | `R3-20` | **ACCEPT, staged (P2 lifecycle, Wave 3 after `R3-07` & `R3-18`)** | Product decision: treat `stopped`/`failed` as `ended-resumable` (so operator Resume stays intact and `artifact-ttl` skips resumable runs until finalized/past retention) while requeuing stranded investigation steps on resume; move `recover()` to `AppRuntime.startupRecover()` handing lab containers to `ensureStartupRecovery`; add `lifecycle-fuzz.test.ts` + emit-only `checkRunLiveness`; pause-aware `registerResource` (suspends warm pool, holds lab targets & OOB); then `lifecycle.ts` warn-then-enforced transition tables. | `r3-20-lifecycle` | `src/server/lifecycle.ts` (new), `src/server/store-runs.ts` (after R3-07/R3-18), `src/server/run-status.ts` (after R3-18), `src/server/{artifact-ttl,storage-maintenance,app-runtime,store,run-context,run-actor,execution,qa-anomalies}.ts`, `tests/{lifecycle-fuzz,crash-recovery-contract}.test.ts` (new) |

### Parallel workstreams & execution log (updated 2026-11-26 by agy)

#### Binding Rules & Active Overlap Check
- **Active background work:** `task-9655` (v8 M2 Docker certification at `3fe490d` writing to `/home/omarchy/guardian-bench-tmp/m2-cert-3fe490d/`) — read-only on repo files, zero overlap. Zero other coding workers active.
- **Strict 1-writer-per-file hot-file serialization:**
  - `scripts/merge-stream.sh` & `scripts/parallel-pulse.sh`: `R3-01` → `R3-05` (`merge-stream.sh` hook) / `R3-10` (`parallel-pulse.sh` tripwire)
  - `scripts/worker-gate.sh`: `R3-09` (SOLE OWNER; `R3-05`/`R3-06`/`R3-07`/`R3-08`/`R3-10`/`R3-12` register via R3-09)
  - `scripts/check-contract-change.ts`: `R3-04` (SOLE OWNER)
  - `scripts/run-fast-tests.sh`: `R3-02a` (drift block) → `R3-06` (quarantine block)
  - `src/server/execution.ts` & `src/server/store-runs.ts`: `R3-03` → `R3-07` → `R3-09` (`effective_config`) / `R3-18` (`isRunActive`/metrics) → `R3-20`
  - `src/server/exec-worker-runner.ts`: `R3-01` (1-strike fix) → `R3-09` (Maps) → `R3-14` (wallClock/retry)
  - `src/server/oracle-invariants.ts`, `proof-receipt.ts`, `verify-claims.ts`, `terminal-oracle-registry.ts`: `R3-05` kernel lane active first → `R3-11` (`exec-verify`) / `R3-19` → `R3-13` → `R3-16` → `R3-17`
  - `src/server/store.ts` migrations (single owner serialized): `R3-14` (`failureKind`) → `R3-15` (per-route coverage)
- **Merge order (Acceptance Protocol Rules #2 & #3):** `r3-01-main-green` lands FIRST to fix the 3 Move-3 red-main suites and CI `verify.yml` OOM, installs the main-ref guard, and turns CI GREEN. `r3-03-lease-auth`, `r3-15-coverage-truth`, and `r3-02a-ledger-guard` run in parallel in disjoint worktrees and merge EXCLUSIVELY via `scripts/merge-stream.sh <branch>` ONLY AFTER `R3-01` is on `main` and CI is GREEN.

#### Wave Plan
- **Wave 0 (RED-MAIN FIX — LANDS FIRST):** `r3-01-main-green` (`R3-01`)
- **Wave 1 (DISPATCHED IN PARALLEL, 100% DISJOINT, MERGES AFTER `R3-01` CI GREEN):** `r3-03-lease-auth` (`R3-03`), `r3-15-coverage-truth` (`R3-15`), `r3-02a-ledger-guard` (`R3-02` Stream A)
- **Wave 1b / 2 (unlocks as Wave 0/1 merge):** `r3-04-kernel-gate` (`R3-04`), `r3-09-reach-gate` (`R3-09`), `r3-02b-scorer-batch` (`R3-02` Stream B), `r3-07-claim-owner` (`R3-07`), `r3-05-kernel-lane` (`R3-05`), `r3-18-run-activity` (`R3-18`), `r3-12-fp-matrix` (`R3-12`), `r3-06-quarantine` (`R3-06`), `r3-08-sec-inputs` (`R3-08`), `r3-10-size-clones` (`R3-10`), `r3-11-vuln-id` (`R3-11`), `r3-14-typed-retry` (`R3-14`), `r3-19-typed-kernel` (`R3-19`)
- **Wave 3 (gated on `R3-02` + `R3-05` + `R3-12`):** `r3-13-oracle-spec` (`R3-13`), `r3-16-custody-nonce` (`R3-16`), `r3-17-kernel-stages` (`R3-17`), `r3-20-lifecycle` (`R3-20`)

#### Execution Log

| Item | Stream | State (`merged` / `verified` / `complete`) | Merge SHA | `merge-stream.sh` Gate Digest | CI Run ID (green) | Mechanical `success_metric` Evidence on `main` |
|---|---|---|---|---|---|---|
| `R3-01` | `r3-01-main-green` | IN FLIGHT (Wave 0) | — | — | — | pending |
| `R3-02` (A) | `r3-02a-ledger-guard` | IN FLIGHT (Wave 1) | — | — | — | pending |
| `R3-03` | `r3-03-lease-auth` | IN FLIGHT (Wave 1) | — | — | — | pending |
| `R3-15` | `r3-15-coverage-truth` | IN FLIGHT (Wave 1) | — | — | — | pending |
| `R3-02` (B) | `r3-02b-scorer-batch` | QUEUED (after `R3-02a` + `R3-01`) | — | — | — | pending |
| `R3-04` | `r3-04-kernel-gate` | QUEUED (after `R3-01`) | — | — | — | pending |
| `R3-05` | `r3-05-kernel-lane` | QUEUED (after `R3-01` + `R3-04`) | — | — | — | pending |
| `R3-06` | `r3-06-quarantine` | QUEUED (after `R3-01` + `R3-05` + `R3-02a`) | — | — | — | pending |
| `R3-07` | `r3-07-claim-owner` | QUEUED (after `R3-03`) | — | — | — | pending |
| `R3-08` | `r3-08-sec-inputs` | QUEUED (after `R3-09`) | — | — | — | pending |
| `R3-09` | `r3-09-reach-gate` | QUEUED (after `R3-01`) | — | — | — | pending |
| `R3-10` | `r3-10-size-clones` | QUEUED (after `R3-01` + `R3-09`) | — | — | — | pending |
| `R3-11` | `r3-11-vuln-id` | QUEUED (after `R3-05` + `R3-15`) | — | — | — | pending |
| `R3-12` | `r3-12-fp-matrix` | QUEUED (after `R3-01` + `R3-09`) | — | — | — | pending |
| `R3-13` | `r3-13-oracle-spec` | QUEUED (Wave 3: after `R3-02`/`R3-04`/`R3-05`/`R3-12`) | — | — | — | pending |
| `R3-14` | `r3-14-typed-retry` | QUEUED (after `R3-09`) | — | — | — | pending |
| `R3-16` | `r3-16-custody-nonce` | QUEUED (Wave 3: after `R3-02`/`R3-05`/`R3-13`) | — | — | — | pending |
| `R3-17` | `r3-17-kernel-stages` | QUEUED (Wave 3: after `R3-05`/`R3-12`/`R3-13`) | — | — | — | pending |
| `R3-18` | `r3-18-run-activity` | QUEUED (after `R3-03`) | — | — | — | pending |
| `R3-19` | `r3-19-typed-kernel` | QUEUED (after `R3-02`/`R3-05`/`R3-11`) | — | — | — | pending |
| `R3-20` | `r3-20-lifecycle` | QUEUED (Wave 3: after `R3-07` + `R3-18`) | — | — | — | pending |

