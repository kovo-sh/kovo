# Claude systemic quality audit — ranked improvements

> Status: **PROPOSED — awaiting reviewer triage.** Author: Claude Code (Opus 5.5), 2026-11-25, `main` @ `09a5126`.

> Read-only audit: no code edited, no benchmarks run. Impact estimates rely on numbers already recorded in `plans/ROADMAP-v5.md`, `VERIFICATION-v5.md`, `plans/CONVERSION-AUTOPSY.md`, `plans/SPEC-SUBMISSION.md`, `plans/HANDOVER-SWARM.md`, not fresh measurement.

## Method

- 8 independent read-only finders, each with one lens: recall funnel, precision/oracles, benchmark overfitting, measurement validity, architecture debt, agent loop, state isolation/silent failure, regression churn/gate efficacy → **67 raw issues**.
- Clustered into **12 systemic themes** (shared root causes, not one-off bugs); the ranking pass split one theme, giving **13 ranked items**.
- Each theme reviewed by **2 adversarial skeptics** (evidence-accuracy lens; is-it-systemic/impact lens). No theme was fully refuted; ~a dozen overstated sub-claims were dropped or narrowed (listed in *Verification notes*).
- A final ranking pass applied the corrections, scored each item (impact × leverage) / effort (S=1, M=2, L=3) weighted by confidence, and treated precision/safety invariants as non-negotiable.
- Spot-checked on `main` by the coordinator after the run: wordlist default ON (`scripts/benchmark-realistic.ts:416`), smoke `liftBaseline` default 0 + `Math.max(0, …)` clamp (`scripts/smoke-agentic.ts:329,815`), empty-matrix precision 1 (`scripts/benchmark-agentic-matrix.ts:679`), dual `settlementTurn` (`exec-dispatch.ts:3079` vs `agent-session.ts:3072`), non-enum `cannot_build_spec` advertised (`agent-session.ts:2340`, `exec-recon-planner.ts:3185`), `strictRunScope: false` (`persona-auth.ts:1297`), every chain-step exit marked `complete` (`exec-worker-runner.ts:583,600,614,2014`), fixture secret grammar in `deterministic-specs.ts:1327` / `probes/authz.ts:181`.

Line numbers are as of `09a5126`; re-`grep` before editing.

## Summary table

| # | id | Improvement | Impact | Leverage | Effort | Confidence | Depends on |
|---|---|---|---|---|---|---|---|
| 1 | `fail-closed-measurement-quickwins` | Make benchmark scoring fail closed and turn off fixture-route inflation in every reporting path | 4 | 5 | S | high | — |
| 2 | `versioned-results-ledger-heldout-hygiene` | Commit a versioned results ledger (benchmarkVersion and EffectiveConfig hash) and restore a real held-out split | 4 | 4 | M | high | `fail-closed-measurement-quickwins` |
| 3 | `blocking-behavioral-merge-gate` | Run the fast suite and a dev regression floor before merging, and require a Contract-change trailer for edits to tunables and assertion literals | 4 | 5 | M | high | `fail-closed-measurement-quickwins` |
| 4 | `confirmation-path-parity-corpus` | Run recorded TP/FP transcripts through every confirmation entry point under label permutations, then close the per-path guard gaps | 4 | 5 | M | high | `blocking-behavioral-merge-gate` |
| 5 | `typed-terminal-outcomes-and-loss-accounting` | Give chain steps, sessions and floor hypotheses typed terminal states, and account for capped or lost work per (route, class) | 4 | 5 | M | high | `fail-closed-measurement-quickwins` |
| 6 | `agent-contract-single-source` | Derive every number, tool and gap code the agent sees from the code that enforces it | 3 | 4 | S | high | — |
| 7 | `unify-floor-policy-across-modes` | Run the same deterministic floor in --no-llm and agentic modes, and report the agentic increment against that run's own floor | 4 | 3 | S | medium | `fail-closed-measurement-quickwins`, `versioned-results-ledger-heldout-hygiene` |
| 8 | `effective-config-and-shipped-parity` | Measure the configuration that actually ships: an EffectiveConfig fingerprint, a re-routed no-profile floor, required provenance, a production-shaped bench cell, and a product inner loop | 4 | 4 | M | high | `versioned-results-ledger-heldout-hygiene` |
| 9 | `fixture-leak-barrier-and-novel-vocab-cell` | Mechanically keep benchmark fixture vocabulary, canary grammar and VFS paths out of src/server, and gate on a novel-vocabulary cell | 4 | 4 | M | high | `fail-closed-measurement-quickwins`, `versioned-results-ledger-heldout-hygiene` |
| 10 | `typed-persona-and-step-semantics` | Store persona tenant/privilege and step routing metadata as typed fields instead of re-deriving them from labels and prose | 4 | 4 | M | medium | `confirmation-path-parity-corpus` |
| 11 | `composition-manifest-and-unwired-ratchet` | Add a capability-manifest snapshot, an unused-export and cycle ratchet, and pulse state derived from git | 3 | 4 | M | high | `blocking-behavioral-merge-gate` |
| 12 | `single-class-taxonomy-contract` | Collapse the drifting class, CWE and role tables into one data contract, and add a conformance test first | 3 | 4 | L | medium | `confirmation-path-parity-corpus`, `versioned-results-ledger-heldout-hygiene` |
| 13 | `scope-isolation-invariants` | Make run and persona scope required, give per-run state an owner, and require a finally-guarded restore for mutating recipes | 3 | 4 | L | medium | `fail-closed-measurement-quickwins` |

## Ranking rationale

Each item is scored as (impact × leverage) / effort (S=1, M=2, L=3), weighted by confidence. Measurement validity goes first because every other item is steered by benchmark numbers that are not trustworthy yet. The default-on wordlist alone adds about 15pp to dev recall. Smoke and matrix gates treat missing input as a pass. Held-out is a single autopsied seed whose fixtures were edited during triage. No scorecard records a version.

1. Fail-closed scoring plus wordlist OFF (S, 4×5): cheapest, highest leverage, and only tightens.
2. The versioned ledger and held-out hygiene: makes later comparisons valid.
3. A blocking behavioral merge gate: stops the restore/realign cycle and catches tunable changes that slip in unmeasured.
4. The path-parity transcript corpus: the precision guardrail. It has to exist before any verifier, taxonomy or semantics change, because those touch the non-negotiable precision invariants. It can be built in parallel with items 1-3.
5. Typed terminal outcomes and loss accounting (4×5, staged M): high leverage, but its value depends on trustworthy measurement.
6. The agent contract fix: S effort, confirmed defects, so it ranks high even though its lift impact is unproven.
7. The floor-policy A/B: S, but medium confidence that it explains the zero lift.
8-10. Config/shipped parity, fixture-leak removal and typed persona/step semantics: M items with impact 4. Ranked lower because they depend on the ledger or the parity corpus, and because fixture or semantics changes can move precision.
11-13. Process tooling, taxonomy consolidation and scope isolation: real and systemic, but either L effort, or their current failures are mostly fail-closed recall or maintainability losses rather than measurement or precision breaks. Each has an S first step. The redaction-cap fail-closed change in item 13 is a safety invariant and should ship early on its own.

Verdict corrections applied:
- Dropped these claims: '13/14 pools', '28 tests', 'traversal/XXE structurally dead', '5 boolean implementations', '3 stub detectors', 'opsportal stuck at 87.5%', 'replay-verifier 0 LOC', '2 wrong-tenant confirmations', '153/270 caused by prose routing', autopsy fix #2 open, and kovo_verify 'one of several backends'.
- Narrowed these: floor truncation is visible in aggregate counters; retry is ad hoc, not absent; matrix failures exit non-zero; strict receipts mostly backstop upstream fail-open paths.
- Rejected these proposed fixes: shrinking local-lab gating, having the grader import the product taxonomy, a blanket catch lint, and host auto-submit. All of them threaten precision, safety or measurement independence.

---

## 1. Make benchmark scoring fail closed and turn off fixture-route inflation in every reporting path

`id: fail-closed-measurement-quickwins` · impact 4/5 · leverage 5/5 · effort S · confidence high · depends on: —

**Problem.** Measurement code treats missing or failed inputs as passing. A failed matrix cell adds 0 targets, so the denominator shrinks. An empty cell reports precision 1. The smoke net-new gate compares against a baseline of 0 behind a Math.max clamp, and sites count as 'preserved' even when unconfirmed. A product finding with no CWE becomes a wildcard that matches by endpoint only, and its params are widened to the whole inventory. The local-lab-only conventional route wordlist is on by default in every certify and hillclimb path, and that alone adds about 15pp to dev recall. Every capability decision downstream is steered by these numbers.

**Verified evidence.**

- scripts/benchmark-realistic.ts:416 sets conventionalWordlist ON unless --no-conventional-wordlist is passed. certify-phase1.ts:2065-2085,2181 builds floor-dev and floor-heldout cells without that flag. ROADMAP-v5.md:264-277 measured 35/59 with it on vs 26/59 with it off, and :270 had already accepted 'Benchmarks turn noun wordlists OFF'.
- scripts/smoke-agentic.ts:329,348,815: liftBaseline defaults to 0 and netNew=Math.max(0,...), so the gate cannot fail. Lines 735-741 credit preserved sites that never confirmed. VERIFICATION-v5.md:33 records a Queue #14 'PASS' measured against that empty baseline.
- scripts/benchmark-agentic-matrix.ts:679 returns precision 1 when tp+fp=0. benchmark-realistic-matrix.ts:188,197 give a failed cell targets 0, so the printed recall line shrinks its denominator, although the exit code is non-zero.
- benchmarks/realistic-bench/grader/match.ts:66-67 treats a finding with no class and no CWE as compatible. scripts/benchmark-realistic.ts:993-998 adds every inventory param of every matched endpoint row.
- scripts/benchmark-score.ts:97-119 matches classes with unanchored regexes (graphql maps to sqli/authz, csrf to sqli/authz/xss). benchmark-core.ts:167-170 counts only confirmed decoys as FP. These back the xben-25 and held-out-saas '0 FP' gates.

**Observed symptoms.** A '+9pp' floor win was later reclassified as wordlist inflation. A smoke lift PASS was recorded against a vacuous baseline. Recall lines are copied out of logs from runs where a cell failed. Legacy 100%-precision gates cannot see off-manifest over-claims.

**Systematic improvement.**

Ship a set of small, strictly-tightening changes to the measurement layer.
(a) Default the conventional wordlist to OFF in scripts/benchmark-realistic.ts and make it opt-in. Any scorecard with wordlistOn=true is stamped non-reportable.
(b) If any cell failed, the matrix aggregate prints INVALID with no recall line. Empty precision is null, never 1.
(c) Smoke lift requires an explicit --lift-baseline or a pinned floor scorecard, and reports UNMEASURED otherwise. Remove the clamp. 'Preserved' requires outcome==='confirmed'. Pick the rotation app from the seed or SHA instead of the day of year. runLiftCellTwice reports both runs and gates on the worse one.
(d) The product translation carries vulnClass from the verifying spec's probe class and params from the mutated input. A finding with no class and no CWE counts as unmatched.
(e) Anchor the legacy classCompat and drop the csrf->sqli/authz/xss and graphql->authz rows. Report unmatched over-claims next to decoy FPs.

**First PR-sized steps.**

1. scripts/benchmark-realistic.ts:416,538: invert conventionalWordlist to opt-in via --conventional-wordlist, and write wordlistOn into the scorecard JSON.
2. scripts/benchmark-realistic-matrix.ts and scripts/benchmark-agentic-matrix.ts summarizeMatrix: when failed>0, emit recall:null and status:'INVALID'. Return precision null when tp+fp===0.
3. scripts/smoke-agentic.ts: require --lift-baseline (or read a pinned floor scorecard path), remove Math.max at line 815, filter preservedSiteIds on confirmed, and derive rotateSecondApp from the seed.
4. scripts/benchmark-realistic.ts translateFindings (around 993-1027): set vulnClass from the spec, use only the spec's mutated params, and mark findings with no CWE and no class unmatched_classless.
5. scripts/benchmark-score.ts:97-119: anchor the patterns, remove the cross-family rows, and add unmatchedConfirmed to the output of benchmark-core.ts countFalsePositives. Re-baseline xben-25 once and note it in benchmarks/CHANGELOG.md.

**Success metric.** Every reported dev, held-out and xben number comes from a wordlist-OFF, all-cells-valid run. No gate can return PASS when its baseline is missing. Re-baselined numbers are recorded once, and later comparisons use only post-change scorecards.

**Risks / invariants to preserve.** Reported recall drops (dev by about 9 targets from the wordlist alone) and xben may show unmatched FPs. Re-baseline once, explicitly, so the drop is not read as an engine regression. Every change only makes measurement stricter, so verifier precision invariants are untouched. The product's real-target behavior does not change, because the wordlist is already local-lab-only (exec-floor-lane.ts:912).

---

## 2. Commit a versioned results ledger (benchmarkVersion and EffectiveConfig hash) and restore a real held-out split

`id: versioned-results-ledger-heldout-hygiene` · impact 4/5 · leverage 4/5 · effort M · confidence high · depends on: `fail-closed-measurement-quickwins`

**Problem.** Certified numbers are kept in hand-edited prose that points at /tmp artifacts. Tables mix SHAs and configurations, and no scorecard records a fixture, grader or config version. Realistic-bench held-out has shrunk to one salted seed, 1000042. That seed was autopsied target by target, used to tune product constants, and its fixtures were edited during FP triage. Its '100% precision' certificate depends partly on those benchmark edits. Because nothing separates the data used to tune from the data used to certify, the gate numbers are effectively dev-tier evidence.

**Verified evidence.**

- grep benchmarkVersion|suiteVersion|fixtureHash over src, scripts and benchmarks finds 0 hits. No results ledger is committed.
- VERIFICATION-v5.md:30-34: the dev floor is 37/59, but the per-app denominators (22+19+17) sum to 58. Floor rows (aca8262) and agentic rows (4010d05) come from different SHAs.
- benchmarks/CHANGELOG.md:9-14 shows shopflow hardenings on held-out seed 1000042 credited with 'precision 81.8% -> 100%'. git f86757c then flips the held-out worst-run precision row from FAIL to PASS on the same cell.
- src/server/exec-dispatch.ts:2789-2791: the turn cap went from 12 to 18 because '14 of 19 held-out no_spec_submitted targets hit the turn cap'. plans/HELDOUT-LIFT.md autopsies seed 1000042 target by target.
- benchmarks/realistic-bench/generator/materialize.ts:62-72 and variant.ts:18-20 build held-out from the same site code and the same committed vocab pools. scripts/benchmark-agentic-matrix.ts:16,760 defaults to --seeds 1,1000042.
- plans/ROADMAP-v5.md:277 vs :1041: the dev/held-out gap went from 6.2pp to 12.7pp, which breaches the <=10pp gate at :266.

**Observed symptoms.** Certificate errata (the 26 vs 28/58 held-out discussion). Lift claims later reclassified as noise (ROADMAP-v5.md:840). A widening dev/held-out gap. Fixture edits that make before/after numbers silently incomparable.

**Systematic improvement.**

1. Add an append-only JSONL ledger, benchmarks/results/ledger.jsonl. Each row records sha, a dirty flag, an EffectiveConfig hash (every behavior-changing KOVO_* var plus deterministicOnly, environment, approvalPolicy and wordlist), benchmarkVersion, seed, repeat, a per-site outcome vector, and the raw pre-adjudication precision. benchmarkVersion is a content hash of the apps, truth, grader and lib directories.
2. Generate the VERIFICATION-v5 and ROADMAP metric tables from the ledger, and have compare/certify refuse to compare rows across versions or config hashes.
3. Burn seed 1000042 into dev-2. Certify on 3 or more freshly drawn salted seeds per certification, reporting aggregates only.
4. Report raw (pre-adjudication) precision as the headline. A valid_unplanted side column is allowed only with serial-replay evidence.
5. Any diff under apps, truth or grader needs a CHANGELOG row naming the triggering run and bucket, and must bump benchmarkVersion.

**First PR-sized steps.**

1. Add scripts/bench-ledger.ts: computeBenchmarkVersion() hashes benchmarks/realistic-bench/{apps,truth,grader,lib}, and computeEffectiveConfig() covers the KOVO_* set. Call both from the writeScorecard paths in scripts/benchmark-realistic.ts, benchmark-agentic-matrix.ts and benchmark-realistic-matrix.ts, and append rows to benchmarks/results/ledger.jsonl.
2. Add scripts/render-verification-tables.ts. It regenerates the metric tables in VERIFICATION-v5.md from the ledger and fails on mixed benchmarkVersion or config hashes inside one table.
3. Change the default --seeds in scripts/benchmark-agentic-matrix.ts and scripts/certify-phase1.ts buildRunPlan to draw 3 fresh salted seeds from listSeeds. Add a committed burn list, benchmarks/realistic-bench/BURNED_SEEDS, starting with 1000042, and make certify reject burned seeds.
4. Add rawPrecision, plus a validUnplanted column that requires replay evidence, to benchmarks/realistic-bench/grader/score.ts. Keep strictPrecision as the gate.
5. Add a check to scripts/worker-gate.sh: a diff under benchmarks/**/{apps,truth,grader} requires a new benchmarks/CHANGELOG.md row and a changed benchmarkVersion.

**Success metric.** Every number in VERIFICATION and ROADMAP traces to a ledger row with a SHA, a config hash and a benchmarkVersion. Certification cites only fresh, unburned seeds (n>=3, with spread reported). There are no hand-copied /tmp references.

**Risks / invariants to preserve.** Rotating seeds and demoting 1000042 will probably lower held-out numbers and break current V7.2 PASS rows, so the roadmap has to accept a metric discontinuity. Agentic n>=3 costs roughly 3x per certification, so keep n=1 in the smoke tier and label it non-certifying. Do NOT make the grader import product taxonomy. A valid_unplanted column must never feed the headline precision, or it becomes a new adjudication loophole.

---

## 3. Run the fast suite and a dev regression floor before merging, and require a Contract-change trailer for edits to tunables and assertion literals

`id: blocking-behavioral-merge-gate` · impact 4/5 · leverage 5/5 · effort M · confidence high · depends on: `fail-closed-measurement-quickwins`

**Problem.** The only pre-merge check is worker-gate.sh. It runs a hand-picked list of 4 contract suites and 2 invariants, and does not exercise the precision kernel (oracle-invariants, proof-receipt, composite-receipt, floor-recipe-engine). CI runs after a local merge to main, so it cannot block anything. About 340 test files run only through an optional runner that nothing calls. Suites are left red and later 'realigned' in bulk. That realignment has baked in unmeasured budget changes, for example a gate literal edited in the same commit that raised a benchmark budget.

**Verified evidence.**

- scripts/worker-gate.sh:40-83 runs typecheck, the v8 lint, two grep-gated invariant suites, 4 fixed contract suites (v4-m7-orch, v5-m1, v5-m2, sys-contract-canary), and the slice only when --app is passed. package.json has no `test` script. .github/workflows/verify.yml runs test:boundaries (6 files).
- scripts/parallel-pulse.sh:110 says to 'merge it, run worker-gate, push'. The gate runs after the merge, and run-fast-tests.sh (which globs tests/) is called by no gate, CI job or AGENTS.md rule.
- 5b77b1c raised BENCH_MAX_REQUESTS_DEFAULT from 3800 to 6000 (scripts/benchmark-core.ts) and edited the gate suite tests/v4-m7-orch.test.ts literal, in a commit titled 'restore held-out-saas 20/20'.
- cbc87dd cut the Phase A floor cap with an empty commit body. 91898cc then realigned assertions from 168_000 to 72_000 inside the '28 drifted test suites updated; fast suite ~97% green' merge (7b94d08).
- src/server/exec-dispatch.ts:2424: planRoundRobinDispatch has no production caller and skips the frontierController branch. 13 test files use it, including the gate's v7-dispatch-funnel invariant.
- plans/CLAUDE_AUDIT.md:718-735 (M-34/M-35) already flagged orphaned tests and the narrow gate with the same fix. It was never adopted.

**Observed symptoms.** About 66 restore/regress/erratum commits. Several 'make CI green' merges a day. A steady state of roughly 97% green fast suite. The golden E2E was red for about 8 hours (25d409c). Engine-port regressions were caught only partly.

**Systematic improvement.**

1. Make worker-gate.sh run the run-fast-tests.sh suite set before merging. Keep a checked-in quarantine file (tests/QUARANTINE.json) with an owner, an expiry and a size cap, seeded with today's failures rather than bulk-realigning them. Add an orphan check that fails when a tests/*.test.ts file is neither in the glob nor excluded.
2. Add an in-process dev regression floor: xben-25, held-out-saas --no-llm and golden e2e, diffed against a committed baseline scorecard. A lost TP or a gained FP fails the gate. Run it once per merge.
3. Add a diff lint. A commit that changes numeric literals in assert.* lines of gate or kernel suites, or exported *_DEFAULT, *_BUDGET or *_MS constants in src/server or scripts/benchmark-core.ts, must carry a 'Contract-change:' trailer and an A/B ledger reference.
4. Swap the pulse order to gate, then merge, then push.
5. Add a nightly Docker tier under umask 0077 and uid 10001, starting from v8-docker-perms and v8-repos-eacces.
6. Port the funnel-invariant tests to FrontierDispatcher with a controller, then delete planRoundRobinDispatch.

**First PR-sized steps.**

1. scripts/worker-gate.sh: call scripts/run-fast-tests.sh with --quarantine tests/QUARANTINE.json, and add the orphan check (the M-35 recommendation).
2. Create tests/QUARANTINE.json from the current failing set, with owner, expiry and a cap enforced by a small validator script.
3. Add scripts/regression-floor.sh. It runs xben-25, held-out-saas --no-llm and tests/v8-seam1-golden-e2e.test.ts, then diffs against benchmarks/baselines/floor.json, using the ledger from the previous item.
4. Add scripts/check-contract-change.ts, invoked by worker-gate. It parses git diff for changed numeric literals in assert lines and in *_DEFAULT, *_BUDGET and *_MS exports, and requires the trailer.
5. Edit scripts/parallel-pulse.sh:110 and AGENTS.md so the gate runs before the merge. Port tests/v7-dispatch-funnel to FrontierDispatcher.dispatch.

**Success metric.** No merge to main with a non-quarantined red suite. The quarantine list shrinks every week. Restore/realign commits drop from about 8 per 150 commits to under 2. Every tunable change carries an A/B reference.

**Risks / invariants to preserve.** A blocking full-suite gate on a suite that is about 97% green will stall merges, or the quarantine will fill up. Cap its size and require expiries. Never bulk-realign kernel suites (oracle, receipt, confirm-consistency) to make the gate green. Their changes need the Contract-change trailer. Do NOT run the salted held-out split per merge, because that turns it into dev data.

---

## 4. Run recorded TP/FP transcripts through every confirmation entry point under label permutations, then close the per-path guard gaps

`id: confirmation-path-parity-corpus` · impact 4/5 · leverage 5/5 · effort M · confidence high · depends on: `blocking-behavioral-merge-gate`

**Problem.** Several live confirmation entry points apply different subsets of the same guards under different preconditions: replay-verifier with the strict receipt, verify-claims, the floor recipe engine, and the composite/v8 path. Fixes land in the shared assessor and get unit tests there, while a caller drops the result. Every cut and every tightening has been followed by a 'restore' commit, which only a full matrix catches. The Tier-0 FP corpus calls assessors directly with a class chosen in advance, so routing defects are never exercised. The strict receipt default (b4a7287) backstops most of these paths, so the main cost today is precision/recall oscillation and slow feedback, plus a few remaining fail-open seams.

**Verified evidence.**

- src/server/replay-verifier.ts:508 enforces proofStrength only when claim==='authorization' (spot-checked on a6d66b9). The 'universal status-only ban' from 31a3e2a therefore never takes effect in that caller. tests/v7-status-diff-guard.test.ts:391 tests the assessor, not verifyReplaySpec.
- src/server/verify-claims.ts:1784,1796,1848 and floor-recipes.ts:1610-1623 call matchInjectionFingerprint on unstripped text with no family argument. The kernel applies stripRequestEchoes (oracle-invariants.ts:2900) and binds the family.
- src/server/verify-claims.ts:1808 skips class gates for 'other'. In this path the class comes from regexes over the model-written title and description (verify-runner.ts:469-481, oracle-invariants.ts:561-562).
- scripts/smoke-agentic.ts:455-500 evaluateArchetype calls assess* functions with a class fixed in advance. The 'anon-control-authz' and 'error-status-only-injection' archetypes requested in AGENT-FP-TRIAGE.md section 4 appear nowhere in the repo.
- Restore pattern: 4375eb8 -> e939298 (XSS browser_sink regression), ecc0cae, 19a6fdd, 4f65e31 'Floor restored 31/59'. ROADMAP-v5.md:799 notes that only re-measuring after each verifier merge catches these.
- src/server/floor-recipe-engine.ts:3737-3739 lets four host-persisted spec kinds (cache_differential, auth_protocol_proof, upload_probe, ws_chain) confirm without a ProofReceipt.

**Observed symptoms.** Precision and recall oscillate after each verifier cut (held-out BFLA, xben 18/20, golden chains). Tier-0 reports 11/11 while routing FPs have shipped. The legacy http_chain VM was moved into floor-recipe-engine.ts instead of deleted.

**Systematic improvement.**

1. Build tests/parity/ as recorded transcripts (host exchanges plus a claim envelope), with a TP side and an FP side. Seed it from AGENT-FP-TRIAGE rulings and the xben and held-out-saas confirmations.
2. Write one harness that feeds each case through verifyReplaySpec with the strict receipt, the floor recipe path, verify-runner/evaluateClaims together with the exec-verify persistence invariant, and the composite receipt.
3. Permute labels: canonical class, 'other', CWE-20, CWE-only, and free-text title. Assert identical verdicts. Block a merge on any lost TP or gained FP.
4. With that harness in place, make the cheap fixes, each tested through the real entry point:
   - Enforce proofStrength for all claims at replay-verifier.ts:508.
   - Remove the duplicate impactGate veto at :648.
   - Route the verify-claims and floor-recipe fingerprint matches through stripRequestEchoes and the family binding.
   - Wire the isJobOrHandleStub guard into the receipt and floor paths.
   - Make the receipt-exempt kinds an explicit, tested list.
   - Refuse KOVO_PROOF_RECEIPT=off/shadow outside test builds.
5. Gate each LEGACY_UNWIRED graduation (floor-recipes.ts:2139-2192) on a verdict diff from this harness.

**First PR-sized steps.**

1. Create tests/parity/corpus/*.json in the recorded-exchange and claim-envelope format, plus tests/path-parity.test.ts. The harness calls verifyReplaySpec, the recipe engine's receiptCheckForResult, evaluateClaims and verifyCompositeReceipt.
2. Add the two missing archetypes (anon-control authz, error-status-only injection) as transcript cases with label permutations.
3. Fix src/server/replay-verifier.ts:508 to enforce proofStrength.satisfied for every claim class, and add a verifyReplaySpec-level test. Run the regression floor before merging.
4. Change verify-claims.ts:1784/1796/1848 and floor-recipes.ts:1617 to call the kernel's stripped, family-bound fingerprint helper.
5. In src/server/proof-receipt.ts:3468-3473, reject the 'off' and 'shadow' modes unless NODE_ENV==='test', and add the receipt mode to the EffectiveConfig hash.

**Success metric.** The parity suite runs in worker-gate in under 2 minutes. Zero verdict disagreements across entry points and permutations. No 'restore' commit is needed after verifier merges for two consecutive batches.

**Risks / invariants to preserve.** Enforcing proofStrength for non-authz claims and stripping echoes in verify-claims will demote some current confirmations. Measure them with the parity corpus and the dev regression floor before merging, and accept genuine demotions as precision gains. Do not delete the upstream path guards in favor of the receipt alone until the parity diff shows the receipt covers everything they catch (R2-C-9 vault-scrubbed reflection is one risk). Strict-receipt fail-closed behavior must stay the default.

---

## 5. Give chain steps, sessions and floor hypotheses typed terminal states, and account for capped or lost work per (route, class)

`id: typed-terminal-outcomes-and-loss-accounting` · impact 4/5 · leverage 5/5 · effort M · confidence high · depends on: `fail-closed-measurement-quickwins`

**Problem.** There is no typed state for work that was formed or attempted but not finished. The four worker-runner sites set a chain step to 'complete' for every exit: stalled after retry, rotated, generic failure, turn_limit and nudged_out. Coverage treats any complete or assigned step as covered and reads routes out of step prose. Floor caps and deadline cuts appear only as aggregate counters. Planner parse failures are swallowed. The grader has no dispatch or verify stage. So admission, re-queueing and grading cannot tell lost work from a real negative.

**Verified evidence.**

- src/server/exec-worker-runner.ts:583,600,614,2012-2015 call updateChainStep({status:'complete'}) for stall-after-retry, pre-session rotation, generic failure, and every post-session status (turn_limit, nudged_out, wall_clock_rotated). src/server/schema.ts:164 has no failed, partial or capped step status.
- src/server/exec-recon-planner.ts:2797-2798 passOneCoverage counts assigned/complete/running as dispatched. Lines 2775-2777 stepMentionedRoutes takes routes from title and hypothesis text. Lines 2833-2840 run the top-up with listEndpoints limit 80 and exclude confirmed routes by path only, ignoring class.
- src/server/exec-recon-planner.ts:4548 has `catch { parsedPlanner = null }`. grep for parse_failed, invalid_json or parseFailed in src/server returns 0 hits.
- src/server/deterministic-engine.ts:5033 breaks on the deadline and 5037-5038 skips over-cap hypotheses with `continue`. baseQuotas (2532-2537) and intentCaps (4975-4993) disagree (xxe 5/4, race 8/6, ssrf 7/6, auth_protocol 2/3). Only aggregate hypothesesFormed/Run are emitted (exec-floor-lane.ts:1096-1108).
- benchmarks/realistic-bench/grader/attribution.ts:64-77 has no never_dispatched, route_hit_no_verify or capped_out bucket and falls through to replay_spec_miss. 9b7ee20 deleted scripts/conversion-autopsy.ts. plans/CONVERSION-AUTOPSY.md:74-81 counts 15/52 never_dispatched and 24/52 route_hit_no_verify.

**Observed symptoms.** Agentic lift has been about +0 across cycles (36/59 floor vs 36/59 unified, HANDOVER-SWARM.md:24). Every loss bucket had to be found by manual autopsy. kovo_verify produced no receipts for a long stretch and no metric showed it.

**Systematic improvement.**

Stage it on top of existing keys and counters. Do not add a parallel store.
(1) Add step and session terminal statuses: infra_failed, turn_capped, nudged_out, rotated_partial and model_failure. The scheduler treats them as terminal for no-ready-work checks. passOneCoverage counts only proved and gap_coded as covered. Retryable states are re-queued once per (route, class), charged against dynamicStepBudget, the wall clock and RunSafetyBudgets.
(2) Emit capped_out {cap, stage, class, kept, dropped} from the engine at the intentCaps `continue` and at the deadline break, by extending deterministic_engine.summary. Persist the unprobed tail as det_leads, and merge baseQuotas and intentCaps into one table.
(3) Make the coverage key (origin, METHOD, route, class) from structured route binding set at step creation. Delete stepMentionedRoutes as the coverage source in the same PR, and key the confirmed-exclusion check by class.
(4) Emit planner_parse_failed and persona_resolve_failed degradation events, and add a run validity check for critical degradations, replacing isInertAgenticRun (scripts/benchmark-realistic.ts:1313-1323).
(5) Rebuild the never_dispatched, route_hit_no_verify, verify_rejected and capped_out buckets in attribution.ts from product events.

**First PR-sized steps.**

1. src/server/schema.ts:164: add the new step statuses, and update src/server/exec-worker-runner.ts:583,600,614,2014 to set the right status from sessionResult.status.
2. src/server/exec-recon-planner.ts:2797-2798: treat only complete-with-outcome (proved or gap_coded) as covered. Add a single bounded requeue for turn_capped and nudged_out steps, keyed by reinvestigationKey.
3. src/server/deterministic-engine.ts:5033,5038: collect a per-class unprobed tail into the report. In exec-floor-lane.ts:1096-1108, add byClassUnprobed to the summary, and persist the tail as det_lead facts.
4. src/server/exec-recon-planner.ts:4548 and src/server/execution.ts:1950-1957: emit typed degradation events. scripts/benchmark-realistic.ts: mark a cell INVALID on persona_resolve_failed, or on zero kovo_verify attempts in agentic mode.
5. benchmarks/realistic-bench/grader/attribution.ts: add dispatch and verify stage buckets that consume the new product events.

**Success metric.** Per-cell funnel output itemizes every target as proved, gap_coded, capped_out, infra_failed, never_dispatched or route_hit_no_verify, with no fallthrough to replay_spec_miss. A turn-capped step is retried at most once. Wall-clock and request totals do not regress at the smoke tier.

**Risks / invariants to preserve.** Re-queueing can bring back duplicate-trial churn (287 turns, CONVERSION-AUTOPSY.md:236). Cap it at one retry per key, inside existing budgets, and never relax RunSafetyBudgets. Keep the sqli-last ordering, because the 5xx breaker depends on it, or replace it with per-class reserved slots. This makes losses visible and recoverable. It is not the main lift fix, because the dominant miss bucket is agents hitting the route without submitting a proof. No change touches verify-before-persist or the oracle path, and re-queued work keeps the same scope, tier and staging gates.

---

## 6. Derive every number, tool and gap code the agent sees from the code that enforces it

`id: agent-contract-single-source` · impact 3/5 · leverage 4/5 · effort S · confidence high · depends on: —

**Problem.** The worker is told contradictory budgets. Prompt text says '8-10 turns' while dispatch gives 18-34. Settlement starts at 0.85N in the session, but dispatch computes an N-2 settlementTurn that nothing reads. Wall-clock settlement is computed twice with different formulas. Prompts advertise a gap code ('cannot_build_spec') that the parser rejects, which blocks early exit for a model that follows the host's own advice. Rejection messages tell the model to probe after probing tools have been revoked. A live network tool (crawl_state_graph) is in no category set, and settlement uses a denylist, so new network tools fail open into settlement. Proof conversion is the dominant miss bucket, so contract drift spends the scarce turns.

**Verified evidence.**

- src/server/exec-dispatch.ts:3079,3098,3114 compute settlementTurn=maxTurns-2, and nothing in src reads it. src/server/agent-session.ts:3072 recomputes floor(0.85*maxTurns) (spot-checked on a6d66b9).
- src/server/agent-prompts.ts:1655 (buildAgenticPromptContext) tells workers '8-10 turns; 6-8 turns for det_lead upgrades', while exec-dispatch.ts:2791 sets SINGLE_STEP_ASSIGNMENT_MAX_TURNS=18 and chain budgets of 20-34.
- src/server/agent-session.ts:2340 and exec-recon-planner.ts:3185 advertise proofGapReason 'cannot_build_spec', which is not in SPEC_PROOF_GAP_CODES or the aliases (agent-prompts.ts:196-231). An uncoded gap blocks early exit (agent-session.ts:3158).
- src/server/agent-prompts.ts:693-710: the gap-rejection message says to 'probe the route', but it usually fires after SETTLEMENT_REVOKED_TOOLS has revoked probing. It also says a repeated unsupported gap will not block again.
- src/server/agent-session.ts:326-356,1624: crawl_state_graph is in neither SETTLEMENT_REVOKED_TOOLS nor ROUTE_EVIDENCE_TOOLS. 'requestHttpRace' is a handler key listed as a tool.
- src/server/exec-worker-runner.ts:1844-1845 vs agent-session.ts:3028-3030 compute wall-clock settlement with two different formulas.

**Observed symptoms.** Repair turns are wasted on blocked tools. 15/19 held-out misses were cap-truncated and 7 of 12 were mid-repair (plans/SPEC-SUBMISSION.md:70-77). Agent-session churn tunes one rule after another.

**Systematic improvement.**

1. Finish the existing AssignmentBudget instead of adding a new object. runAgentSession consumes budget.settlementTurn and the wall-clock settlement value. Delete the 0.85 recomputes, the legacy AGENTIC_SPECIALIST_MAX_TURNS and resolveAgenticTurnBudget, and the hard-coded '8-10 turns' string. Render all prompt numbers from the budget.
2. Add one tool metadata table (network, routeEvidence, proofSubmission, settlementPhase). Derive the settlement, route-evidence, wrap-up and banner sets from it, and turn settlement gating into an allowlist so new network tools fail closed. Make gap codes an enum.
3. Add a static contract test. It extracts every proofGapReason literal and tool name from the prompt and rejection builders, and asserts that each code parses and each named tool is callable in the phase where the message is emitted. Add an exhaustiveness test that every defineTool is categorized.
4. Add host-side alias-usage counters for kovo_verify args before any further alias pruning.
5. Start a small structured trace-replay corpus from the 19 SPEC-SUBMISSION targets' tool-call sequences, run offline against the settlement and obligation state machine. This is the VCR gate ROADMAP-v5.md:253,258 already accepted.

**First PR-sized steps.**

1. src/server/exec-worker-runner.ts:1898: pass the whole AssignmentBudget into runAgentSession. Replace agent-session.ts:3072 and 3028-3030 with budget fields, and drop settlementNudgeAtTurn or make it truthful.
2. src/server/agent-prompts.ts:1655: render turnBudget from the budget, and delete AGENTIC_SPECIALIST_MAX_TURNS and its use at execution.ts:2740.
3. Fix the 'cannot_build_spec' advertisements at src/server/agent-session.ts:2340 and exec-recon-planner.ts:3185, either by adding the code to SPEC_PROOF_GAP_CODES or by switching to a canonical code. In agent-prompts.ts:693-710, point repairs at tools that are allowed in settlement.
4. Add src/server/agent-tool-registry.ts (a metadata table) and derive the sets at agent-session.ts:326-356 from it. Add tests/agent-contract.test.ts with the literal-extraction and exhaustiveness checks.
5. Add alias-hit counters in the host verify-runner and emit them in the run summary.

**Success metric.** The contract test passes, and every number in the rendered prompt equals the enforced threshold for every budget class. Zero uncategorized tools. Repair turns spent on tools blocked in the current phase fall to 0. Measure verify_called and confirmed on the smoke tier, and on n>=3 seeds at batch end.

**Risks / invariants to preserve.** An allowlist for settlement could block a tool that has a legitimate use during settlement, so derive the initial allowlist from current behavior. Do NOT add host auto-submit of canonical proofs in this item. SPEC-SUBMISSION.md:113 shows more submissions brought a new FP, and 0297400 just tightened live-target persistence. If auto-submit is pursued later, it should only re-queue to the floor or verify kernel under its own provenance, behind a flag, measured on salted held-out. Requiring coded gaps on ruled_out costs turns, so keep that rejection one-shot.

---

## 7. Run the same deterministic floor in --no-llm and agentic modes, and report the agentic increment against that run's own floor

`id: unify-floor-policy-across-modes` · impact 4/5 · leverage 3/5 · effort S · confidence medium · depends on: `fail-closed-measurement-quickwins`, `versioned-results-ledger-heldout-hygiene`

**Problem.** The agentic product's in-run floor is capped at min(75 s, 12% of wall), and the cap applies only when model profiles exist. --no-llm gets no cap. The value came from a commit with no measurement and contradicts a recorded 150-180 s decision that warned 'dual configs guarantee drift'. On the deadline the engine drops the rest of a queue that is always sorted the same way, so sqli and the other late classes get cut. The reported 'agentic increment' therefore compares two different floors, and the agentic run cannot reproduce --no-llm confirmations.

**Verified evidence.**

- src/server/run-actor.ts:810-812 (PHASE_A_FLOOR_MAX_WALL_CLOCK_MS=75_000, share 0.12; spot-checked) and 919-931, where the cap applies only when hasProfiles. The execution.ts:2518-2524 docstring confirms --no-llm is unrestricted.
- plans/ROADMAP-v5.md:331 accepted a Phase A floor of 150-180 s and ruled that 'dual configs guarantee drift'. cbc87dd introduced 75 s with an empty commit body.
- src/server/deterministic-engine.ts:5017-5036 breaks with stoppedReason='time'. intentPriority (2523-2528) puts sqli last on purpose, for the 5xx breaker.
- src/server/execution.ts:2528-2570: hasPreHydratedFloorSnapshot and the deterministic_lane.skipped event already exist, so the persisted-floor reuse path is partly built.
- plans/HANDOVER-SWARM.md:24: 36/59 floor and 36/59 unified, a lift of +0.

**Observed symptoms.** Agentic lift of about 0 across three cycles. The agentic in-run floor misses targets the --no-llm floor confirms. The 'increment' metric mixes floors.

**Systematic improvement.**

1. Run a smoke-tier A/B: the 75 s cap, a 165 s cap, and reuse of a pre-hydrated full floor snapshot through the existing hasPreHydratedFloorSnapshot path. Measure same-run floor confirmations and the agentic increment on dev, then on held-out at the batch boundary.
2. Adopt one floor policy for both modes. Prefer reusing the persisted floor, so agentic wall time is not spent re-running it.
3. Report agentic increment = unified minus the same run's floor, as a ledger field.
4. Emit the per-class unprobed tail in deterministic_engine.summary (shared with the loss-accounting item) so any remaining cap is visible.
5. Keep sqli last, or reserve per-class slots, so breaker safety is preserved.

**First PR-sized steps.**

1. Add a KOVO_PHASE_A_FLOOR_MS override only to the A/B harness invocation, not as a shipped knob. Record it in the EffectiveConfig hash. Run scripts/hillclimb-loop.sh at the smoke tier for the 75 s, 165 s and snapshot-reuse arms.
2. src/server/run-actor.ts:919-931: replace the hasProfiles branch with the chosen single policy, and update the pinned test literals with a Contract-change trailer and the A/B ledger reference.
3. src/server/execution.ts:2528-2570: wire agentic runs to consume a persisted full floor snapshot when one exists for the same target and SHA.
4. scripts/benchmark-realistic.ts: compute and emit agenticIncrementSameRun from the run's own floor provenance. This requires provenance to be mandatory (see the runtime-config item).

**Success metric.** The agentic run's floor confirmations equal --no-llm's on the same seed. The agentic increment is reported against the same run's floor on dev and on fresh held-out seeds.

**Risks / invariants to preserve.** A longer floor takes wall time from Phase B agents. That is why the A/B must include snapshot reuse, and the result may show the cap is not the main cause of zero lift (the route_hit_no_verify bucket dominates). Breaker safety depends on the sqli ordering, so keep it. Changing the cap needs a Contract-change trailer, not a bulk realign.

---

## 8. Measure the configuration that actually ships: an EffectiveConfig fingerprint, a re-routed no-profile floor, required provenance, a production-shaped bench cell, and a product inner loop

`id: effective-config-and-shipped-parity` · impact 4/5 · leverage 4/5 · effort M · confidence high · depends on: `versioned-results-ledger-heldout-hygiene`

**Problem.** Behavior is switched by 145 process.env reads spread over 46 files, and there is no central config. The product benchmark forces recon siblings on, even though no shipped entrypoint enables them. Every cell runs as local-lab with auto_review. A shipped run without a model profile takes the legacy M1 floor, which no benchmark measures. The hill-climb inner loop scores a forked capability harness of about 6.6K LOC on seed 42, and that harness is still being edited despite the freeze. Measured and shipped behavior differ by construction.

**Verified evidence.**

- scripts/benchmark-realistic.ts:2684-2688 and scripts/smoke-agentic.ts:1214 force KOVO_RECON_SIBLINGS='1'. src/server/phase0-recon.ts:4009 treats the flag as opt-in, and no shipped entrypoint sets it.
- src/server/execution.ts:2959-2969 is the legacy M1 no-profile floor (driveDeterministicInvestigation). The shipped constructors at execution.ts:4490 and scripts/cli.ts:598 never set deterministicOnly, while every '--no-llm' benchmark passes deterministicOnly:true (benchmark-realistic.ts:3173).
- scripts/benchmark-realistic.ts:2947,2997 create every cell with environment 'local-lab' and approvalPolicy 'auto_review'. No product cell exercises strict approval or staging_isolated.
- src/server/store-findings.ts:1807 still has `options: FindingProvenanceOptions = {}`. f15d20d fixed only one call site of the unattributed-floor-findings bug.
- scripts/hillclimb-loop.sh:38-42 runs the capability harness on seed 42. benchmarks/realistic-bench/kovo-adapter.ts:209-236 imports it 'deliberately opaque to tsc'. 46 of the last 150 commits touch the 'maintenance-only' scripts/benchmark-probes.ts and benchmark-specs*.ts (+7,955 lines).
- plans/ROADMAP-v5.md:230: the procedural harness scored 38/59 against product --no-llm at 26/59.

**Observed symptoms.** Product-only regressions surface only at matrix time (the 4375eb8 XSS floor). Harness and product numbers diverge. Production branches (strict approval, staging_isolated) have no recall measurement. Floor vs agentic attribution was corrupted once already.

**Systematic improvement.**

1. Write an EffectiveConfig fingerprint (shared with the ledger item) into every run record and bench JSON. A result is labelled 'product' only if it matches the shipped defaults or carries an allow-listed diff.
2. Pick one siblings default: ship it on, or stop forcing it in the harnesses.
3. Route the shipped no-profile path to driveEngineInvestigation, the benchmarked path, then delete the M1 lane. Make FindingProvenanceOptions a required parameter.
4. Add a mandatory production-shaped product cell that runs strict or judge-mediated approval in staging_isolated with shipped recon defaults and the wordlist off. Keep the loopback egress exemption only, and report this cell's recall as the customer-facing number. Keep the local-lab double gates as they are.
5. Change the hillclimb smoke leg to product --no-llm on certification-style seeds with recon reuse. Make worker-gate flag harness-only edits that lack a matching src/server change.
6. Introduce src/server/config.ts incrementally, starting with the variables that change verification semantics (receipt mode, wordlist, siblings, local-lab), and route the 12 inline KOVO_ALLOW_LOCAL_LAB checks through isLocalLabEnabled.

**First PR-sized steps.**

1. scripts/benchmark-realistic.ts:2684-2688 and scripts/smoke-agentic.ts:1214: remove the forced siblings flag, or flip the product default in phase0-recon.ts:4009 after a smoke A/B.
2. src/server/execution.ts:2959-2969: route the no-profile branch to driveEngineInvestigation and delete runDeterministicInvestigation's M1 wrapper in exec-floor-lane.ts:530. Make the options parameter of store-findings.ts:1807 required and fix the callers the typecheck flags.
3. scripts/benchmark-realistic.ts: add a --production-shaped cell flag (approvalPolicy strict or judge, staging_isolated) and include it in certify-phase1.ts buildRunPlan.
4. scripts/hillclimb-loop.sh: replace the benchmark-realistic-matrix leg with scripts/benchmark-realistic.ts --no-llm --reuse-recon on seeds 1 plus one fresh held-out seed.
5. Add src/server/config.ts covering the verification-semantics vars, and replace the inline checks at surface-engine.ts:941, probes/*.ts, floor-recipe-engine.ts:1790, exec-floor-lane.ts:912 and execution.ts:1382 with isLocalLabEnabled().

**Success metric.** Every product scorecard carries a config fingerprint equal to the shipped defaults. A production-shaped recall number is reported every certification. The inner loop's smoke metric is product Execution. Harness-only commits drop to bugfixes.

**Risks / invariants to preserve.** Do NOT shrink local-lab gating to egress scope only. That would extend auto-approval of state changes, JWT claim_swap and mutating GraphQL/XXE branches to customer targets and break the approval and safety invariants. Deleting scripts/benchmark-specs*.ts is blocked until xben/benchmark-live and patch retest have migrated (ROADMAP-v5.md:898), so migrate first. The production-shaped cell will report lower recall. That number is honest, not a regression.

---

## 9. Mechanically keep benchmark fixture vocabulary, canary grammar and VFS paths out of src/server, and gate on a novel-vocabulary cell

`id: fixture-leak-barrier-and-novel-vocab-cell` · impact 4/5 · leverage 4/5 · effort M · confidence high · depends on: `fail-closed-measurement-quickwins`, `versioned-results-ledger-heldout-hygiene`

**Problem.** Product regexes and probe oracles contain fixture-specific nouns and the fixture canary grammar. Examples are baskets, bags, wares, testimonials, journals, billing-docs and endpointHost, the rbs_/rbc_ grammar, /app/config/secrets.env and audit.log. A credential regex labelled 'generic' matches only the fixture grammar. Held-out draws from the same committed pools, and the only contamination lint covers v8 archetype names. The roadmap's 'no English route/param heuristics' rule is policy only, so reported recall overstates generalizable recall. Some confirmation modes, such as cache cross-actor and the secret-disclosure fallback, cannot fire on non-fixture apps.

**Verified evidence.**

- src/server/deterministic-specs.ts:1327,1362: GENERIC_CREDENTIAL_PATTERN = the rb[s]_ fixture grammar, used as the default secretPattern for credential-read proofs. src/server/probes/authz.ts:181 uses the same grammar.
- src/server/probes/cache.ts:34-40: cross-actor cache confirmation needs a fixture-grammar canary in the body. Header-based modes at 129 and 185 still work.
- src/server/deterministic-engine.ts:2088,2092,3243 contain shopflow pool alternates (carts|baskets|bags, wares, ratings|testimonials). src/server/phase0-recon.ts:2313-2315 FILE_ROUTE_HINT contains journals and billing-docs.
- src/server/exec-floor-lane.ts:1141-1170 lists the wordlist, which includes held-out-only alternates (/api/v1/wares/:productId/photos, manifests, product-import). It is gated at :912 to local-lab.
- scripts/check-v8-contamination.ts:1-14 scans only v8 tokens. benchmarks/realistic-bench/generator/variant.ts:18-20 picks held-out vocab from the committed bp.vocab pools.
- benchmarks/realistic-bench/lib/vfs.ts:78-88 defines exactly the entities and markers used in probes/xxe.ts:121-124 and traversal.ts:77-78.

**Observed symptoms.** Dev recall inflated about 15pp by the wordlist alone. A small dev/held-out gap on injection classes gets read as generalization. Users see a sharp drop-off on real-world apps.

**Systematic improvement.**

1. Generalize scripts/check-v8-contamination.ts into a fixture-leak lint in worker-gate. It hard-fails on (i) any rb[cs]_ or rb[s]_ grammar or lib/vfs.ts path literal in src/server or worker, in any spelling, (ii) distinctive pool options that are not in a curated generic API lexicon (wares, baskets, bags, testimonials, journals, billing-docs, endpointHost, logFile, manifests, product-import), and (iii) two or more alternates from one pool in one regex or array.
2. Add a novel-vocab generator mode in variant.ts. It synthesizes random nouns, a randomized canary/secret grammar, a randomized VFS layout and a random reveal-toggle name, and runs as a certify-phase1 cell and a nightly leg. This becomes the reported generalization number.
3. Remove the fixture-only branches:
   - Delete the secrets.env, .env and audit.log entities from traversal and xxe, keeping the passwd and content-differential and the OOB CanaryBroker oracles.
   - Make cache cross-actor use the request's persona actorMarkers instead of the fixture grammar.
   - Replace GENERIC_CREDENTIAL_PATTERN with per-run Kovo-minted markers, keeping the anonymous-denial and masked-control differential.
4. Delete expandConventionalSurfaceTargets.
5. Rewrite the roughly 12 fixture-pinned test files against synthetic vocab in the same PRs.

**First PR-sized steps.**

1. Extend scripts/check-v8-contamination.ts to derive tokens from benchmarks/realistic-bench blueprints minus scripts/generic-api-lexicon.json, and add the grammar and VFS rules. Start it as a ratchet baseline listing the current hits.
2. benchmarks/realistic-bench/generator/variant.ts: add a novelVocab mode, and add a 'floor-novel' cell to scripts/certify-phase1.ts buildRunPlan.
3. src/server/probes/traversal.ts:74-85 and probes/xxe.ts:121-124: remove the fixture VFS entities and markers, and run the regression floor to confirm the generic oracles still confirm xben.
4. src/server/probes/cache.ts:34-40: bind the canary to req.actorMarkers.owner. src/server/deterministic-specs.ts:1327: rename the pattern and drive it from run-minted markers.
5. Delete expandConventionalSurfaceTargets in src/server/exec-floor-lane.ts:1126-1170 and its call at :912.

**Success metric.** The lint ratchet reaches zero fixture-specific hits. A novel-vocab cell is reported every certification, and its gap to dev is tracked and stays under the ROADMAP gate after re-baselining.

**Risks / invariants to preserve.** Expect an honest drop in the floor. Re-baseline the gates rather than chasing the loss with new heuristics. Vendor-format or entropy secret detectors raise FP risk on hashes, ETags and UUIDs, so no single-response pattern match may confirm. Keep the two-sided control-absent and probe-present differentials mandatory. Planting canaries through persona writes mutates the target, so it must go through approval leases and RunSafetyBudgets and fail closed in read-only or production scope.

---

## 10. Store persona tenant/privilege and step routing metadata as typed fields instead of re-deriving them from labels and prose

`id: typed-persona-and-step-semantics` · impact 4/5 · leverage 4/5 · effort M · confidence medium · depends on: `confirmation-path-parity-corpus`

**Problem.** Persona tenant and privilege exist only inside a free-text roleLabel in the '${role} (${tenant})' format, and only the benchmark harness writes that format. The product UI defaults to 'User A', so for real users cross-tenant BOLA cannot confirm, and benchmark authz recall is a benchmark-only number. Three lexicons disagree on 'owner'. Dispatch lane, EVI and cap are written as [lane=] tags into hypothesis prose by Kovo's own seeders and regexed back out, because chain_steps has no columns for them and registerStepMeta has no callers. Proof strength is decided by jq syntax, and the publicness check returns 'public' before it reads the canary markers its own contract says defeat publicness.

**Verified evidence.**

- src/server/schema.ts:80-93: the persona table has only roleLabel and no tenant or privilege. PersonaFormModal.tsx defaults to 'User A'. scripts/benchmark-realistic.ts:659 writes roleLabel `${p.role} (${p.tenant})`.
- src/server/exec-floor-lane.ts:977-993 (owner maps to member), src/server/oracle-invariants.ts:128-147 and src/server/v8-oracle-hydrate.ts:90-92 (owner is privileged, privilege also inferred from the handle) are three disagreeing lexicons. actorsAreCrossTenant (oracle-invariants.ts:192-203) returns false when tenant is missing.
- src/server/schema.ts:150-172: chain_steps has no lane, originSource, evi or hopDepth columns. exec-dispatch.ts:2391 registerStepMeta has no callers. Seeders write [lane=]/[evi=] tags into prose (exec-recon-planner.ts:1543, exec-dispatch.ts:610-611,3713).
- src/server/floor-recipe-engine.ts:2743-2761 classifyHttpChainAssertion returns content_bound whenever any .steps.X.json is referenced, so a no-op json clause escapes the status-only class.
- src/server/oracle-invariants.ts:443-475: assessPublicness branch (A) returns public on any anonymous 2xx JSON read before consulting canaryMarkers, which contradicts its own doc comment. registerCanaryMarker has no production callers.
- git 44204dd fixed same-tenant BOLA FPs by widening the label parser and edited the paygrid fixture in the same commit.

**Observed symptoms.** Authz verdicts depend on a label convention only benchmarks supply. Recurring fix families for status-only (1cca4b5, 98480cc, 31a3e2a, 3e44f4b), publicness (48092b7, 5b5bb43) and role labels (497dc56, f21d6fb, d3da8f2, 44204dd).

**Systematic improvement.**

1. Add typed persona tenantRef and privilege columns to the schema, the API and PersonaFormModal. The bench fills those fields instead of the label. Add an opaque-label ablation cell (labels randomized) to measure label dependence. Delete the duplicate tenantOf/privilegeOf parsers so one resolver reads the typed fields, with the label parse as a logged fallback.
2. Add lane, originSource, evi and hopDepth columns to chain_steps and set them in every seeder. Count each time classifyDispatchLane reaches its regex tail and ratchet that count to zero.
3. Roll out host-computed evidence kind as AND: the typed recorded-exchange evidence plus the existing jq check. Make a json field count only when it is compared to a control-bound extracted value. Add metamorphic tests that rewrite jq and titles without changing their meaning.
4. Move the publicness canary/owner-binding check ahead of branch (A), and wire registerCanaryMarker or delete it.
5. Have verify-claims guards return typed {code, missingEvidence[]}.

**First PR-sized steps.**

1. src/server/schema.ts personas: add tenant_ref and privilege. Add the field to PersonaFormModal.tsx. Set the fields in scripts/benchmark-realistic.ts:659 and keep the label free-form. Add an --opaque-persona-labels cell.
2. Create a single src/server/persona-identity.ts resolver and switch exec-floor-lane.ts:977-993, oracle-invariants.ts:128-147 and v8-oracle-hydrate.ts:90-92 to it.
3. src/server/schema.ts chain_steps: add the lane, origin_source, evi and hop_depth columns. Set them at the exec-recon-planner.ts:1543 and exec-dispatch.ts:610,3713 seeders, and add a regex-fallback counter in classifyDispatchLane.
4. src/server/oracle-invariants.ts:461-471: evaluate canaryMarkers and owner binding before branch (A). Validate against benchmarks/realism-suite/traps/fp-archetypes.json and the parity corpus.
5. src/server/floor-recipe-engine.ts:2743-2761: require that the json reference is compared against an extracted or control value, and add rewrite property tests.

**Success metric.** The opaque-label ablation cell's authz recall matches the labelled cell. Zero regex-tail dispatch classifications on seeded steps. Status-only and publicness fix commits stop recurring.

**Risks / invariants to preserve.** When the typed fields are empty, the oracle must keep failing closed, with no cross-tenant confirmation. Any bounded identity probe must record observed tenant evidence bound to a persona exchange, or the same-tenant BOLA FPs fixed in 44204dd come back. Tightening classifyHttpChainAssertion will demote some true positives, so run it through the parity corpus first. Do not change the step budget to count only live steps without a separate cancel-churn cap. Do not credit this item with the 153/270 unassigned steps or the 287 trial turns: the autopsy attributes those to deadlines, stalls and fan-out timing.

---

## 11. Add a capability-manifest snapshot, an unused-export and cycle ratchet, and pulse state derived from git

`id: composition-manifest-and-unwired-ratchet` · impact 3/5 · leverage 4/5 · effort M · confidence high · depends on: `blocking-behavioral-merge-gate`

**Problem.** Primitives merge with unit tests but no production call site, and the docs then describe some of them as live. When a fix moves to a new layer, the old path is left behind as a dead duplicate. Lease-era workaround types outlive the lease. The coordination backlog that the pulse reads is about 540 commits stale, so UNDER-PARALLELIZED is noise. The proof kernel has a runtime import cycle. Nothing checks what the composition root actually wires.

**Verified evidence.**

- src/server/patch-workflow.ts:1662: retestCompositeChainPatch is called only from tests/v8-patch-retest.test.ts, yet ARCHITECTURE.md:137,187 describe it as the live patch-verification stage.
- src/server/exec-dispatch.ts:2847-2854 has resolveProviderStallNoTokenMs (test-only) beside the live provider-stream.ts:12-46 / exec-worker-runner.ts:695 watchdog, a dead dual path.
- src/server/floor-recipes.ts:88-101: the Cut3FloorRecipeId union and its 'outside this stream's lease' comment survived after src/replay-spec.ts:202-213 absorbed the ids.
- plans/STREAM-BACKLOG.md is pinned at fb93a8a (about 540 commits behind) and lists merged items as ready. scripts/parallel-pulse.sh:76-80 greps it.
- src/server/composite-receipt.ts:11 <-> terminal-oracle-registry.ts:14-24 is a value-level import cycle. scope-policy.ts:1392,1499 signScopeManifest and evaluateSignedScopeRequest are unwired.
- plans/PARAM-DISCOVERY.md:153: the hypothesis-selection fix was deferred as 'outside lease' and a recon risk bump in the lease was used instead.

**Observed symptoms.** Reviewers plan against stale docs. Multi-hop findings get no hop-level patch closure. Pulse signals are unreliable. Wrong-layer workarounds pile up.

**Systematic improvement.**

1. Add a composition-root capability manifest test in worker-gate. It builds AppRuntime for the docker, DooD and local-jq/fake backends and emits the registered tools, reachable recipe ids, oracle families and approval binders. Diff it against a checked-in manifest. A manifest diff that removes a capability requires a Contract-change trailer. The local-jq manifest asserts kovo_verify is absent.
2. Add a knip/ts-prune ratchet. A test-only export needs an expiring tag whose resolution is 'delete' or 'keep-unwired with a measured-gate ticket', never 'wire by deadline'. Add a madge zero-new-cycle check, and fail when an ARCHITECTURE stage cites a symbol that has no non-test caller.
3. Derive pulse state from branches and git trailers (Stream:, Decision-ref:). The pulse refuses to read a backlog pinned more than N commits behind HEAD.
4. Instead of stricter lease enforcement, add a stale-merge-base check on hot files (execution.ts, phase0-recon.ts, deterministic-engine.ts, oracle-invariants.ts) and first-class, expiring cross-lease 'required diff' tickets. A workaround must name its ticket and is removed when the ticket closes.

**First PR-sized steps.**

1. Add tests/capability-manifest.test.ts building on tests/contract-wiring.test.ts and the AppRuntime composition root (c3f8033), plus tests/fixtures/capability-manifest.json, and add it to scripts/worker-gate.sh.
2. Add knip (or ts-prune) and madge as devDependencies. Add scripts/check-unwired.ts with a baseline file and wire it into worker-gate as a ratchet.
3. Delete exec-dispatch.ts:2847-2854 and port tests/v7-stall-warmpool.test.ts to the provider-stream resolver. Remove the Cut3FloorRecipeId union and the stale comment at floor-recipes.ts:88-101.
4. Fix ARCHITECTURE.md:137,187 to say retestCompositeChainPatch is not wired, or wire it behind a ticket. Break the composite-receipt <-> terminal-oracle-registry cycle by injecting the registry.
5. scripts/parallel-pulse.sh:76-80: compute ready/active from unmerged agents/* branches, and ignore STREAM-BACKLOG entries whose branch is merged.

**Success metric.** The unused-export count and cycle count are non-increasing and then falling. Zero ARCHITECTURE citations of test-only symbols. The pulse's UNDER-PARALLELIZED signal matches the actual branch state.

**Risks / invariants to preserve.** Teams will rubber-stamp manifest updates unless a capability removal requires a trailer. The ratchet must not pressure anyone into wiring precision-sensitive primitives hastily, such as non-JSON body binding or signed-scope enforcement. Allow 'keep unwired with a ticket'. Lease or queue tooling must never delay merges that restore approval or scope guards, which are exactly the changes RC-4 lost.

---

## 12. Collapse the drifting class, CWE and role tables into one data contract, and add a conformance test first

`id: single-class-taxonomy-contract` · impact 3/5 · leverage 4/5 · effort L · confidence medium · depends on: `confirmation-path-parity-corpus`, `versioned-results-ledger-heldout-hygiene`

**Problem.** At least nine independent class/CWE tables, spread over src/server and the graders, disagree on concrete CWEs. CWE-362 resolves four ways (authorization, bola, conservation_race, race). CWE-269 is missing from the bfla receipt family while two other tables map it to bfla. Role ranks disagree on owner vs admin. Under strict receipts the failures are mostly fail-closed, costing silent recall, label drift and strictPrecision charges. Each new subsystem copies an existing table along with its mis-mappings, as the newest one did today.

**Verified evidence.**

- src/server/floor-recipe-engine.ts:3416-3425 CWE_TO_RECEIPT_CLASS maps 362 and 1021 to 'bola' (added in c60f6a6 on 2026-11-25). src/server/deterministic-specs.ts:2053-2084 maps 362 to race_double_spend and 79 to xss_reflected where the receipt table says xss_stored.
- src/server/exec-verify.ts:316-317 bfla family (285/862/863/639/284) lacks 269, while oracle-invariants.ts:600 and floor-recipe-engine.ts:3416 map 269 to bfla.
- src/server/oracle-invariants.ts:567 vs 3695-3703: BUSINESS_LOGIC_CWE_RE contains 1284 but IMPACT_CLASS_CWES.business_logic does not, and IMPACT_CLASS_CWES.bola is only [639].
- src/server/floor-heuristics.ts:209-222 sets owner==admin (both 4), which disagrees with ROLE_RANK in oracle-invariants.ts:30 ('single source of truth') and suppresses BFLA hypotheses for owner-vs-admin pairs.
- benchmarks/realistic-bench/grader/match.ts:8-27 vs 85-91: familyCwes.authz lacks 269 while cweClassKey maps 269 to bfla. reason-bench has a further copy.
- src/server/finding-fingerprint.ts:222,236 hashes the raw normalized CWE, so sibling CWEs on one endpoint always get separate fingerprints.

**Observed symptoms.** Four label-alignment commits in three days (faba8c3, 160213f, f9af452, c60f6a6). incompatibleClassCount and strictPrecision charges. No CWE-first route to the path_traversal, ssti or cmdi receipt rules.

**Systematic improvement.**

1. Start with an exhaustiveness and conformance test (S). It enumerates every CWE and alias in every current table and asserts that they agree on a shared contract. It will immediately flag 362->bola, the missing 269 and the 1284 split.
2. Create src/server/vuln-taxonomy.ts as a logic-free, versioned data module with one row per class: id, aliases, CWE family, canonical label, sibling set, receipt rule, and an explicit gate field (impact / dedicated / advisory). Generate the src tables from it one at a time. Each migration is gated by the parity corpus.
3. Use a single role lattice.
4. Keep the grader's truth taxonomy independent and versioned. A cross-conformance test asserts that the product's canonical CWEs and siblings fall inside the grader families. Changes to grader tolerance bump benchmarkVersion.
5. Version the fingerprint (it is in IMMUTABLE_CONFIRMED_FINDING_FIELDS) before re-keying identity on the sibling-set id.
6. Add a CI check that greps for CWE regex alternations outside the module.

**First PR-sized steps.**

1. Add tests/taxonomy-conformance.test.ts that imports the tables from oracle-invariants.ts, proof-receipt.ts IMPACT_CLASS_BY_VULN, exec-verify.ts (cweFamilyForReceiptClass, CWE_ALIAS_GROUP_BY_CWE, agentProofAttribution), floor-recipe-engine.ts CWE_TO_RECEIPT_CLASS and deterministic-specs.ts vulnClassOfSpec, and asserts that they agree. Record the current disagreements as a ratchet.
2. Fix the confirmed drifts behind the parity corpus: 362/1021 out of 'bola' in floor-recipe-engine.ts:3416-3425, 269 added to the bfla family at exec-verify.ts:316-317, and 1284 aligned at oracle-invariants.ts:3695.
3. Create src/server/vuln-taxonomy.ts and migrate CWE_TO_RECEIPT_CLASS first, since it is the newest fork.
4. Delete floor-heuristics.ts ROLE_PRIVILEGE_RANK in favor of ROLE_RANK, after checking new BFLA hypotheses against fixtures where admins legitimately hold owner powers.
5. Add a benchmarks/realistic-bench/grader conformance test that pins a grader taxonomy version without importing product code.

**Success metric.** The conformance test runs in worker-gate with zero disagreements. CWE tables outside vuln-taxonomy.ts drop to zero. Label-alignment commits stop.

**Risks / invariants to preserve.** Several classes intentionally resolve to 'other' or null because they have dedicated receipt rules (open_redirect, ssrf, xxe, webhook). Map them to 'dedicated', not 'advisory', or recall drops. Never give a previously null CWE a receipt rule unless its assessor really models the class, so strict-mode fail-closed is preserved. Routing CWE-22/78/1336 into the generic injection rule is a widening and needs its own FP check. Re-keying fingerprints breaks cross-run dedupe unless it is versioned and migrated. Merging bola and bfla identity could merge distinct root causes.

---

## 13. Make run and persona scope required, give per-run state an owner, and require a finally-guarded restore for mutating recipes

`id: scope-isolation-invariants` · impact 3/5 · leverage 4/5 · effort L · confidence medium · depends on: `fail-closed-measurement-quickwins`

**Problem.** runId, assignmentId, role and persona are optional and fall back to shared 'default' buckets. Each subsystem builds its own key, so the browser jar mirror and the HTTP path disagree. Broker per-run Maps are never disposed. The redaction registry is broker-wide with a silent 5,000-entry FIFO, so redaction can fail open for log and LLM-bound text. Mutating recipes have no mandatory, planner-independent restore. One such gap (0df720d) caused a real recall regression and an unreproducible certificate. The systemic RunScoped fix was recommended in round 1 and never adopted, so the class keeps recurring one subsystem at a time.

**Verified evidence.**

- src/server/broker.ts:1904 resolveScopeRunKey falls back to 'default'. broker.ts:2137-2139 sessionCookiesForBrowser rebuilds the key from scope.runId and ignores grant.scopePolicy.runId.
- src/server/persona-auth.ts:1297 strictRunScope:false, and nothing in src or tests ever sets it true (spot-checked).
- src/server/broker.ts:1714-1728 redactedSecrets is broker-wide with a FIFO cap of 5,000 and no event. src/server/execution.ts:786-794,861-902: cleanupRunState and the 8 registered resources never purge broker jars, scope revisions, persona owners or secrets.
- src/server/derived-custody.ts:52-57,86-87: resetRunCustodyBudgets has zero production callers.
- src/server/floor-recipes.ts:955-970: the persisted_mutation restore runs only when args.reset is set and is not in a finally, so a FloorRecipeAbort skips it. floor-recipe-engine.ts:565 sets reset only when functionState.reset is known.
- plans/HANDOVER-SWARM.md:122-131 bisects the 26-vs-28 held-out discrepancy to 0df720d dropping the restore. git show 0df720d:tests/v7-cut3b-parity.test.ts:346 asserted the step list without a restore. plans/CLAUDE_AUDIT.md:1244 had already prescribed RunScoped<T>.

**Observed symptoms.** A certificate erratum caused by target-state drift (a recall loss, not wrong-tenant confirmations). Cross-run browser context destruction (R2-H-20) and concurrent repo staging merges (R2-H-21), each fixed separately. Unbounded per-process memory growth.

**Systematic improvement.**

1. First, add a cheap served-scope validity check: a per-persona tenant fingerprint read before and after each assignment. A cell is INVALID on drift.
2. Every mutating recipe must either capture a restore from its own baseline_read or declare sideEffects:'isolated_tenant', and the planner rejects recipes that do neither. All restore and cleanup sends run in finally.
3. Make the redaction registry per-run and never evict a live run's secrets. At the cap, fail closed by aborting the assignment or refusing to persist unredacted text, rather than FIFO-dropping.
4. Use one shared resolveJarKey(req, grant) for both the HTTP jar and the browser mirror.
5. Add a RunScoped<K,V> registry owned by RunContext for broker jars, scope revisions, persona owners and custody budgets. Disposal is tested, and evictions emit a degradation record. A lint forbids new module-level per-run Maps (caches are exempt).
6. Instrument strict-scope fallback hits, then make runId required on broker requests and strictRunScope the only mode.

**First PR-sized steps.**

1. Add a served-scope check in scripts/benchmark-realistic.ts. It reads each persona's tenant fingerprint before and after each assignment from host exchanges, and marks the cell INVALID on mismatch.
2. src/server/floor-recipes.ts:955-970: wrap the probe and post-read in try/finally that runs the restore. src/server/floor-recipe-engine.ts:565: derive the restore from the observed baseline_read when functionState.reset is unknown, or refuse the recipe.
3. src/server/broker.ts:1714-1728: key redactedSecrets by runId, drop entries at run disposal, and fail closed at the cap. Register the broker maps with the RunActor in execution.ts:861-902.
4. src/server/broker.ts:2137-2139: replace the mirror key construction with a shared resolveJarKey that also consults grant.scopePolicy.runId.
5. src/server/persona-auth.ts:1560-1578: emit a counter whenever the bare-handle or single-run fallback is used, and flip strictRunScope after the counter reads zero at the smoke tier.

**Success metric.** The served-scope check passes on every certification cell. Broker per-run maps are empty after disposeRun, which a test asserts. Zero redaction-cap evictions of live-run secrets. Strict-scope fallback hits reach zero before the flip.

**Risks / invariants to preserve.** Flipping strictRunScope before auditing unscoped callers (execution.ts:554-559 reauth) turns reauth into silent false negatives, so instrument first. Some sharing is intentional at run granularity (browser pool, persona login), so scopeKeyString needs an explicit granularity. Do not force assignment granularity everywhere, or re-logins may trigger target lockouts. Restores are additional live mutations and must stay inside approval leases and RunSafetyBudgets. The redaction fail-closed change is a safety invariant and should ship early, whatever happens to the rest of this item.

---

## Verification notes

- Themes refuted outright: none.
- The ranking pass's dropped/narrowed claims and rejected fixes are listed at the end of the rationale above. In short, these fixes were **rejected as unsafe**: shrinking local-lab gating to egress scope only, having the grader import the product taxonomy, a blanket catch lint, and host auto-submit of canonical proofs. Each threatens precision, approval/safety invariants, or measurement independence.

## Known gaps in this audit

I did not run any benchmark or test suite. Impact estimates rest on the plan documents' recorded numbers and on the verdicts, not on fresh measurement. In particular, how much of the zero agentic lift comes from the 75 s floor cap, from contract drift, or from agent proof behavior (route_hit_no_verify) has not been quantified.

I spot-checked only 5 evidence sites on a6d66b9: replay-verifier.ts:508, settlementTurn unread / 0.85N, the wordlist default at benchmark-realistic.ts:416, strictRunScope defaulting false, and the 75 s cap. Everything else relies on the two adversarial verdicts per theme.

Not examined:
- The worker container and sandbox security surface, beyond scope isolation.
- The UI, except PersonaFormModal.
- Model-provider reliability, apart from the stall watchdog.
- Cost per run and token economics.
- The multihop-saas and reason-bench graders in depth.
- Whether the redaction FIFO fail-open is actually reachable in realistic runs.
- The precise count of test-only exports and of recall-relevant silent catch sites.
- Whether the realistic-bench oracle emits exchange IDs, which causal attribution needs.

The number of real-app recall regressions that fixture removal would cause is also unmeasured. A novel-vocab cell is the proposed way to measure it.

## Expected metric discontinuity

Items 1, 2, 8 and 9 will **lower reported recall**: the wordlist default alone is about 9 dev targets, and retiring seed 1000042 / fixture vocabulary will move held-out. Re-baseline once, explicitly, in `benchmarks/CHANGELOG.md` and the results ledger. Do not read that drop as an engine regression or chase it with new heuristics.

## Reviewer triage (completed 2026-11-25, `main` @ `4c2a45d`)

> Context since `09a5126`: 6 commits landed on `main` (`fix-m2-prompt-skills`, `fix-m2-budgets-seal`, `fix-m2-edge-binding`, `sys-contract-canary` [unified `run-safety-budgets.ts` + 4-check CI canary in `worker-gate.sh`, 70/70 PASS], `fix-m2-static-fp` [verify-before-persist + live `static_ast_proof` demotion], `docs-agents-systemic`), and 6 Option A streams are active in parallel worktrees (`opencode/sys-host-autodag`, `sys-q1-worker-pool`, `sys-q2-repo-tools`, `sys-q3-oob-browser`, `sys-q4-broker-auth`, `sys-q5-phase0-graph`).

| # | id | Verdict (accept / reject / defer) | Reason | Stream / owner | Lease (files) |
|---|---|---|---|---|---|
| 1 | `fail-closed-measurement-quickwins` | **accept** (P0, Wave 1) | Strictly tightening, S effort, zero precision/safety risk and zero overlap with active `sys-*` streams; fixes +15pp wordlist inflation, vacuous smoke clamp, empty precision=1, and classless/unanchored matching. Re-baseline realistic-bench/xben once in `CHANGELOG.md` without blocking v8 M2. | `cq-1-fail-closed-scoring` | `scripts/benchmark-realistic.ts`, `scripts/benchmark-realistic-matrix.ts`, `scripts/benchmark-agentic-matrix.ts`, `scripts/smoke-agentic.ts`, `scripts/benchmark-score.ts`, `scripts/benchmark-core.ts`, `benchmarks/realistic-bench/grader/match.ts`, `benchmarks/CHANGELOG.md`, `tests/cq-1-fail-closed-scoring.test.ts` |
| 2 | `versioned-results-ledger-heldout-hygiene` | **accept** (P1, Wave 1) | Stops mixed-SHA/config tables and retires over-autopsied seed `1000042` (`BURNED_SEEDS`); keep `strictPrecision` as headline gate (`validUnplanted` side column only with replay evidence) and `n>=3` for certification only (never smoke). Include v8 `certify-v8.ts` ledger schema compatibility. | `cq-2-ledger-heldout` | `scripts/bench-ledger.ts`, `scripts/render-verification-tables.ts`, `scripts/certify-phase1.ts`, `benchmarks/realistic-bench/BURNED_SEEDS`, `benchmarks/realistic-bench/grader/score.ts`, `benchmarks/results/ledger.jsonl`, `scripts/benchmark-realistic.ts` (post-`cq-1`), `scripts/benchmark-*-matrix.ts` (post-`cq-1`), `tests/cq-2-ledger-heldout.test.ts` |
| 3 | `blocking-behavioral-merge-gate` | **accept (narrowed)** (P1, Wave 2) | Fixes orphaned ~340 tests and bulk-realign churn via `QUARANTINE.json` (capped, owner+expiry), orphan check, and `Contract-change:` trailer lint. **Narrowing:** keep `worker-gate.sh` <60s (fast suite + quarantine + lints); run `regression-floor.sh` (`xben-25` + `held-out-saas --no-llm` + `v8-seam1-golden-e2e`) at batch-boundary/pre-push + CI, not every merge. Skip v5 `parallel-pulse.sh` edits (retiring to `/swarm`). | `cq-3-merge-gate` | `scripts/worker-gate.sh`, `scripts/run-fast-tests.sh`, `scripts/regression-floor.sh`, `scripts/check-contract-change.ts`, `tests/QUARANTINE.json`, `tests/v7-dispatch-funnel.test.ts`, `tests/cq-3-merge-gate.test.ts` |
| 4 | `confirmation-path-parity-corpus` | **accept** (P0 precision guardrail, Wave 2) | Verified fail-open seams (`replay-verifier.ts:508` authz-only `proofStrength`, unstripped `verify-claims`/`floor-recipes` fingerprints, `'other'` skip, `KOVO_PROOF_RECEIPT=off/shadow` outside tests). Must land before #10/#12 and **after `opencode/sys-host-autodag`** (which edits `verify-claims.ts` & `composite-receipt.ts`) and `cq-13a`. Keep strict-receipt fail-closed default. | `cq-4-parity-corpus` | `tests/parity/**`, `tests/path-parity.test.ts`, `src/server/replay-verifier.ts`, `src/server/verify-claims.ts`, `src/server/proof-receipt.ts`, `src/server/floor-recipes.ts` (post-`cq-13a`), `src/server/floor-recipe-engine.ts` (post-`cq-13a`) |
| 5 | `typed-terminal-outcomes-and-loss-accounting` | **accept** (P1, Wave 2/3) | Eliminates silent loss from marking `turn_limit`/`nudged_out`/`wall_clock_rotated` as `'complete'`, prose-parsed coverage, and swallowed planner JSON parse errors. **Overlap:** serialize after active `sys-q1-worker-pool` (`exec-worker-runner.ts`) and fold in our Tier-2 Q6 (`FrontierWaveController` authority). Cap requeue at 1 retry/key inside `RunSafetyBudgets`; keep `sqli`-last breaker ordering. | `cq-5-typed-outcomes` | `src/server/schema.ts` (step statuses), `src/server/exec-worker-runner.ts`, `src/server/exec-recon-planner.ts`, `src/server/exec-dispatch.ts`, `src/server/deterministic-engine.ts`, `src/server/exec-floor-lane.ts`, `benchmarks/realistic-bench/grader/attribution.ts`, `tests/cq-5-typed-outcomes.test.ts` |
| 6 | `agent-contract-single-source` | **accept** (P0, Wave 2) | S effort, 100% verified turn-wasting drift (unread `settlementTurn`, `'8-10 turns'` vs 18–34, unparsed `'cannot_build_spec'`, `crawl_state_graph` uncategorized). **Overlap:** serialize after `sys-q1-worker-pool` (`exec-worker-runner.ts`) and `sys-q2-repo-tools` (`agent-session.ts`, `agent-prompts.ts`), and fold `agent-contract.test.ts` into `sys-contract-canary.test.ts`. Agree: no host auto-submit (protects `0297400`). | `cq-6-agent-contract` | `src/server/agent-tool-registry.ts`, `src/server/agent-session.ts`, `src/server/agent-prompts.ts`, `src/server/exec-worker-runner.ts`, `src/server/exec-dispatch.ts`, `src/server/verify-runner.ts`, `tests/agent-contract.test.ts` |
| 7 | `unify-floor-policy-across-modes` | **defer** (Wave 4, post-M2) | Real discrepancy (`75s` cap only when `hasProfiles`), but 0 impact on v8 M2 (`--no-llm` is 0/12) and medium confidence on realistic-bench zero lift (`route_hit_no_verify` dominates). Raising floor cap steals Phase B budget unless `hasPreHydratedFloorSnapshot` reuse wins; defer until #1/#2 ledger exists, then run 3-arm smoke A/B before flipping `run-actor.ts`. | `cq-7-floor-policy-ab` | `src/server/run-actor.ts`, `src/server/execution.ts`, `scripts/benchmark-realistic.ts`, `tests/cq-7-floor-policy.test.ts` |
| 8 | `effective-config-and-shipped-parity` | **accept (phased)** (P1, Wave 3) | Fixes real shipped-vs-measured drift (`KOVO_RECON_SIBLINGS`, unbenchmarked M1 no-profile lane, optional `FindingProvenanceOptions`, no `strict`/`staging_isolated` bench cell). **Overlap:** serialize siblings default after `sys-q5-phase0-graph`. Keep local-lab double gating intact (only loopback egress exemption in `--production-shaped`). Defer deleting `benchmark-specs*.ts` until xben/retest migrate. | `cq-8-shipped-parity` | `src/server/config.ts`, `src/server/execution.ts`, `src/server/store-findings.ts`, `scripts/hillclimb-loop.sh`, `scripts/benchmark-realistic.ts`, `scripts/smoke-agentic.ts`, `scripts/certify-phase1.ts`, `tests/cq-8-shipped-parity.test.ts` |
| 9 | `fixture-leak-barrier-and-novel-vocab-cell` | **accept** (P1, Wave 3) | High generalization leverage: removes `rb[s]_` grammar, shopflow vocab, VFS paths, and `expandConventionalSurfaceTargets` behind a mechanical lint ratchet + `floor-novel` cell. **Overlap:** serialize after `sys-q5-phase0-graph` (`phase0-recon.ts`) and `cq-5` (`exec-floor-lane.ts`). **Safety/precision:** no entropy/vendor-format regex replacements (FP risk); keep two-sided differentials + approval-leased minted markers. | `cq-9-fixture-barrier` | `scripts/check-v8-contamination.ts`, `scripts/generic-api-lexicon.json`, `benchmarks/realistic-bench/generator/variant.ts`, `src/server/probes/{traversal,xxe,cache,authz}.ts`, `src/server/deterministic-specs.ts`, `src/server/phase0-recon.ts`, `src/server/exec-floor-lane.ts`, `tests/cq-9-fixture-barrier.test.ts` |
| 10 | `typed-persona-and-step-semantics` | **accept** (P1, Wave 3) | Critical real-user fix (`PersonaFormModal` `'User A'` blocks live cross-tenant BOLA) + fixes `assessPublicness` branch (A) canary bypass & prose-tagged `chain_steps`. **Overlap/order:** must run after #4 parity corpus, #5 (`schema.ts`), `sys-q4` (`persona-auth.ts`), and `sys-host-autodag` (`v8-oracle-hydrate.ts`). Fail closed when `tenantRef`/`privilege` are empty; gate `classifyHttpChainAssertion` tightening on #4 parity diff. | `cq-10-typed-semantics` | `src/server/schema.ts` (post-`cq-5`), `src/server/persona-identity.ts`, `src/components/personas/PersonaFormModal.tsx`, `src/server/oracle-invariants.ts`, `src/server/v8-oracle-hydrate.ts`, `src/server/floor-recipe-engine.ts` (post-`cq-4`), `tests/cq-10-typed-semantics.test.ts` |
| 11 | `composition-manifest-and-unwired-ratchet` | **accept (narrowed)** (P2, Wave 3) | Capability manifest (`docker`/`DooD`/`local-jq`), `knip`/`madge` ratchet, breaking `composite-receipt <-> terminal-oracle-registry` cycle, and removing dead `resolveProviderStallNoTokenMs`/`Cut3FloorRecipeId` prevent silent unwired rot. **Narrowing:** drop `parallel-pulse.sh`/`STREAM-BACKLOG.md` work (retiring to `/swarm`); allow `keep-unwired` tickets so precision-sensitive code is never rushed live; align `ARCHITECTURE.md` with Q8 (`retestCompositeChainPatch`). | `cq-11-manifest-ratchet` | `tests/capability-manifest.test.ts`, `tests/fixtures/capability-manifest.json`, `scripts/check-unwired.ts`, `src/server/composite-receipt.ts`, `src/server/terminal-oracle-registry.ts`, `ARCHITECTURE.md`, `package.json`, `tests/v7-stall-warmpool.test.ts` |
| 12 | `single-class-taxonomy-contract` | **accept Stage 1 / defer Stage 2** (P1/Wave 3, L-refactor Wave 4) | **Stage 1 (S, Wave 3):** ship `tests/taxonomy-conformance.test.ts` + fix verified drifts (`362/1021` out of `bola`, `269` in `bfla`, `1284` in `business_logic`) behind #4 parity corpus. **Stage 2 (L, Wave 4 defer):** full `vuln-taxonomy.ts` consolidation, `ROLE_PRIVILEGE_RANK` unification (verify admin-with-owner-powers fixtures), and versioned `finding-fingerprint.ts` migration. Keep grader taxonomy independent; never widen `22/78/1336` into generic injection without FP gating. | `cq-12a-taxonomy-conformance` (Wave 3) → `cq-12b-vuln-taxonomy` (Wave 4) | Wave 3: `tests/taxonomy-conformance.test.ts`, `src/server/floor-recipe-engine.ts`, `src/server/exec-verify.ts`, `src/server/oracle-invariants.ts`. Wave 4: `src/server/vuln-taxonomy.ts`, `src/server/floor-heuristics.ts`, `src/server/finding-fingerprint.ts`, `src/server/deterministic-specs.ts`, `src/server/proof-receipt.ts` |
| 13 | `scope-isolation-invariants` | **accept split: 13a P0 (Wave 2) / 13b defer (Wave 4)** | **Ranking challenge:** #13 bundles a **P0 safety invariant** (broker-wide 5k `redactedSecrets` FIFO failing open on live secrets) + proven `finally`-restore omission (`floor-recipes.ts:955`) inside an L-effort `RunScoped` refactor. **Split:** ship **13a (S, Wave 2)** immediately after `sys-q4` merges (per-run fail-closed `redactedSecrets`, shared `resolveJarKey`, `disposeRun` purge of broker maps + `resetRunCustodyBudgets`, `try/finally` + baseline-derived recipe restore). **Defer 13b (L, Wave 4):** `RunScoped<K,V>`, Map lint, served-scope check, and `strictRunScope` telemetry-first flip (must audit `execution.ts:554` reauth first). | `cq-13a-redaction-restore` (Wave 2) → `cq-13b-run-scoped` (Wave 4) | Wave 2 (`13a`): `src/server/broker.ts`, `src/server/derived-custody.ts`, `src/server/execution.ts`, `src/server/floor-recipes.ts`, `src/server/floor-recipe-engine.ts`, `tests/cq-13a-redaction-restore.test.ts`. Wave 4 (`13b`): `src/server/run-scoped.ts`, `src/server/persona-auth.ts`, `scripts/benchmark-realistic.ts` |

### Proposed parallel workstreams (completed by reviewer)

Per `AGENTS.md` ("Parallelization by default"): one writer per file, disjoint worktree branches (`agents/<stream>`), merge as streams finish, and explicit serialization exceptions for shared hot files. **Active Option A baseline (`opencode/sys-host-autodag`, `sys-q1`..`sys-q5`) finishes and merges first** except Wave 1 (`cq-1`), which has zero file overlap and can start immediately if approved.

#### Wave 1 — Measurement Validity & Ledger (Zero overlap with active `sys-*` streams)
1. **`agents/cq-1-fail-closed-scoring`** *(Item #1, S)* — starts immediately.
   - Lease: `scripts/benchmark-realistic.ts`, `scripts/benchmark-realistic-matrix.ts`, `scripts/benchmark-agentic-matrix.ts`, `scripts/smoke-agentic.ts`, `scripts/benchmark-score.ts`, `scripts/benchmark-core.ts`, `benchmarks/realistic-bench/grader/match.ts`, `benchmarks/CHANGELOG.md`, `tests/cq-1-fail-closed-scoring.test.ts`.
   - Validation: `worker-gate.sh` + scoring unit tests; batch-boundary one-time realistic-bench/xben re-baseline.
2. **`agents/cq-2-ledger-heldout`** *(Item #2, M)* — **serialized after `cq-1`** (shares `scripts/benchmark-realistic.ts`, `scripts/benchmark-*-matrix.ts`).
   - Lease: `scripts/bench-ledger.ts`, `scripts/render-verification-tables.ts`, `scripts/certify-phase1.ts`, `benchmarks/realistic-bench/BURNED_SEEDS`, `benchmarks/realistic-bench/grader/score.ts`, `benchmarks/results/ledger.jsonl`, plus the 3 benchmark runner scripts post-`cq-1`, `tests/cq-2-ledger-heldout.test.ts`.
   - Validation: `worker-gate.sh` + ledger/version-mismatch tests; batch-boundary `n>=3` fresh salted seeds at certification only.

#### Wave 2 — Merge Gate, Safety-Critical Redaction/Restore, Agent Contract & Parity Corpus (4 parallel streams after Option A + `cq-1` merge)
3. **`agents/cq-3-merge-gate`** *(Item #3 narrowed, M)* — starts after `cq-1` merges.
   - Lease: `scripts/worker-gate.sh`, `scripts/run-fast-tests.sh`, `scripts/regression-floor.sh`, `scripts/check-contract-change.ts`, `tests/QUARANTINE.json`, `tests/v7-dispatch-funnel.test.ts`, `tests/cq-3-merge-gate.test.ts`.
   - Validation: `worker-gate.sh` (<60s full fast-suite + quarantine + orphan + trailer checks) + batch-boundary `scripts/regression-floor.sh`.
4. **`agents/cq-13a-redaction-restore`** *(Item #13a P0 safety slice, S)* — starts immediately after `sys-q4-broker-auth` merges.
   - Lease: `src/server/broker.ts`, `src/server/derived-custody.ts`, `src/server/execution.ts`, `src/server/floor-recipes.ts`, `src/server/floor-recipe-engine.ts`, `tests/cq-13a-redaction-restore.test.ts`.
   - Validation: `worker-gate.sh` + `test:boundaries` + redaction fail-closed / `disposeRun` / `finally`-restore tests.
5. **`agents/cq-6-agent-contract`** *(Item #6, S)* — starts immediately after `sys-q1-worker-pool` + `sys-q2-repo-tools` merge.
   - Lease: `src/server/agent-tool-registry.ts`, `src/server/agent-session.ts`, `src/server/agent-prompts.ts`, `src/server/exec-worker-runner.ts`, `src/server/exec-dispatch.ts`, `src/server/verify-runner.ts`, `tests/agent-contract.test.ts`.
   - Validation: `worker-gate.sh` + `tests/agent-contract.test.ts` + `tests/sys-contract-canary.test.ts` + smoke tier verify_called check.
6. **`agents/cq-4-parity-corpus`** *(Item #4, M)* — starts immediately after `opencode/sys-host-autodag` + `cq-13a` merge (**serialized after `cq-13a`** on `floor-recipes.ts` / `floor-recipe-engine.ts`).
   - Lease: `tests/parity/**`, `tests/path-parity.test.ts`, `src/server/replay-verifier.ts`, `src/server/verify-claims.ts`, `src/server/proof-receipt.ts`, `src/server/floor-recipes.ts`, `src/server/floor-recipe-engine.ts`.
   - Validation: `worker-gate.sh` + `tests/path-parity.test.ts` (<2m) + **batch-boundary** `scripts/regression-floor.sh` + `tests/v8-seam1-golden-e2e.test.ts` (12/12 + 0 twin FPs).

#### Wave 3 — Typed Outcomes, Shipped Parity, Fixture Barrier, Typed Semantics, Manifest & Taxonomy Stage 1 (parallelized across disjoint leases after Wave 2)
7. **`agents/cq-5-typed-outcomes`** *(Item #5 + Q6 Frontier/Continuations, M)* — after `cq-6` & `cq-13a` merge.
   - Lease: `src/server/schema.ts` (step statuses), `src/server/exec-worker-runner.ts`, `src/server/exec-recon-planner.ts`, `src/server/exec-dispatch.ts`, `src/server/deterministic-engine.ts`, `src/server/exec-floor-lane.ts`, `benchmarks/realistic-bench/grader/attribution.ts`, `tests/cq-5-typed-outcomes.test.ts`.
   - Validation: `worker-gate.sh` + funnel attribution tests + smoke tier wall-clock/request non-regression.
8. **`agents/cq-8-shipped-parity`** *(Item #8 phased, M)* — parallel with `cq-5` (after `cq-2`, `cq-13a`, `sys-q5` merge).
   - Lease: `src/server/config.ts`, `src/server/execution.ts`, `src/server/store-findings.ts`, `scripts/hillclimb-loop.sh`, `scripts/benchmark-realistic.ts`, `scripts/smoke-agentic.ts`, `scripts/certify-phase1.ts`, `tests/cq-8-shipped-parity.test.ts`.
   - Validation: `worker-gate.sh` + `test:boundaries` + smoke A/B on `KOVO_RECON_SIBLINGS`; batch-boundary `--production-shaped` cell.
9. **`agents/cq-11-manifest-ratchet`** *(Item #11 narrowed, M)* — parallel with `cq-5` & `cq-8` (after `cq-3`, `cq-6`, `sys-host-autodag` merge).
   - Lease: `tests/capability-manifest.test.ts`, `tests/fixtures/capability-manifest.json`, `scripts/check-unwired.ts`, `src/server/composite-receipt.ts`, `src/server/terminal-oracle-registry.ts`, `ARCHITECTURE.md`, `package.json`, `tests/v7-stall-warmpool.test.ts`.
   - Validation: `worker-gate.sh` + `tests/capability-manifest.test.ts` + `madge` cycle check + `v8-seam1-golden-e2e.test.ts`.
10. **`agents/cq-9-fixture-barrier`** *(Item #9, M)* — **serialized after `cq-5`** (shares `exec-floor-lane.ts`) & `sys-q5` (`phase0-recon.ts`) & `cq-8` (`certify-phase1.ts`).
    - Lease: `scripts/check-v8-contamination.ts`, `scripts/generic-api-lexicon.json`, `benchmarks/realistic-bench/generator/variant.ts`, `src/server/probes/{traversal,xxe,cache,authz}.ts`, `src/server/deterministic-specs.ts`, `src/server/phase0-recon.ts`, `src/server/exec-floor-lane.ts`, `tests/cq-9-fixture-barrier.test.ts`.
    - Validation: `worker-gate.sh` + fixture-leak lint + **batch-boundary** `scripts/regression-floor.sh` + `floor-novel` cell (recorded in ledger + `CHANGELOG.md`).
11. **`agents/cq-10-typed-semantics`** *(Item #10, M)* — **serialized after `cq-4`** (parity corpus + `floor-recipe-engine.ts`) & **`cq-5`** (`schema.ts`).
    - Lease: `src/server/schema.ts`, `src/server/persona-identity.ts`, `src/components/personas/PersonaFormModal.tsx`, `src/server/oracle-invariants.ts`, `src/server/v8-oracle-hydrate.ts`, `src/server/floor-recipe-engine.ts`, `tests/cq-10-typed-semantics.test.ts`.
    - Validation: `worker-gate.sh` + `tests/path-parity.test.ts` + `tests/e2e-ui-journeys.test.ts` + opaque-persona-label ablation cell.
12. **`agents/cq-12a-taxonomy-conformance`** *(Item #12 Stage 1, S)* — **serialized after `cq-10`** (shares `oracle-invariants.ts`, `floor-recipe-engine.ts`).
    - Lease: `tests/taxonomy-conformance.test.ts`, `src/server/floor-recipe-engine.ts`, `src/server/exec-verify.ts`, `src/server/oracle-invariants.ts`.
    - Validation: `worker-gate.sh` + `tests/path-parity.test.ts` + `tests/taxonomy-conformance.test.ts`.

#### Wave 4 — Deferred Post-M2 Certification
- **`agents/cq-7-floor-policy-ab`** *(Item #7)*: 3-arm smoke A/B (75s vs 165s vs `hasPreHydratedFloorSnapshot`) after ledger is live; batch-boundary held-out before flipping `run-actor.ts`.
- **`agents/cq-12b-vuln-taxonomy`** *(Item #12 Stage 2)*: full `src/server/vuln-taxonomy.ts` migration + versioned `finding-fingerprint.ts` migration, gated on `tests/path-parity.test.ts` + `scripts/regression-floor.sh`.
- **`agents/cq-13b-run-scoped`** *(Item #13b)*: `RunScoped<K,V>` registry, module-level Map lint, served-scope pre/post check, and telemetry-first `strictRunScope` flip.

#### Explicit Merge Order & Serialization Exceptions
- **Merge order:** `[Option A sys-*]` → Wave 1 (`cq-1` → `cq-2`) → Wave 2 (`cq-3`, `cq-13a`, `cq-6` in parallel → `cq-4`) → Wave 3 (`cq-5`, `cq-8`, `cq-11` in parallel → `cq-9`, `cq-10` in parallel → `cq-12a`) → Wave 4 (`cq-7`, `cq-12b`, `cq-13b`).
- **Serialization exceptions (shared hot files):**
  - `scripts/benchmark-realistic.ts`: `cq-1` → `cq-2` → `cq-8`
  - `src/server/broker.ts`: `sys-q4-broker-auth` → `cq-13a`
  - `src/server/execution.ts`: `cq-13a` → `cq-8`
  - `src/server/exec-worker-runner.ts` & `src/server/exec-dispatch.ts`: `sys-q1-worker-pool` → `cq-6` → `cq-5`
  - `src/server/agent-session.ts` & `src/server/agent-prompts.ts`: `sys-q2-repo-tools` → `cq-6`
  - `src/server/verify-claims.ts` & `src/server/composite-receipt.ts`: `opencode/sys-host-autodag` → `cq-4` (then `cq-11` for cycle break)
  - `src/server/floor-recipes.ts` & `src/server/floor-recipe-engine.ts`: `cq-13a` → `cq-4` → `cq-10` → `cq-12a`
  - `src/server/schema.ts`: `cq-5` → `cq-10`
  - `src/server/oracle-invariants.ts`: `cq-10` → `cq-12a`
  - `src/server/phase0-recon.ts` & `src/server/exec-floor-lane.ts`: `sys-q5-phase0-graph` / `cq-5` → `cq-9`


