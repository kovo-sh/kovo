# Engine-port compatibility audit (v5.1 Slice 3 prep)

**Stream:** `compat-audit` (read-only analysis) — branch `agents/compat-audit`
**Base:** `main @ 0145c74` (assigning fixture). `main` advanced to `b316f80` (docs/worker-gate only) during the audit; no engine code differs.
**Engine branch:** `agents/engine-port @ 73c6c4e` (merge-base with main = `bb8976b`).
**Deliverable owner:** this file only. No engine or test file was modified.

---

## 1. What "merging engine-port" actually means

The engine-port delta against its own base is three source files plus its own test file:

| File | Delta |
| --- | --- |
| `src/server/execution.ts` | rewritten around a deterministic closed loop (~+977/−395) |
| `src/server/deterministic-engine.ts` | new, ~1.8k lines (triage → probes → verify → persist) |
| `src/server/deterministic-specs.ts` | new, ~1k lines (hypothesis → replay-spec synthesis) |
| `tests/v5-engine-port.test.ts` | new (14 contracts for the engine itself) |

`main` then **reverted** the merge (`a73f07e`) and continued to harden `execution.ts`
(Tier-3 origin-bound auto-approval, workflow-quantity synthesis, JWT body-token proof, …).
So `git diff main agents/engine-port` is **not** an engine-port delta: it also *removes* every
main-side commit made after the engine branch forked. Any integration that copies the file
wholesale re-introduces those losses (see RC-4). This is the single most important fact for
Slice 3.

## 2. Method

1. Scratch worktree = `main @ 0145c74` + `git checkout agents/engine-port --` the three engine
   files (i.e. the literal "merge the engine" state). `node_modules` symlinked; no other edits.
2. Baseline = unmodified `main` worktree, same `node_modules`.
3. Every suite run with `node --test --test-reporter=tap`, TAP parsed structurally
   (no raw logs or HTTP bodies inspected; only test ids, assertion names and counters).
4. Docker-dependent suites executed through `newgrp docker -c '…'`; without the group the
   baseline itself shows ~80 spurious failures, so **all tier comparisons below are docker-on**.
5. Isolation lever: `KOVO_DETERMINISTIC_ENGINE=0` (the engine's own disable switch) to
   prove which failures are caused by the in-Execution sweep.

### Baseline drift (not caused by engine-port)

With docker available, `main` already fails 6 leaf tests in the tier catalog:
`T1-11b` (jsHarvest), `T2-16d` (sql_time_diff jitter), `T2-26e` (benchmark-recall CLI),
`T4-01` (SIGKILL recovery), `T4-09` (SSE replay), `T4-14` (container escape). They are
environmental/flaky and are excluded from the regression count. `T2-10c` is additionally flaky
in the opposite direction (fails on main, passes on the port).

## 3. Root causes (5 clusters)

### RC-1 — Blocking sweep gate before any agentic dispatch  *(engine-regression)*

`driveInvestigation` now refuses to dispatch anything until a deterministic sweep completes:

```
execution.ts:3440  driveInvestigation(run, profiles)
         :3449    if (!this.deterministicCompleted.has(key)) { driveDeterministicInvestigation(...); return }
         :3453    // budget persistence
         :3460    expandEligibleMultiTrialSteps(run)
```

The sweep is bounded by **1800 requests / 240 s** (`deterministic-engine.ts:33-37`,
`execution.ts:4156-4164`), and resumes the agentic path only from the promise's `.finally`
(`execution.ts:3606-3630`). Everything that used to happen at *dispatch time* — dynamic step
budget, multi-trial fanout, specialist assignment/grant creation, planner review, K=6 stop —
now sits behind that gate.

Proof: with `KOVO_DETERMINISTIC_ENGINE=0` the sweep returns immediately and
`T1-22a`, `T1-24a`, `T2-22c` and `M4.8` all pass unchanged. With the engine on they fail on
their 0.5–8 s deadlines. This is an ordering contract break, not a modelling difference.

### RC-2 — M1 no-profile fallback was replaced, not extended  *(engine-regression)*

`main`'s `runDeterministicInvestigation` is a bounded direct probe pass that proposes **pending**
specs into the normal Zero-LLM verification queue. The port's version is engine-only and starts
with `if (!deterministicEngineEnabled()) return` (`execution.ts:3980-3986`). Consequences:

* flag **off** ⇒ no deterministic fallback at all (the legacy path no longer exists);
* flag **on** ⇒ the engine's inline-confirm funnel (confirmed finding / lead fact) replaces the
  propose-then-verify funnel.

On the `M1` fixture the engine's probes *do* run (≥4 recorded exchanges) but yield 0
`sql_boolean_diff` specs, so the legacy-confirmed detection is not at parity. The same gap is
visible end-to-end: `T4-08` runs a full deterministic CLI `scan --local-lab` and no longer exits 2
with a confirmed high finding.

### RC-3 — Deterministic lane engages before dispatch on profile-backed runs  *(engine-regression)*

`driveDeterministicInvestigation` registers `deterministicInFlight` synchronously
(`execution.ts:3595`) before the promise is created, and `driveInvestigation` calls it even when
`profiles.length > 0` (`execution.ts:3449-3451`). The frozen invariant "a profile-backed run never
enters deterministic mode" is therefore false even with the engine disabled. The design intent
(additive lane) is fine; the *bookkeeping and the gate position* are not.

### RC-4 — Wholesale `execution.ts` overwrite silently reverts main-side hardening  *(merge defect)*

`buildGrant` on the port branch lacks the Tier-3 local-lab auto-approval guards that main gained
after the engine branch forked. Port version:

```
if (allowLocalLab && KOVO_ALLOW_LOCAL_LAB === '1' && fresh.capabilityTier >= 3)
```

Main version additionally requires `project.environment === 'local-lab'`,
`approvalPolicy !== 'strict'`, `isLocalLabAutoApprovalOrigin(origin)`, and writes a
`recordAutoApprovalDecision` audit row **before** the state change leaves the broker
(main `execution.ts:1113-1241`). Not covered by any of the six suites, and `v5-tier3-safety`
passes 8/8 on the port, so this regression is currently *invisible to tests*.

### RC-5 — Funnel-shape contract change (expected, must be declared)  *(contract-change)*

Port-specific, intended changes that any test touching the deterministic funnel will hit:

| Before (main) | After (engine-port) |
| --- | --- |
| `deterministic_probes.summary` event | `deterministic_probes.complete` + `deterministic_engine.{start,lead,confirmed,hidden,complete}` |
| pending spec + verification worker | replay-confirmed finding, or `deterministic_engine_lead` **fact** (`execution.ts:4451-4487`) |
| per-finding dedupe key `(origin, CWE)` | structural dedupe/rotation by `(origin, endpoint, method, param, class family)` (`execution.ts:4276-4300`) |
| agentic work always dispatched | agentic spec rejected if its `(endpoint, class family)` was never triaged, and frozen if the class was already engine-confirmed (`agenticSpecInDeterministicScope`, `execution.ts:3559-3588`) |

`persistDeterministicConfirmed` returns `null` for `static_ast_proof` (`execution.ts:4278`):
white-box `static_verified` still comes from specialists, but nothing guards this invariant.

---

## 4. Classification table (measured)

"Legacy" = behaviour on `main @ 0145c74`. Line refs are into `tests/v4-e2e-tiers.test.ts`
unless another file is named.

| # | Test | Expected behaviour | What engine-port changed | Class | Minimal fix | Slice |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `T1-22a` dynamicStepBudget clamp BVA (`v4-e2e-tiers:2754`) | `dynamic_step_budget = clamp(24, crown*2+suspects, 200)` persisted at investigation start | persistence moved below the sweep gate → stays `null` | **engine-regression** | compute + persist budget at `driveInvestigation` entry, before the profile branch | 3 |
| 2 | `T1-22c` K=6 dry-step stop (`:2819`) | 6 dry steps ⇒ phase advances to verification | K=6 branch only reachable after the sweep; window consumed by the gate | **engine-regression** | same ordering fix; sweep must not own the only path to the K=6 check | 3 |
| 3 | `T1-22d` `needs_follow_up` coverage ranking (`:2857`) | planner gets ≥1 LLM turn and prioritises open coverage | planner never dispatched until sweep completes | **engine-regression** | same ordering fix | 3 |
| 4 | `T1-23b` specialist turn-cap BVA (`:2920`) | step routed to specialist; turn cap 25–40 ≤ 60 | no specialist assignment created (dispatch gated) | **engine-regression** | same ordering fix | 3 |
| 5 | `T1-23d` specialist scoped tools/skills (`:2969`) | each profile's grant has its scoped tools + skills | no assignment ⇒ no grant to inspect | **engine-regression** | same ordering fix | 3 |
| 6 | `T1-24a` multi-trial fanout trigger (`:3016`) | priority ≥ 88 ⇒ ≥2 trials, priority 40 ⇒ 1 | fanout called only after sweep; 500 ms deadline hits first | **engine-regression** | call `expandEligibleMultiTrialSteps` before/independently of the sweep | 3 |
| 7 | `T1-24b` fanout BVA 2/3/3 (`:3049`) | 2 default, 3 critical, ceiling 3 | same as #6 | **engine-regression** | same as #6 | 3 |
| 8 | `T2-22c` planner-side K=6 halt (`:6386`) | dry planner exits investigation ≤3.5 s | gated behind the sweep | **engine-regression** | same as #2 | 3 |
| 9 | `T2-23a` BOLA/BFLA specialist tools (`:6442`) | scoped tools, no XSS/SSRF clutter | no assignment/grant | **engine-regression** | same as #4 | 3 |
| 10 | `T2-23b` injection specialist tools | sqli/xxe/IAST tools + skills | no assignment/grant | **engine-regression** | same | 3 |
| 11 | `T2-23c` auth/oauth specialist tools | auth_protocol/canary/verify | no assignment/grant | **engine-regression** | same | 3 |
| 12 | `T2-23d` client/browser specialist tools | browser/WS/xss_context | no assignment/grant | **engine-regression** | same | 3 |
| 13 | `M4.8` multi-trial early-stop (`v4-m4:675`) | fanout 2 at priority 90; first confirmation cancels sibling + `trial.early_stopped` | fanout gated ⇒ 1 trial; early-stop never reached | **engine-regression** | same as #6 | 3 |
| 14 | `M1 fallback: zero profiles probe … propose deterministic findings` (`v5-m1:826`) | legacy probe pass: ≥4 exchanges, 1 `sql_boolean_diff` spec, pending finding, verification worker, `differential_anomaly` fact | legacy pass deleted; engine runs but proposes 0 specs; flag-off is inert | **engine-regression** (recall parity) | keep legacy pass under flag-off; engine parity under flag-on | 2 |
| 15 | `M1 fallback: agentic path untouched when a profile exists` (`v5-m1:908`) | `deterministicInFlight`/`Completed` empty, no deterministic worker | key registered synchronously before dispatch | **engine-regression** (invariant) | don't register the lane on profile-backed runs unless flag on; separate lane set | 3 |
| 16 | `T2-24b` early-stop cancels sibling in SQLite (`:6633`) | losing sibling reaches `canceled` when trial 0 confirms | winner's confirmation never dispatched ⇒ sibling finishes `complete` (50 s) | **engine-regression** | same ordering fix as #6; early-stop trigger must not depend on the sweep | 3 |
| 17 | `T2-24e` `trial.early_stopped` SSE event (`:6753`) | event emitted on sibling cancellation | no cancellation ⇒ no event | **engine-regression** | same as #16 | 3 |
| 18 | `T3-24` crown-jewel lead → 2 trials → cancel sibling (`:8114`) | 2 parallel trials, first confirmation cancels the other | fanout suppressed by the sweep gate | **engine-regression** | same as #6 | 3 |
| 19 | `T4-08` full `kovo-hunter scan --local-lab --sarif` (`:8560`) | deterministic CLI exits 2 on a confirmed high finding; SARIF/MD/summary valid | scan finishes without the confirmed finding (exit 1) | **engine-regression** (product floor) | restore the legacy deterministic pass (flag off) before the engine lane; parity-gate the engine | 2 |

Measured: **19 regressions in the six files** (16 tier leaves + 3 contract-file tests), plus 6
pre-existing baseline flakes. The recorded "25" is the same failure population counted with the
tier aggregate rows and the docker-less environment, where specialist/worker tests fail
spuriously; it is not a different defect set.

### What is *not* a regression

The port touched only three files, so these are **unchanged and must stay green**:
`computeDynamicStepBudget` / `computeMultiTrialFanout` bodies, `expandEligibleMultiTrialSteps`,
trial early-stop abort + `trial.early_stopped` emission (`execution.ts:3211-3250`),
`countConsecutiveDrySteps`, DELETE never probed (`execution.ts:3988-3991`), specialist profile
definitions, and the whole replay verifier. Confirmed by running the suites on the port with the
engine disabled: `T1-22a`, `T1-24a`, `T2-22c`, `M4.8` pass outright. The multi-trial tests
(`T1-24a/b`, `T2-24b/e`, `T3-24`, `M4.8`) fail **only** because the confirmation that triggers
early-stop is never dispatched — the cancellation machinery they exercise is intact.

---

## 5. The eight focus areas, one line each

1. **Sweep-before-dispatch gating** — RC-1. It is a *sequencing* decision, not a modelling one; the
   gate blocks budget, fanout, scopes, planner and K=6.
2. **`dynamicStepBudget` null** — RC-1 symptom. Budget is a pure function of facts/endpoints; it has
   no reason to wait for a sweep and must be written before the profile branch.
3. **K=6 stop** — RC-1 symptom in two places (`driveInvestigation` and the planner). The counting
   logic itself is byte-identical to main and correct.
4. **M1 no-profile fallback** — RC-2. The engine replaced the fallback instead of adding to it, and
   its disable switch makes the run inert rather than falling back.
5. **Multi-trial early-stop** — RC-1 symptom. Fanout is the only trigger for early-stop, so
   `M4.8`, `T1-24a/b`, `T2-24b/e` and `T3-24` fail together; the abort/SSE machinery is untouched,
   and the losing sibling simply runs to `complete` instead of `canceled`.
6. **Specialist tool scopes** — RC-1 symptom. Grants are built from assignments; with no assignment
   there is no scope to assert. No scope list changed in the port.
7. **DELETE / Tier policy** — preserved. The engine filters `method !== 'DELETE'`
   (`execution.ts:3991`) and requires `capabilityTier ≥ 1`; the destructive-method test passes.
   *However* RC-4 weakens Tier-3 auto-approval; that is a containment regression, not a DELETE one.
8. **Confirmed-pair hiding/dedupe** — implemented but risky: `hideDeterministicConfirmedSteps`
   sets ready/pending steps to `canceled` (`execution.ts:3533-3552`). It exempts steps with
   `dependsOnStepIds` and chain-like titles, which matches the "never break chains" trap, but the
   pair sets are **in-memory only** (`execution.ts:951-953`) and fail open after restart, and
   `agenticSpecInDeterministicScope` suppresses a whole class family once one endpoint confirms.
   Slice 5 must persist pairs and add an explicit chain-preservation test.

---

## 6. Ordered checklist for Slice 3

1. **Merge hygiene first.** Never `git checkout agents/engine-port -- src/server/execution.ts`.
   Port Slice 1/2 as modules + named hunks. Diff `buildGrant` explicitly and keep main's Tier-3
   guards (`environment === 'local-lab'`, `approvalPolicy !== 'strict'`,
   `isLocalLabAutoApprovalOrigin`, `recordAutoApprovalDecision`).
2. **Land `deterministic-engine.ts` + `deterministic-specs.ts` alone** (Slice 1). Verified safe:
   `npm run check` passes with them on top of unmodified main; they depend only on existing
   `surface-engine`, `replay-verifier`, `dedupe`, `broker`, `store`, `worker-backend` exports.
3. **Split the fallback instead of replacing it** (Slice 2): keep `main`'s
   `runDeterministicInvestigation` as the flag-off path; add the engine as the flag-on path.
   Invert the switch: opt-in (`KOVO_DETERMINISTIC_ENGINE=1`), not opt-out.
4. **Move budget persistence to the top of `driveInvestigation`**, before the
   `profiles.length` branch. This alone clears #1 and unblocks the K=6/planner paths.
5. **Move `expandEligibleMultiTrialSteps` + `refreshReadyChainSteps` ahead of the sweep** so fanout
   and early-stop are independent of triage.
6. **Make the sweep non-blocking**: start it, do not `return`. Dispatch the agentic lane
   concurrently behind the flag, with the seeded-step guard, the 30 % / 180 s cap, K=6 and budget
   isolation, and no step cancellation.
7. **Separate lane bookkeeping** so profile-backed runs do not populate `deterministicInFlight`
   before the sweep is actually started (restores #15's invariant).
8. **Narrow the engine budget in agentic mode** to the plan's 30 % / 180 s; 1800 req / 240 s is only
   defensible in the no-LLM lane.
9. **Validate** in this order: contract suites
   (`v5-m1-wiring-correctness`, `v4-m4-surface-orchestration`, `v5-m2-auth`, `v5-m0-realistic-harness`,
   `v5-m3-probes3`) → tier catalog with docker → `Execution --no-llm ≥ 25/59 @ 100 %` →
   agentic strictly additive at ≥ 95 % precision and ≤ 10 pp held-out gap → full gate with the flag
   **forced on**.
10. **Then** flip the default and record the result in `plans/ROADMAP-v5.md`.

## 7. Tests to update vs invariants to preserve

**Must be updated (contract-change) — only after the order is fixed:**

| Test | Change |
| --- | --- |
| `v5-m1-wiring-correctness` M1 #1 (tail assertions) | pending-spec + `verifyWorkers===1` → engine-confirmed finding *or* lead fact; `deterministic_probes.summary` → `deterministic_probes.complete` / `deterministic_engine.*` |
| new `v5-m1-wiring-correctness` case for flag-on | assert additive contract: no step cancellation outside confirmed pairs, fanout preserved, budget non-null |
| `v4-e2e-tiers` `T1-22a/c/d`, `T1-23b/d`, `T1-24a/b`, `T2-22c`, `T2-23a-d`, `M4.8` | **no change expected** once §6.4–6.7 land; these are the regression detectors |

**Invariants that must be preserved (do not rewrite the tests):**

1. `dynamic_step_budget` is non-null and correct the moment investigation starts.
2. Multi-trial fanout and `trial.early_stopped` work at dispatch time, with K=6 and budget isolation.
3. A profile-backed run never enters deterministic mode unless the additive flag is on.
4. No model profile ⇒ a real deterministic floor exists (never inert).
5. Specialist grants keep their scoped tools/skills and turn caps.
6. DELETE/unsafe methods are never probed by the engine.
7. White-box `static_verified` findings stay static and are never upgraded by the engine.
8. Confirmed pairs hide duplicates **without** cancelling chain/dependent steps.
9. Ladder approvals keep origin binding, strict-precedence and audit attribution.

## 8. Reproduction

```bash
# scratch: main + engine-port files
git worktree add -f /tmp/port-probe -b probe/engine-port-on-main 0145c74
git -C /tmp/port-probe checkout agents/engine-port -- \
  src/server/execution.ts src/server/deterministic-engine.ts \
  src/server/deterministic-specs.ts tests/v5-engine-port.test.ts
ln -sfn "$PWD/node_modules" /tmp/port-probe/node_modules

# contract suites (no docker)
cd /tmp/port-probe && node --test --test-reporter=tap \
  tests/v4-m4-surface-orchestration.test.ts tests/v5-m1-wiring-correctness.test.ts \
  tests/v5-m2-auth.test.ts tests/v5-m0-realistic-harness.test.ts tests/v5-m3-probes3.test.ts

# tier catalog (docker required; baseline needs it too)
newgrp docker -c "cd /tmp/port-probe && node --test --test-reporter=tap tests/v4-e2e-tiers.test.ts"

# isolation lever proving RC-1
KOVO_DETERMINISTIC_ENGINE=0 node --test --test-reporter=tap \
  --test-name-pattern='T1-22a|T1-24a|T2-22c' tests/v4-e2e-tiers.test.ts
```

## 9. Limitations

* Read-only: no engine fix was attempted, so every "minimal fix" is a hypothesis backed by the
  disable-switch experiment, not by a green run.
* All six assigned files were re-run to completion with docker. The product-level `T4-08` failure
  and the multi-trial cluster (`T2-24b/e`, `T3-24`, `M4.8`) were verified individually; other
  Execution-driven tier workflows that also traverse the same 240 s gate were not itemised beyond
  the ones that actually failed.
* The recorded "25 regressions" could not be reproduced as an exact count: with docker available
  the comparable set is 19, plus 6 baseline flakes and 4 tier aggregate rows. The defect
  population is the same; only the counting convention differs.
