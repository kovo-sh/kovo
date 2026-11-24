# Conversion autopsy — why 140 agent investigations converted 1 planted target

**Status:** diagnostic only. No detection logic changed, no benchmarks re-run.
**Data:** kept cells from the final dev + salted held-out agentic matrices (seed 1 and 1000042,
grey-box, 600 s wall cap per cell). **Branch:** `agents/conversion-autopsy` (base `f86757c`).
**Artifact:** `scripts/conversion-autopsy.ts` (read-only) + its JSON output; every number below is
reproducible from the kept sqlite stores and result JSON without touching the network.

```bash
node scripts/conversion-autopsy.ts --json /tmp/conversion-autopsy.json
```

The script resolves each seed's runtime route map from the app blueprints (`generateVariant`), reads
`guardian.sqlite`, `agent-sessions/*.sqlite`, and the cell `.json`, and prints only structured
fields. It does not read response bodies, does not print payloads, and never writes to the data
dirs. The held-out salt is read from the owner-only file and never printed.

---

## Headline

| | Count |
|---|---:|
| Planted targets (6 cells) | 117 |
| Confirmed by the deterministic floor (`Execution --no-llm`) | 64 |
| Confirmed **only** by an agent investigation (increment) | **1** |
| Confirmed total | 65 |
| Planted-but-unfound | **52** |
| Planned chain steps | 270 |
| Steps that ever received an assignment | 117 (43%) |
| Agent investigation rows dispatched | **140** |
| Completed investigation rows | **67** = 61 agent + 6 deterministic-engine |
| Agent finding proposals | 43 |
| Proposals that never reached a verdict (`pending/open_proof_gap`) | 24 |
| Proposals that reached a verdict | 19 (2 confirmed, 1 dismissed, 16 inconclusive) |
| Net-new targets from all agent work | **1** (`review-stored-xss`, held-out shopflow) |

The brief's "67 agent investigations" is exactly the **67 completed investigation rows** (61 agent
assignments + the 6 deterministic-engine rows that are stored with `phase = 'investigation'`). The
broader picture: 142 agent assignment rows exist, 140 actually dispatched — 61 completed, 45
stall-canceled, 36 paused at the cell deadline, 2 never produced a trace. The agentic increment over
the floor is 1 target in both framings.

---

## Bucket table

One row per planted-but-unfound target (52 rows). Buckets are applied in this precedence:

1. **`never_dispatched`** — no agent request was ever made on any entry/trigger route of the target.
   Sub-reasons: `no_planned_step_named_route`, `step_<status>_never_assigned`,
   `assigned_but_route_untouched`.
2. **`route_hit_no_verify`** — the route was requested, but no `guardian_verify` /
   `verify_replay_spec` call was **bound to that route** and no replay spec was recorded for it.
3. **`verify_called_but_oracle_rejected`** — a verify verdict artifact exists for the target and is
   non-confirming; the normalized reason code is recorded.
4. **`probed_missed_bug`** — verify ran (or a spec was recorded) but no target-bound verdict exists;
   the evidence simply did not show the bug.

| Suite | App | Targets | Floor | Agent inc. | Missed | Never dispatched | Route hit, no verify | Oracle rejected | Probed, missed |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dev | acme-saas | 22 | 14 | 0 | 8 | 2 | 2 | 4 | 0 |
| dev | opsportal | 18 | 10 | 0 | 8 | 0 | 5 | 1 | 2 |
| dev | shopflow | 19 | 12 | 0 | 7 | 3 | 4 | 0 | 0 |
| heldout | acme-saas | 22 | 11 | 0 | 11 | 2 | 7 | 1 | 1 |
| heldout | opsportal | 17 | 7 | 0 | 10 | 4 | 3 | 3 | 0 |
| heldout | shopflow | 19 | 10 | 1 | 8 | 4 | 3 | 0 | 1 |
| **total** | | **117** | **64** | **1** | **52** | **15** | **24** | **9** | **4** |

Investigation roll-up (each dispatched investigation counted once, at its furthest-progress bucket):

| Bucket | Investigations | Target rows |
|---|---:|---:|
| `never_dispatched` | 4 | 15 |
| `route_hit_no_verify` | 15 | 24 |
| `verify_called_but_oracle_rejected` | 9 | 9 |
| `probed_missed_bug` | 4 | 4 |
| planned units with **no** assignment | 10 | 10 |

So the largest single class is **not** an oracle problem: 24/52 targets were requested by an agent
that never submitted a route-bound proof. The next is pure dispatch starvation (15/52).

---

## Per-app operations

`stopReason` is identical in all six cells: **the 600,000 ms wall-clock cap was reached while the run
was in `investigation`, and the run was stopped**. `terminalStatus=stopped`,
`terminalPhase=investigation`, `timedOut=true`, `durationMs` 600,070–600,340.

| Suite | App | stopReason | Dispatched / planned steps | Distinct steps assigned | Stall-canceled | Paused at cap | Targets never touched |
|---|---|---|---:|---:|---:|---:|---:|
| dev | acme-saas | wall-clock cap 600,000 ms, stopped/investigation | 20 / 52 | 16 | 10 | 6 | 2 |
| dev | opsportal | wall-clock cap 600,000 ms, stopped/investigation | 23 / 40 | 18 | 8 | 6 | 0 |
| dev | shopflow | wall-clock cap 600,000 ms, stopped/investigation | 22 / 41 | 19 | 4 | 6 | 3 |
| heldout | acme-saas | wall-clock cap 600,000 ms, stopped/investigation | 27 / 57 | 25 | 8 | 6 | 2 |
| heldout | opsportal | wall-clock cap 600,000 ms, stopped/investigation | 21 / 33 | 19 | 3 | 6 | 4 |
| heldout | shopflow | wall-clock cap 600,000 ms, stopped/investigation | 27 / 47 | 20 | 12 | 6 | 4 |

Paused is exactly **6 in every cell** — one per worker slot (`workerConcurrency: 6`). The run did not
wind down; it was cut off with a full fleet mid-investigation.

Depth and verification breadth:

| Suite/app | Agent turns | Turns on stall-canceled | Turns on paused | Verified any route | Never verified |
|---|---:|---:|---:|---:|---:|
| dev/acme-saas | 284 | 158 | 49 | 6 | 14 |
| dev/opsportal | 327 | 105 | 76 | 8 | 15 |
| dev/shopflow | 283 | 34 | 49 | 4 | 18 |
| heldout/acme-saas | 306 | 88 | 22 | 3 | 24 |
| heldout/opsportal | 292 | 31 | 70 | 2 | 19 |
| heldout/shopflow | 319 | 136 | 40 | 6 | 21 |
| **total** | **1,811** | **552 (30%)** | **306 (17%)** | **29 (21%)** | **111 (79%)** |

Only 29 of 140 investigations ever called `guardian_verify` or `verify_replay_spec` at all (53 calls
in total). 47% of all agent turns were spent in investigations that never reached a terminal state.

---

## Cross-tab against the deterministic funnel

| Truth bucket | never dispatched | route hit, no verify | oracle rejected | probed, missed |
|---|---:|---:|---:|---:|
| `replay_spec_miss` (13) | 4 | 7 | 1 | 1 |
| `hypothesis_miss` (18) | 6 | 7 | 3 | 2 |
| `context_reset` (9) | 0 | 5 | 3 | 1 |
| `budget_exhausted` (5) | 5 | 0 | 0 | 0 |
| `form_encoding_missing` (5) | 0 | 4 | 1 | 0 |
| `csrf_blocked` (2) | 0 | 1 | 1 | 0 |

Two things stand out. All 5 `budget_exhausted` targets were never dispatched at all — the funnel
labels them budget, the autopsy says they never got a slot. And `replay_spec_miss` is not mostly an
oracle problem: 11 of 13 were never verified on the route, or never reached.

---

## What each bucket actually looks like

### `never_dispatched` — 15 targets

Breakdown: 6 no planned step names the route, 3 step `ready` and never assigned, 1 step `canceled`
and never re-queued, 5 assigned but the route was never requested.

Representative rows:

| Target | Why |
|---|---|
| `acme.seat-invariant` (dev) | Step 40 names `POST /api/seats`; status `ready`; zero assignments. |
| `acme.invite-workflow-skip` (dev) | Step 50 names `POST /api/enrollments/accept`; status `ready`; zero assignments. |
| `giftcard-race` (dev shopflow) | Step 14 (`POST /api/v1/store-credit/:creditId/redeem`) canceled, never re-queued; no request on the route. |
| `coupon-after-lock` (dev shopflow) | Step 37 ran 17/30 and was paused at the cap; the re-apply route was never requested. |
| `acme.webhook-forgery` (held-out) | Step 56 got a 2/30-turn assignment and was paused before requesting `POST /api/hooks/receive`. |
| `payment-webhook-forgery` (both shopflow seeds) | No planned step references the inbound callback route. |
| `acme.jwt-none` (held-out) | No step references `POST /api/auth/token`. |
| `og.dashboard-cache-poison`, `og.log-filter-sqli`, `checkout-open-redirect` | No step references the dashboard, journal-filter, or checkout-return routes. |

The 6 "no planned step" cases are a planner coverage gap, not a scheduler gap: the routes were
discovered as endpoints but no step ever named them. The other 9 were planned and lost to the cap.

### `route_hit_no_verify` — 24 targets

These are the cleanest product bug. Mean 18.3 turns used; the route was requested; a proof was never
attempted. End state: 13 provider-stall cancels, 8 completed, 3 wall-clock pauses.

Final tool per row: `complete_intent` 8, `request_http` 7, `request_http_batch` 3,
`probe_surface` 2, `propose_chain_finding` 2, `load_skill` 1, unbound `verify_replay_spec` 1.
Across the final three calls of these rows, bookkeeping dominates (`record_coverage` 12,
`complete_intent` 8, `board_post` 3). Most rows end in probing that was cut off; the 8 "completed"
rows close their coverage without a proof.

Only 5 of the 24 recorded a coded proof gap: `no_reproducible_signal` ×3, `baseline_empty` ×1,
`runtime_unavailable` ×1. The other 19 simply stopped.

Clean examples: `og.viewer-bfla` (dev) used all 30/30 turns, closed with
`record_coverage` → `record_coverage` → `complete_intent`, and never verified;
`api-jwt-alg-none` (dev shopflow) completed at 11/30 with no verify;
`acme.invite-workflow-skip` (held-out) completed at 29/30 with `no_reproducible_signal`.

### `verify_called_but_oracle_rejected` — 9 target rows (8 distinct targets)

| Target | Verdict | Normalized reason |
|---|---|---|
| `acme.member-role-privesc` (both suites) | inconclusive | `no_cross_actor_differential` — actor is in the resource tenant |
| `acme.report-ssti` (dev) | inconclusive | `control_error_status` — control step returned 404, `requireControlNonError` |
| `acme.report-cache-poison` (dev) | inconclusive | `control_error_status` — same control, same 404 |
| `acme.legacy-auth-bypass` (dev) | dismissed | `no_reason` (final turn was a max-turn close) |
| `og.log-filter-sqli` (dev) | inconclusive | `no_semantic_oracle` — no failing probe arm |
| `og.account-bola-write` (held-out) | inconclusive | `no_persisted_impact` — post-mutation readback identical |
| `og.viewer-bfla` (held-out) | inconclusive | `no_cross_actor_differential` |
| `og.ticket-assign-cross-write` (held-out) | inconclusive | `status_only` — 2xx is not an access-control differential |

Three of these are the same rule (`oracle-invariants.ts:762`): the probe wrote inside its own tenant,
so the oracle sees policy-compliant behaviour. Two are a spec-authoring bug: the cross-tenant
control used an object the attacker cannot see, got 404, and failed `requireControlNonError`
instead of proving the second-order render.

One is a **measurement attribution problem, not an engine miss**: `og.ticket-assign-cross-write`
(the agent's own outcome says "[proved] Promoted the cross-tenant case REASSIGNMENT write-BOLA lead
to a runtime-confirmed finding") produced confirmed finding `4b26dfbf`, but the grader matched that
finding to the sibling target `og.ticket-bola-read`. The target that names the assign route is then
scored missed. Confirmed precision stays 100%, but one real proof is being counted against the wrong
planted site.

### `probed_missed_bug` — 4 targets

`og.user-mass-assignment` (24/30), `og.search-sqli` (14/30), `acme.auditlog-secret` (29/30),
`api-jwt-alg-none` held-out (8/30). Each called verify 1–2 times but no target-bound verdict was
recorded, and the probes did not produce the planted signal. These are probe-quality misses, not
scheduling losses.

---

## Top 3 concrete causes

### Cause 1 — Dispatch starvation: the 600 s cap plus stall churn and trial fan-out

The cap is the binding constraint, and it lands on a full fleet.

- All six cells: `maxDurationMs=600000`, `durationMs≈600.2s`, `timedOut=true`,
  `terminalPhase=investigation`. The 600 s value is passed by the recall harness itself
  (`scripts/hillclimb-loop.sh:53`, `--max-duration-ms 600000`), not the 15 min default
  (`scripts/benchmark-realistic.ts:92`). The deadline is awaited at
  `scripts/benchmark-realistic.ts:3116` and the stop is recorded at `:3127`.
- 153 of 270 planned steps never received an assignment; **87 of those were `ready`** at the stop.
- Exactly 6 investigations are `paused` in every cell — one per worker slot. 306 turns (17%) were in
  flight at the cut.
- 45 provider-stream stalls (`worker.provider_stall`) cancel 45 investigations and burn 552 turns
  (30%). The watchdog aborts a turn after 28 s with no token
  (`src/server/execution.ts:1448`), and `MAX_PROVIDER_STALL_RETRIES = 1` (`:1442`) requeues once.
  For a reasoning model whose thinking phase can exceed 28 s of stream silence, this is a systematic
  tax.
- Trial fan-out is already gated on surplus slots (`planMultiTrialExpansion`,
  `src/server/execution.ts:749-783`, `multiTrialSurplusSlots` at `:734`). The residue is that the
  gate is evaluated on the queue at one instant and ignores in-flight work: when the queue is
  momentarily shallow, a p100 step expands to 3 trials (`computeMultiTrialFanout`, `:551-563`), and
  those duplicates persist into later rounds. 21 trial rows consumed 287 turns (16%). Example: the
  acme dev auth step ran trials 0/1/2 (all p100); two were stall-canceled and the third closed at
  18/18 without `complete_intent`, while that cell ended with 36 steps still unassigned.

### Cause 2 — The proof obligation is not enforced per route, and one coded gap discharges all of them

111 of 140 investigations (79%) never called a verify tool. 24 of 52 missed targets were requested
and then dropped without a route-bound proof.

- `specSubmissionPending` (`src/server/agent-session.ts:604-606`) is:
  `probes > 0 && codedProofGaps === 0 && !targetCovered`.
  `codedProofGaps` is a single global counter (`:488`), and `targetCovered` is the last route that a
  spec matched. **A coded `record_coverage` gap on any route removes the obligation for every
  subsequently probed route.** Five of the 24 no-verify rows closed exactly this way
  (`no_reproducible_signal`, `baseline_empty`, `runtime_unavailable`).
- The 85% settlement path (`agent-session.ts:170`, `:187`) revokes all network probing tools, so the
  last 15% of turns cannot collect new evidence. 8 dispatched investigations reached that threshold
  without ever verifying.
- The settlement tool gate (`:811`) explicitly offers the gap as an alternative to
  `guardian_verify`. Agents take it: for the 24 no-verify rows, the final three calls are dominated
  by `record_coverage` (12), `complete_intent` (8) and `board_post` (3), while only one row ends on a
  verify tool (and that call was not bound to the target route).
- Proposal funnel: 43 agent proposals → 24 `pending/open_proof_gap`, 16 `inconclusive`, 2
  `confirmed`, 1 `dismissed`. 40 of 43 were never confirmed.

### Cause 3 — The oracle rejects the evidence shape agents produce (and two specs are built wrong)

9 of 52 targets got a coded non-confirming verdict; another 4 probed without producing the signal.

- `oracle-invariants.ts:762`: a mutating probe is accepted only if it crosses a privilege/ownership
  boundary. Agents repeatedly wrote inside their own tenant (3 of 9 rejected rows, and 6 specs
  overall — the single most common rejection family).
- `oracle-invariants.ts:965`: a read-only proof is rejected when the response body is not JSON
  ("no object-scoped attribute can be bound"). Four specs died on this rule; it also blocks
  re-verifying the text-body path traversal that the deterministic floor already confirms.
- `oracle-invariants.ts:1992`: CSRF claims are dismissed when the route is not modelled as
  `csrf_state_change` (six specs), even though two planted CSRF targets exist (`og.viewer-bfla`,
  `og.job-csrf`).
- `control_error_status` ×2: the report second-order specs used a cross-tenant control object the
  attacker cannot see, got 404, and failed `requireControlNonError`. The oracle's advice ("declare
  expectedStatus 404") would make the control meaningless; the spec should act as the owner for the
  control arm and as the attacker for the probe arm.

---

## Ranked fixes (smallest first)

1. **Prompt/spec rule: controls must use an object the actor can legitimately see.**
   `src/server/assignment-brief.ts` (the verify-shape guidance near `:557`) — add one line: a
   cross-tenant control arm must be a request that succeeds for the control actor; never declare
   `expectedStatus: 404` to paper over a missing object. Cost: text only. Recovers 2 rows
   (`report-ssti`, `report-cache-poison`).
2. **Stall watchdog: make the 28 s no-token window profile-aware.**
   `src/server/execution.ts:1448` — treat reasoning profiles (or a stream that emits a reasoning
   heartbeat) as needing 45–60 s before abort. Cost: one constant/one branch. Addresses 45 aborts
   and 552 lost turns; verify with the smoke tier, not a full matrix.
3. **Demote unstarted trial duplicates when a new distinct hypothesis arrives.**
   `src/server/execution.ts:749-783` already gates fan-out on surplus slots, so do not change that
   invariant. Instead, on a planner round that enqueues distinct steps, move `trialIndex > 0` steps
   that have not started behind the new work (or cancel them). Cost: small, keeps
   `tests/v7-dispatch-funnel.test.ts` green. Reclaims up to 287 turns across 21 trial rows.
4. **Per-route proof gaps.** `src/server/agent-session.ts:604-606` — key `codedProofGaps` and
   `targetCovered` by `method + path` (or by the current `SpecRouteEvidence`) instead of a global
   counter, so a gap on route A cannot discharge route B. Keep `complete_intent` gated on the
   *current* route. Cost: ~15 lines. Directly targets 24/52 missed targets and the 19 rows that
   stopped with no gap at all.
5. **Planner coverage for discovered-but-unplanned high-risk routes.**
   `src/server/execution.ts` (`dispatchChainRound`, `:8419`) — after a planner round, assert that
   every discovered endpoint with `risk_score ≥ 80` and an unguarded mutation verb has at least one
   step or an explicit `ruled_out` coverage entry. Cost: medium. Recovers the 6 targets with no
   planned step (`dashboard`, `journals/filter`, `checkout/return`, inbound webhook ×2,
   `auth/token`).
6. **Non-JSON body binding for read-only proofs.** `src/server/oracle-invariants.ts:965` — allow a
   bounded canary/byte-diff binding when the body is not JSON (path traversal, open redirect,
   secret-in-text), with the existing precision tests extended. Cost: medium; must be measured for
   false positives. Recovers the 4 `unbindable_non_json_body` specs and unblocks the agent
   re-verification of a class the floor already confirms.
7. **Raise the recall-tier wall cap.** `scripts/hillclimb-loop.sh:53` — `600000` → `900000` (or a
   `--recall` preset) once fixes 2–4 have reduced per-cell churn. Cost: 1 line but real spend; only
   worth it after the free wins.

Two measurement items that are not product fixes:

- The `og.ticket-assign-cross-write` finding is real and confirmed but attributed by the grader to
  the sibling `ticket-bola-read` target. Check the grader's one-finding-per-target mapping before
  reading that row as an engine miss.
- All six cells used 600 s, not the 15 min default, so these numbers understate recall at the
  intended tier. Do not compare them to a 45 min run.

---

## Missed-target ledger (52 rows)

`Truth bucket` is the deterministic-funnel label in the cell `.json`; `Autopsy bucket` is what the
agent evidence shows. Route paths are templates, not payloads.

| Suite | App | Target | Class | Truth bucket | Autopsy bucket | Evidence |
|---|---|---|---|---|---|---|
| dev | acme-saas | `acme.invoice-bola` | bola | replay_spec_miss | **route_hit_no_verify** | step 3, 25/30, provider_stall, no route-bound verify |
| dev | acme-saas | `acme.member-role-privesc` | mass_assignment | hypothesis_miss | **verify_called_but_oracle_rejected** | step 2, 21/30, `no_cross_actor_differential` |
| dev | acme-saas | `acme.report-ssti` | ssti | context_reset | **verify_called_but_oracle_rejected** | step 7, 24/30, `control_error_status` |
| dev | acme-saas | `acme.project-stored-xss` | xss_stored | replay_spec_miss | **route_hit_no_verify** | step 1, 14/30, provider_stall, no route-bound verify |
| dev | acme-saas | `acme.report-cache-poison` | cache_poisoning | context_reset | **verify_called_but_oracle_rejected** | step 1, 14/30, `control_error_status` |
| dev | acme-saas | `acme.seat-invariant` | business_logic | budget_exhausted | **never_dispatched** | step 40 ready, never assigned |
| dev | acme-saas | `acme.invite-workflow-skip` | workflow_bypass | budget_exhausted | **never_dispatched** | step 40 ready, never assigned |
| dev | acme-saas | `acme.legacy-auth-bypass` | auth_bypass | replay_spec_miss | **verify_called_but_oracle_rejected** | step 18, 18/18, `no_reason` (max-turn close) |
| dev | opsportal | `og.ticket-note-xss` | xss_stored | form_encoding_missing | **route_hit_no_verify** | step 14, 10/18, provider_stall, no route-bound verify |
| dev | opsportal | `og.account-bola-write` | idor | hypothesis_miss | **route_hit_no_verify** | step 2, 24/30, provider_stall, no route-bound verify |
| dev | opsportal | `og.viewer-bfla` | bfla | csrf_blocked | **route_hit_no_verify** | step 6, 30/30, completed, `baseline_empty` gap, no verify |
| dev | opsportal | `og.user-mass-assignment` | mass_assignment | hypothesis_miss | **probed_missed_bug** | step 2, 24/30, verify ×1, no target verdict |
| dev | opsportal | `og.search-sqli` | sqli | replay_spec_miss | **probed_missed_bug** | step 5, 14/30, verify ×2, no target verdict |
| dev | opsportal | `og.api-jwt-forgery` | jwt | context_reset | **route_hit_no_verify** | step 18, 8/30, completed, `no_reproducible_signal` gap, no verify |
| dev | opsportal | `og.job-csrf` | csrf | form_encoding_missing | **route_hit_no_verify** | step 2, 24/30, provider_stall, no route-bound verify |
| dev | opsportal | `og.log-filter-sqli` | sqli | context_reset | **verify_called_but_oracle_rejected** | step 24, 17/18, `no_semantic_oracle` |
| dev | shopflow | `api-jwt-alg-none` | jwt | context_reset | **route_hit_no_verify** | step 34, 11/30, completed, no verify |
| dev | shopflow | `giftcard-race` | race_condition | hypothesis_miss | **never_dispatched** | step 14 canceled, never re-queued |
| dev | shopflow | `payment-webhook-forgery` | webhook_forgery | replay_spec_miss | **never_dispatched** | no planned step names the route |
| dev | shopflow | `coupon-reuse` | business_logic | hypothesis_miss | **route_hit_no_verify** | step 37, 17/30, wall_clock_pause, no verify |
| dev | shopflow | `inventory-oversell` | race_condition | hypothesis_miss | **route_hit_no_verify** | step 37, 17/30, wall_clock_pause, no verify |
| dev | shopflow | `coupon-after-lock` | workflow_bypass | budget_exhausted | **never_dispatched** | step 37, 17/30, wall_clock_pause; route never requested |
| dev | shopflow | `over-refund-chain` | business_logic | form_encoding_missing | **route_hit_no_verify** | step 28, 29/30, `runtime_unavailable` gap, no verify |
| heldout | acme-saas | `acme.invoice-bola` | bola | replay_spec_miss | **route_hit_no_verify** | step 18, 14/30, provider_stall, no verify |
| heldout | acme-saas | `acme.member-role-privesc` | mass_assignment | hypothesis_miss | **verify_called_but_oracle_rejected** | step 3, 20/30, `no_cross_actor_differential` |
| heldout | acme-saas | `acme.webhook-forgery` | webhook_forgery | hypothesis_miss | **never_dispatched** | step 56, 2/30, wall_clock_pause; route never requested |
| heldout | acme-saas | `acme.jwt-none` | jwt | budget_exhausted | **never_dispatched** | no planned step names the route |
| heldout | acme-saas | `acme.sso-open-redirect` | oauth | replay_spec_miss | **route_hit_no_verify** | step 26, 14/30, provider_stall, no verify |
| heldout | acme-saas | `acme.seat-invariant` | business_logic | hypothesis_miss | **route_hit_no_verify** | step 20, 13/30, provider_stall, no verify |
| heldout | acme-saas | `acme.credit-double-spend` | race_condition | hypothesis_miss | **route_hit_no_verify** | step 20, 13/30, provider_stall, no verify |
| heldout | acme-saas | `acme.invite-workflow-skip` | workflow_bypass | hypothesis_miss | **route_hit_no_verify** | step 6, 29/30, completed, `no_reproducible_signal` gap, no verify |
| heldout | acme-saas | `acme.legacy-auth-bypass` | auth_bypass | hypothesis_miss | **route_hit_no_verify** | step 26, 14/30, provider_stall, no verify |
| heldout | acme-saas | `acme.auditlog-secret` | info_disclosure | hypothesis_miss | **probed_missed_bug** | step 6, 29/30, verify ×1, no target verdict |
| heldout | acme-saas | `acme.export-open-redirect` | open_redirect | replay_spec_miss | **route_hit_no_verify** | step 6, 29/30, completed, `no_reproducible_signal` gap, no verify |
| heldout | opsportal | `og.graphql-account-bola` | graphql_bola | replay_spec_miss | **route_hit_no_verify** | step 13, 13/30, completed, no verify |
| heldout | opsportal | `og.dashboard-cache-poison` | cache_poisoning | hypothesis_miss | **never_dispatched** | no planned step names the route |
| heldout | opsportal | `og.account-bola-write` | idor | hypothesis_miss | **verify_called_but_oracle_rejected** | step 2, 25/25, `no_persisted_impact` |
| heldout | opsportal | `og.viewer-bfla` | bfla | csrf_blocked | **verify_called_but_oracle_rejected** | step 20, 19/30, `no_cross_actor_differential` |
| heldout | opsportal | `og.user-mass-assignment` | mass_assignment | hypothesis_miss | **never_dispatched** | step 14, 3/30, wall_clock_pause; route never requested |
| heldout | opsportal | `og.job-csrf` | csrf | form_encoding_missing | **route_hit_no_verify** | step 16, 16/30, wall_clock_pause, no verify |
| heldout | opsportal | `og.log-filter-sqli` | sqli | replay_spec_miss | **never_dispatched** | no planned step names the route |
| heldout | opsportal | `og.backup-webhook-forgery` | webhook_forgery | replay_spec_miss | **route_hit_no_verify** | step 23, 18/30, completed, no verify |
| heldout | opsportal | `og.ticket-assign-cross-write` | idor | form_encoding_missing | **verify_called_but_oracle_rejected** | step 30, 16/30, `status_only`; finding matched to a sibling target |
| heldout | opsportal | `og.integration-ssrf-direct` | ssrf | replay_spec_miss | **never_dispatched** | step 31, 5/30, wall_clock_pause; route never requested |
| heldout | shopflow | `checkout-open-redirect` | open_redirect | hypothesis_miss | **never_dispatched** | no planned step names the route |
| heldout | shopflow | `api-jwt-alg-none` | jwt | context_reset | **probed_missed_bug** | step 33, 8/30, verify ×1, no target verdict |
| heldout | shopflow | `storefront-cache-poison` | cache_poisoning | context_reset | **route_hit_no_verify** | step 4, 23/30, provider_stall, no verify |
| heldout | shopflow | `giftcard-race` | race_condition | hypothesis_miss | **never_dispatched** | step 14 ready, never assigned |
| heldout | shopflow | `payment-webhook-forgery` | webhook_forgery | replay_spec_miss | **never_dispatched** | no planned step names the route |
| heldout | shopflow | `coupon-reuse` | business_logic | context_reset | **route_hit_no_verify** | step 19, 17/30, provider_stall, no verify |
| heldout | shopflow | `inventory-oversell` | race_condition | context_reset | **route_hit_no_verify** | step 19, 17/30, provider_stall, no verify |
| heldout | shopflow | `refund-exceeds-payment` | business_logic | budget_exhausted | **never_dispatched** | step 20, 2/30, wall_clock_pause; route never requested |

---

## Caveats

- **Bucket 2 is "no verify bound to this route", not "no verify call anywhere".** Broad sweeps
  sometimes call verify for a sibling route; that does not discharge the target's proof and is
  deliberately not counted as progress.
- **Second-order targets** count both entry and trigger routes (`spec.routeKeys` +
  `spec.triggerRouteKeys`), which is why e.g. `project-stored-xss` is a route hit rather than a
  dispatch miss.
- **Planner prose uses blueprint nouns and params** (`/api/{noun:webhooks}/receive`,
  `:creditId`), while the runtime instance uses the seed's vocabulary (`/api/event-hooks/charges`,
  `:cardId`). Plan matching normalises both; otherwise several planned targets look unplanned.
- **Two agent-confirmed findings** exist across the six cells; only one is a net-new target
  (`review-stored-xss`, held-out shopflow). The other matched a target the floor had already
  confirmed, which is why the increment is 1.
- No raw bodies, payload strings, or credentials are reproduced here. Rejection reasons are
  normalised to codes; the underlying free-text rules live in `src/server/oracle-invariants.ts`.
