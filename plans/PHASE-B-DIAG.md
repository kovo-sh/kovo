# Phase B diagnosis — where the agentic lane loses value

**Run:** `52a05555-cfd8-4603-b115-ade36be491ca`, acme-saas seed 1, grey-box, agentic, Docker workers,
git `275592a`, wall cap 600 s, `budget_usd 2.00`.
**Artifacts:** kept run `/tmp/unified-acme2/` (scorecard + `guardian.sqlite` + worker session SQLite);
comparison run `/tmp/unified-acme/` (previous) and `/tmp/unified-acme2/summary.json`.
**Method:** structured SQL/JSON only — `assignments`, `chain_steps`, `facts`, `findings`, `replay_specs`,
`broker_exchanges`, `coverage_entries`, `events`, worker-session `tasks`/`entries`. No raw bodies, no
probe payloads, no secrets. Read-only; this document is the only file written.

---

## 1. Headline

| metric | value | note |
|---|---|---|
| unified recall | **11/22 (50.0%)**, precision 100% | equals the deterministic floor exactly |
| floor preserved | 11/11 (`preservationRatio 1.0`) | floor is healthy; this is not a preservation problem |
| **agentic confirmed** | **0** | 0 specs submitted by any worker; 0 verify calls |
| Phase B wall | **415.5 s of 600 s (69%)** | Phase‑0 21.6 s + threat model 18.3 s + floor 144.6 s precede it |
| Phase B requests | **99 of 1,492 (6.6%)** | 415 s of wall bought 6.6% of the run's traffic |
| spend | **$0.129 of $2.00 (6.5%)** | money is not the binding constraint; wall clock is |
| assignments (agentic Phase B) | 3 dispatched, 3 started, **2 completed, 1 killed** | 63 turns total, 0 verdicts |
| chain steps | 41 created: **2 complete, 15 canceled, 23 ready, 1 running** | 26 non-canceled steps → 2 executed |
| leads | 4 emitted, “3 consumed”, **0 investigated to a verdict** | all 4 are the same DELETE/authz_matrix heuristic |
| wall spent on floor leads | **332 s of 415 s (80%)** | 143.6 s BOLA matrix + 188.6 s invoice-lead upgrade |
| wall spent on unproven target classes | **0 s** | no sqli/xss/ssti/xxe/authz-bypass/role/business-logic probe ran |

One sentence: **Phase B did not run out of money, turns, or model capability — it ran out of
dispatch slots, and the one slot it had was spent proving four floor false-positive leads false.**

---

## 2. Assignment ledger

Wall = `worker.started` → `worker.complete`/run stop. Turn latency = generation wall ÷ generations.

| # | assignment | specialist | status | turns / cap | wall | reqs | distinct paths | gen wall | p50 turn | facts | specs |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| A | `caee08fb` deterministic differential engine | floor | complete | – / – | 144.6 s | 1232 | 564 | – | – | 15 | **11 confirmed** |
| B | `bce7ea67` Round‑0 threat model | — | complete | – / – | 37.2 s | 126 | 67 | – | – | – | – |
| C | `a3e65f4a` Surface & chain investigation | protocol-cache-edge | complete | **25 / 25 (cap)** | 83.2 s | 47 | 18 | 82.4 s | 2.4 s | 5 | 0 |
| D | `b6e9a512` Cross-persona BOLA/IDOR matrix | bola-bfla | complete | **29 / 30** | 143.6 s | 43 | 15 | 143.3 s | 3.0 s | **58** | 0 |
| E | `25a06ee7` det_lead upgrade · DELETE invoices | bola-bfla | **paused (killed)** | **9 / 30** | 188.6 s | 9 | 2 | ~180 s (1 gen truncated) | **19.5 s** | 8 | 0 |

Notes:
- Only one investigation worker was ever active: `worker_concurrency = 1` in `runs` (see §7‑F1).
  Phase B wall is therefore exactly the sum of the three assignment walls (415.4 s) — the slot was
  100% busy and always working on the wrong thing.
- Assignment C hit its 25-turn cap; its final `complete_intent` was rejected for exceeding the
  2,000-char summary cap, so it closed on the cap with a truncated outcome.
- Assignment D lost 4 of its 29 turns to the 85% settlement gate (network tools revoked at 25/30) and
  1 turn to a `record_coverage` 600-char validation rejection.
- Assignment E started with 188.5 s left in the run and a 160 s wall budget, but turn latency had
  degraded from ~2.5 s to **19.5 s median** (provider-side), so 9 turns consumed the entire remainder.
  It was stopped mid-generation with no `complete_intent`, no coverage entry and no verdict.

### Phase timeline (s from run start)

| t | event |
|---:|---|
| 0.0 | run created |
| 21.6 | Phase‑0 discovery done (134 req) |
| 21.6–39.9 | threat model (126 req) |
| 39.9–184.5 | **Phase A floor** (1,525 req, 11 confirmed, 4 leads, 12 rejected specs) |
| 184.5 | agentic dispatch (6 ms after floor) |
| 184.5–267.7 | assignment C (edge) |
| 267.8–411.4 | assignment D (BOLA matrix, absorbs 3 leads) |
| 411.5–600.0 | assignment E (invoice lead, killed) |
| 295.3 / 358.6 / 471.3 / 495.2 | planner rounds 1–4 end (**197 s of planner generation** in-window) |
| 600.0 | stopped (`investigation`), 23 steps still `ready` |

---

## 3. Funnel per assignment

No agent submitted a replay spec, so **no per-assignment verifier outcome exists** — the failure
taxonomy for Phase B is “never reached the verifier”, not `oracle_failed` / `transcript_mismatch` /
`replay_spec_miss`. Those buckets in the scorecard belong to the floor lane only.

| assignment | probes (exchanges / paths) | batches | hypotheses (facts committed) | signals | specs | verify calls | coverage entries | verifier outcome |
|---|---|---|---:|---:|---:|---:|---:|---|
| C edge | 47 / 18 | 6 | 5 (1 dom sink, 2 header, 1 config, 1 object_ref) | 0 | 0 | 0 | 5 | none |
| D BOLA matrix | 43 / 15 | 8 | 58 (56 `object_ref`, 2 notes) | 0 | 0 | 0 | 1 ruled_out | none |
| E invoice lead | 9 / 2 | 3 | 8 `object_ref` | 0 | 0 | 0 | 0 | none (killed) |

Tool mix (calls): C = 42 (`request_http` 15, `request_http_batch` 6, `derive_evidence` 4, `get_exchange` 4,
`record_fact` 4, `record_coverage` 4, `probe_differential` 1, `inspect_dns/tls` 2, `search_*` 2,
`board_post` 1, `complete_intent` 1); D = 36 (`derive_evidence` 9, `request_http_batch` 8,
`request_http` 7, `get_exchange` 3, `search_*` 3, `load_skill` 1, `record_fact` 2, `record_coverage` 2,
`complete_intent` 1); E = 15 (`derive_evidence` 4, `request_http_batch` 3, `request_http` 3,
`get_exchange` 2, `load_skill` 1, `search_exchanges` 1).

**Typed proof tools were available in every prompt and used zero times** (`prove_authz_read_diff`,
`prove_state_mutation_diff`); `guardian_verify` likewise **0**. The previous run's single agentic
confirmation came from `prove_authz_read_diff` — i.e. the one thing that produced lift last run is the
one thing this run never called.

Floor-side funnel for comparison: 126 hypotheses → 107 probes → 15 signals → 23 specs → 11 confirmed,
12 rejected (`controlPassed:false`, all on the four DELETE leads, 3 attempts each).

---

## 4. Lead mapping (4 emitted → 0 verdicts)

All four leads are `authz_matrix` / `DELETE` / `verdict:signal`, generated by the same heuristic:
*a non-owner actor received a mutating 2xx*. Each was queued as a p=88 step; the 4th was re-emitted by
the planner at p=96.

| lead fact | endpoint | step | dispatched? | outcome |
|---|---|---|---|---|
| `6fb5cbf4` | `DELETE /api/people/:personId` | 2 (`dd2bc379`, canceled 471 s) | folded into D | **ruled out**: handler returns a 2xx with an `ok` body for any id incl. non-existent; ownership enforced on real ids |
| `cf5993d7` | `DELETE /api/spaces/:projectId` | 3 (`bed748fa`, canceled 471 s) | folded into D | **ruled out**: same idempotent-200 pattern; persona_a DELETE of persona_b's space had no effect |
| `75163905` | `DELETE /api/webhooks/:hookId` | 4 (`0a0bd561`) | **never** | step still `ready` at stop; no probe, no verdict |
| `50b4a807` | `DELETE /api/invoices/:invoiceId` | 19 (`0e4d8298`, p=96) | yes (411.5 s) | **killed** at 9 turns / wall cap; 8 `object_ref` facts, no coverage, no verdict |

Cost of the lead programme: 12 floor spec builds rejected on `controlPassed:false` (~19 s of floor) +
assignment D's 143.6 s + assignment E's 188.6 s = **80% of Phase B wall for 0 confirmed, 1 ruled-out
coverage entry, 1 step never run**.

Measurement defect: `floorLeadsConsumed` increments when a step is **queued** (`lead_consumed` event at
queue time), not when it is investigated. The run reports 3/4 consumed while 0/4 reached a verdict and
1/4 was never dispatched. The invariant “emitted > 0 ⇒ consumed > 0” is therefore satisfiable by doing
nothing.

---

## 5. Context, tooling, safety overhead

| dimension | measurement |
|---|---|
| prompt size (user msg) | **61.1 KB / 62.7 KB / 68.6 KB**; of which **`bolaTestQueue` = 52.9 KB (58 items) in all three, including the cache/CORS/TLS specialist** |
| system prompt | 51.0–57.5 KB, identical tool surface per specialist |
| `bolaTestQueue` composition | 47 GET, 10 DELETE, 1 POST across 20 resource keys; DELETEs are the four det_lead endpoints → the prompt itself biases toward the false-positive workload |
| skills | `load_skill(bola-idor-race)` 1× in D and 1× in E (+5.7 KB), after turns had already been spent |
| approvals | **542/542 auto-approved** (`auto-review:local-lab`), **0 leases**, 0 parked workers → **0 s lost** ✔ |
| broker denials | 22 total, **1 in Phase B** (assignment C), event carries no reason code → not diagnosable |
| rate limit / circuit breaker | 0 trips |
| wasted turns | C: 1 (`complete_intent` 2,000-char reject); D: 1 (`record_coverage` 600-char reject) + 4 by-design settlement; E: whole assignment |
| planner overhead | 4 rounds, 27 generations, **197 s** generation, 8 `dispatch_investigations` calls; round 2 alone canceled 11 duplicate steps |
| model time vs wall | ~600 s of generation inside 415 s of wall (planner ∥ one worker, effective parallelism ≈1.45) |

---

## 6. The floor's unconfirmed targets vs. what Phase B actually did

| target | class | floor bucket | step that existed | agentic probes | result |
|---|---|---|---|---|---|
| `acme.invoice-bola` | bola | hypothesis_miss | **28 Invoice read BOLA `GET /api/invoices/:id` (p=80, ready)** | 0 cross-persona invoice reads; item was in D's queue | not attempted |
| `acme.member-role-privesc` | mass_assignment | hypothesis_miss | 17 role/enrollment grant (p=81, ready) | none | not attempted |
| `acme.reflected-search-xss` | xss_reflected | hypothesis_miss | 41 search param (p=60, ready) | none | not attempted |
| `acme.report-cache-poison` | cache_poisoning | hypothesis_miss | — | C ran `probe_differential cache_poison_deception` (11 req, 0 anomalies) | agent ruled out; disagrees with oracle |
| `acme.report-ssti` | ssti | trigger_miss | 37 report render (p=78, ready) | none | not attempted |
| `acme.project-stored-xss` | xss_stored | trigger_miss | 16 DOM sink (p=84, ready) | none | not attempted |
| `acme.project-search-sqli` | sqli | replay_spec_miss | — | none | not attempted |
| `acme.import-xxe` | xxe | replay_spec_miss | 35 import config blob (p=78, ready) | none | not attempted |
| `acme.seat-invariant` | business_logic | budget_exhausted | 13/23 billing-seat (13 ready, 23 canceled) | none | not attempted |
| `acme.invite-workflow-skip` | workflow_bypass | budget_exhausted | 23 (canceled as dup) | none | not attempted |
| `acme.legacy-auth-bypass` | auth_bypass | budget_exhausted | 12/25 SSO/OIDC (ready/canceled) | none | not attempted |

**9 of 11 misses had a plausible step; 8 of those had it sitting `ready`; 0 received a single probe.**
The invoice read BOLA case is the sharpest: the item was in the worker's own 53 KB queue, the target
was confirmed by an agent on the previous run, and the worker issued `GET /api/invoices` (list) twice
but never `GET /api/invoices/<id>` as another persona. The lead-upgrade prompt (“prove a non-owner can
**delete** the invoice”) overrode the read-differential path.

Previous run, same config, for contrast: 4 investigations / 67 turns, 1 agentic confirmation
(`invoice-bola`, via `prove_authz_read_diff`), because the first three dispatched steps were
planner-authored broad BOLA/BFLA/auth steps at p=100 rather than det_lead upgrades at p=88.
Difference between 0 and 1 is **dispatch order and step composition**, not worker capability.

---

## 7. Ranked fixes (generic, no benchmark literals)

Ranking = expected net-new confirmed targets ÷ effort, at the same 600 s / 22-target budget.

### F1 — Decouple in-run worker concurrency from benchmark cell concurrency (P0)

`runs.worker_concurrency = 1` because the harness passes cell-level `--concurrency` (default 1) into the
run (`workerConcurrency: Math.min(4, Math.max(1, args.concurrency))`). The engine's scheduler already
supports up to `maxWorkerConcurrency` (`execution.ts:4864`) but is handed 1.
**Effect:** Phase B had 26 actionable steps and one slot. At 3 slots the same 415 s window fits
6–9 assignments instead of 3, which reaches “Invoice read BOLA” (step 28) and the role/Grant steps.
**Expected:** +1 to +2 targets on dev; the previous run shows one is reachable with a single ordering
change. Effort: hours, near-zero risk.
**Files:** `scripts/benchmark-realistic.ts` (run config ~2358; keep cell `--concurrency` separate from
a new `--worker-concurrency`), `scripts/benchmark-env.ts` (already models `workerConcurrency: 4`).
**Lease:** `m0-harness`. Add a fast-loop invariant: agentic run must have `worker_concurrency ≥ 3` and
`assignmentsDispatched ≥ 4`.

### F2 — Stop letting floor leads outrank unproven target classes (P0)

det_lead upgrades are created at priority 88 and re-emitted by the planner at 96; planner-authored
class steps sit at 60–92. With one slot, the four DELETE leads pre-empted every class step.
**Effect:** removes the 332 s / 80% wall sink; with F1, keeps one slot free for class coverage.
**Expected:** +0.5 to +1.5 targets. Effort: ~1 day.
**Files:** `src/server/execution.ts` (`queueDetLeadUpgradeSteps` priority 88 and `created >= 4` cap;
multi-trial/`computeMultiTrialFanout` priority thresholds at ~465). Rule: a lead step may never
outrank an uncovered crown-jewel class step; cap concurrently-scheduled lead upgrades at 1–2.
**Lease:** `phaseb-dispatch` (execution.ts scheduler sections only; do not touch `buildBolaTestQueue`).

### F3 — Promote a det_lead only with a failed control (P1)

Every lead came from “non-owner got a mutating 2xx”, and every lead died on `controlPassed:false`
because the handlers return 200 for ids that do not exist — there is no control contrast to build a
proof from. Tightening promotion (control must not also 2xx; or body/state delta must differ from the
control) removes 4/4 false leads at the source.
**Effect:** −12 rejected spec builds (~19 s floor), the 188.6 s invoice-lead assignment disappears, and
the det-lead half of the BOLA/IDOR matrix (which consumed most of its 143.6 s on DELETE proofs) is
removed; makes F2 safe rather than merely reordered.
**Expected:** 0 direct targets, but it is the multiplier for F1/F2 (frees ~80% of Phase B wall for
class work). Effort: ~1 day, and it *strengthens* verification (no weakening).
**Files:** `src/server/deterministic-engine.ts` (lead emission + control-contrast precondition),
`src/server/graph-leads.ts` (payload already carries `reason`; add `controlPassed`).
**Lease:** `detlane-leads`.

### F4 — Slim the injected test queue and order it read-differential-first (P1)

53 KB / 58–61 items injected into **every** worker, including the cache/CORS specialist, with 10 DELETE
variants from the FP leads ahead of one GET invoice item. This costs input tokens on every turn and
biases the agent into the destructive matrix.
**Effect:** ~50 KB (~12 k tokens) removed per assignment → faster turns (more turns before settlement)
and the read-differential item that produced last run's confirmation becomes the first thing tested.
**Expected:** +0.5 to +1 target. Effort: ~1–1.5 days.
**Files:** `src/server/execution.ts` (`buildBolaTestQueue` budgets `perTypeBudget 8`/`overallBudget 80`,
and the `bolaTestQueue` injection at ~8766/8835 — gate it to BOLA/IDOR specialists, cap ~12–16 items,
group by resource key, GET/read variants before DELETE).
**Lease:** `phaseb-brief` — shares `execution.ts` with F2, so **serialize after `phaseb-dispatch`**
(sections are disjoint: queue builder ~900–960 vs scheduler ~4820–4900/6650–6920; declare the split
in the handoff if parallel).

### F5 — Make the assignment budget survivable: mid-flight wall enforcement + clamp-not-reject (P1)

Three defects, one lease:
1. wall budget is only evaluated at turn boundaries (`settlementDue`), so a 160 s budget overshot to
   188.6 s when turns took 19.5 s; the assignment was killed with no verdict;
2. `complete_intent` (2,000 chars) and `record_coverage` (600 chars) **reject** oversize summaries
   instead of truncating — 2 turns lost across C and D;
3. a killed assignment records no closure, so its 8 facts and 5 evidence items produce no coverage
   entry and no partial proof-gap surfacing.
**Effect:** every dispatched assignment ends in a verdict (proved / ruled_out / blocked / partial), which
is what makes coverage-driven dispatch (F2) trustworthy.
**Expected:** +0 to +0.5 targets directly; recovers 2 turns and guarantees clean closure. Effort: ~0.5–1
day.
**Files:** `src/server/agent-session.ts` (`AGENTIC_SPECIALIST_WALL_CLOCK_MS`, `settlementDue`,
`settlementToolBlock`, summary validators), `src/server/execution.ts` (`specialistWallClockMs` at ~4772).
**Lease:** `phaseb-session`.

### Rejected / deferred this pass

- *Raise turn caps.* Caps are not the constraint in the last assignment (9/30 used, wall killed it) and
  C/D already used 25/25 and 29/30. Deferred until F1/F3 free the slot.
- *Drop the 85% settlement gate.* It cost D 4 turns but protected precision; keep it.
- *Add class-specific probes.* Correct long-term but the bottleneck is dispatch, not probe capability —
  steps 16/17/28/35/37/41 already encode the right hypotheses and never ran.
- *Harness-only recall work.* Out of scope by policy (v5.1 maintenance-only); every fix above is in
  `src/server/` or the M0 harness config, and is scored through real `Execution`.

---

## 8. Measurement defects worth fixing while here

| defect | where seen | consequence |
|---|---|---|
| `floorLeadsConsumed` counts queueing, not investigation | 3/4 “consumed”, 0/4 verdicts | the leads invariant can pass with zero work done |
| `failureBuckets.budget_exhausted` = 3 is a **wall-clock** cap, not `--budget-usd` | scorecard | misattributes the limiter; spend was 6.5% of cap |
| `broker.denied` Phase B event has no reason code | assignment C | only Phase B denial is undiagnosable |
| no per-assignment “hypothesis formed / signal” ledger | `facts` is the only proxy | funnel stages 3–4 cannot be attributed to Phase B |
| killed assignment → no `outcome`, no coverage | assignment E | work disappears from the report and from dispatch feedback |

## 9. What to measure next (same harness, no new capability)

1. Run with `worker_concurrency` 3 and F2+F3 applied; report `assignmentsDispatched`,
   `stepsReadyAtStop`, `wallOnLeads/PhaseBWall`, and `agenticConfirmed`.
2. Assert in the fast loop that a run cannot end on the wall cap with `steps_ready_at_stop > 0` while
   slot utilisation (Σ assignment wall ÷ Phase B wall) is < 60%.
3. Re-run the same cell to bound run-to-run variance: 11 vs 12 floor and 0 vs 1 agentic already show
   ±1 target is noise, so F1/F2 must be judged on ≥3 repeats (median [min–max], worst-run precision).
