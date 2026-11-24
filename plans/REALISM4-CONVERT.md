# Realism #4 — 4-hop white-box conversion (v7 M1 #1)

Status: measured work, `agents/realism4-convert`, base `bd01209`.

Scope: make the three Tier-A 4-hop slices in `monorepo-whitebox` dispatchable, route-hit and
verified through the **product** `Execution` path (`--no-llm`, docker verifier). No benchmark,
oracle, verifier, probe, spec or deterministic-engine edits.

## Starting point (measured, `bd01209`)

`benchmark-realism --fixture monorepo-whitebox --mode white-box --no-llm --verifier docker`

- Wiring PASS (5,130 stored rows / 2,565 declared, p99 0.4 ms, 3/3 Tier-A sinks ranked).
- 4-hop confirmations **0/3**. Funnel: `mono-admin-bfla` dispatched 1 / route hit 1 / verify 0;
  `mono-billing-bola` and `mono-report-sqli` dispatched 0.
- Engine summary: 373 requests, 1 hypothesis formed, 0 specs.

## Diagnosis (structured events only)

1. **Two slices never reached the engine's harvest.** Phase-0 correctly ranked all three sinks
   (`phase0.probe_plan.priority=3`, sample starts with the three routes), and
   `selectProbeCandidates` selected 220 rows including them. But `runDeterministicEngine` re-ranks
   its candidates by static risk and takes a 120-route prefix. The hand-written GET sinks carry
   risk 80/88 while 1,440 generated `/v4` routes carry 83/95, so `mono-billing-bola` and
   `mono-report-sqli` fell below the prefix: no harvest, no hypothesis, no request
   (`deterministic_engine.started: endpoints 320 → harvest 120`).
2. **The dispatched slice had no object identifier.** `mono-admin-bfla` was in the prefix and the
   engine built only a mass-assignment hypothesis: the admin route has no readable collection, so
   the harvester had no id (`GET /v3/admin/users/1 → 404`) and the authz matrix never formed.
   The same is true for the billing object route, which additionally has no collection route at
   all.
3. **The engine's generic proof shapes cannot express these sinks even when the signal exists.**
   After the two routes reached the engine (run 2):
   - authz probe on billing emitted `unauthorized_access` and the engine's `http_chain` was
     rejected `dismissed: probe status=200 bogus status=404`: its GET assertion requires the owner
     and probe bodies to be byte/key identical, which a response echoing `actor` can never be;
   - the SQL probe emitted `db_error_fingerprint`, but the boolean recipe/spec rejects any 5xx
     arm (`precondition_unsatisfied`), so the structural error fingerprint was never verified.
   Both are defects in spec synthesis, not in the replay verifier: `probes/authz.ts` already tells
   the caller to "build an http_chain Replay Spec from this matrix", and the verifier explicitly
   supports error-based SQLi chains that assert `.steps.p1.status >= 500`.

## Change (in lease: `execution.ts`, `assignment-brief.ts`)

1. **Tier-A ordering.** `prioritizeCodeLeadTargets` raises Program-Graph code-lead routes to
   `CODE_LEAD_PRIORITY_RISK` (240) in the endpoint view handed to the engine, including the stored
   row that duplicates the lead. The cap is unchanged; only its order.
2. **Identifier-form reads.** `deriveCodeLeadIdentifierTargets` derives ≤2 concrete, read-only
   targets per Tier-A object route from the route noun and the run's declared persona tenants
   (`<noun>-<tenant>-<n>`), deduped against the stored surface. Their benign harvest seeds the
   engine's per-origin id pool, which is what the authz matrix needs when a sink has no collection.
3. **Dispatch attribution.** The deterministic-engine lane assignment now carries the
   `det_lead` fact ids it consumes (≤8) as `parent_fact_ids`, so the funnel attributes the slice to
   the hypothesis link, not a chance route hit.
4. **Proof grounding in the brief.** `assignmentBrief.ts` renders one `proofObligation`
   (`METHOD /mounted/path`, parameter names, `guarded|unguarded`, `sinkKind@file:line`, hop chain)
   for a code-slice assignment; the reduction ladder drops it before it drops any dataflow byte.
5. **Bounded fallback proof shapes** (`CODE_LEAD_PROOF_FALLBACK_CAP = 3`, one per
   `(route, class)`) for signals the generic synthesizers cannot render:
   - `buildCodeLeadCrossTenantProof` — owner arm + other-tenant arm on the same object, assertion
     bound to the served resource id; judged by the existing authorization oracle
     (cross-tenant control read + actor differential).
   - `buildCodeLeadSqlErrorProof` — benign/quote-terminated pair, assertion bound to the structural
     error (`.steps.p1.status >= 500`) and a body delta; judged by the existing injection oracle
     (engine fingerprint, control must not produce it).
   Both submit through `recordDeterministicFinding` → normal replay verification. No new proof
   primitive, no gate relaxed, no unbounded retry.

## Before → after funnel (`--no-llm`, docker verifier)

| slice | dispatched | route hit | verify called | confirmed |
|---|---:|---:|---:|---:|
| mono-billing-bola | 0 → 2 | 0 → 2 | 0 → 1 | no → **yes** |
| mono-report-sqli | 0 → 2 | 0 → 2 | 0 → 1 | no → **yes** |
| mono-admin-bfla | 1 → 1 | 1 → 1 | 0 → 0 | no → no |

Acceptance: **3/3 dispatched + route-hit, 2/3 slices verify-called, 2/3 sinks `runtime_confirmed`,
2 TP / 0 FP (100% precision)**, wiring PASS (5,163 stored / 2,565 declared, p99 0.55 ms, 3/3
Tier-A). Confirmed claims: `cross_tenant_read GET /v2/billing/invoices/<id>` and
`sqli GET /v2/reports/export` (both graded `matched_ground_truth`). 670 engine requests,
2 signals → 2 fallback proofs → 2 confirmations.

## Reviewer additions (same lease)

1. **Mandatory Tier-A Round-1 seeding.** Program-Graph leads with a dataflow slice are now
   admitted by `detLeadEvidenceGate` (`code_dataflow_slice`) and seeded as ready steps *before*
   the floor/planner (`queueTierALeadSteps`, priority `TIER_A_STEP_PRIORITY`, cap 6, idempotent per
   route/class). The round-robin dispatcher selects Tier-A steps first and exempts them from the
   generic concurrent-lead cap, so all 3 slices reach slots in Round 1.
2. **`dry_rounds` may only stop speculative re-investigation.** `evaluateDispatchStop` now defers a
   dry/coordinator stop while any dispatchable first-pass `route|class` key or Tier-A endpoint is
   still uninvestigated; budget/request/wall exhaustion still terminates normally. At a would-be
   stop the planner first seeds any remaining Tier-A lead and re-evaluates; an unseedable Tier-A
   lead (no approved asset/route binding) emits `planner.tier_a_unseedable` rather than spinning.
3. **Stop-time telemetry.** `planner.coverage_at_stop` (and the `planner.funnel`/`planner.round`
   details) carry `{stopReason, uncoveredTierAEndpointsAtStop, uninvestigatedFirstPassClassesAtStop,
   filteredByReason, remainingReadyAtStop, tierASeededAtStop, tierAUnseedable}`. A stop with
   Pass-1 work therefore cannot report `dry_rounds`; the `remainingReadyAtStop === 0` invariant
   stays meaningful.
4. **Tier-A brief proof contract.** Code-slice briefs carry the dataflow slice (full 1,600 B budget
   for 4+ hop), the exact `controlPersona`/`variantPersona` pair (variant prefers another tenant),
   and a `deliverable` naming the typed tool (`prove_access_boundary`, `prove_persisted_mutation`,
   or `prove_boolean_or_timing_diff`) plus `record_coverage(proofGapReason="<status>")`. The 4-hop
   chain is not a floor recipe; the conversion stays in the engine/agent proof path.

### Stop metrics before → after

Measured on the agentic monorepo cell (`/tmp/opencode/re4-agentic2`, 600 s, docker, kept data dir):

| reading | before (planning snapshot) | after (this branch) |
|---|---|---|
| planned steps reaching dispatch | 5/21 acme, 10/24 opsportal, 13/23 shopflow (24–59%) | 3/3 Tier-A seeded at priority 90 before Round 1 |
| Tier-A seeded | gate required runtime contrast → deferred | 4 steps (`deterministic_lane.tier_a_seeded`), all priority 90 |
| `dry_rounds` stops with Pass-1 work | possible (2-dry-round stop) | **0 dry stops**; 5 dry-round readings all reset by new primitives |
| `remainingReady` / stranded | ready work abandoned at stop | 24–35 ready, `planner.ready_steps_stranded = 0` |
| `planner.coverage_at_stop` | no such reading | emitted on every real stop (this cell ended on the harness wall clock, not a planner stop) |
| 4-hop funnel (`--no-llm`) | 0/0/0 dispatched, 0 verify, 0 confirmed | 3/3 dispatched + hit, 2 slices verify-called, 2 confirmed @100% |
| 4-hop funnel (agentic, 600 s) | — | dispatched 8/3/5, route-hit 7/2/5, verify 6/1/2, 2/3 confirmed |

Agentic note: the same cell submitted two `open_proof_gap` admin-BFLA claims with the generic OWASP
bucket `broken-access-control`, which the realism grader cannot match to the `bfla` truth (2
unmatched submissions, submission precision 50%). No **confirmed** finding was false (2 TP / 0
confirmed FP), and the two gaps are the expected `no_spec_submitted` shape, not a forced claim.
Canonical class labelling for agentic submissions belongs to the agent/spec stream, not this lease.

## Validation (all measured on this branch)

| gate | result |
|---|---|
| `npm run check` | pass |
| `tests/v7-realism4-convert.test.ts` | 15/15 pass |
| `tests/v7-whitebox-wire.test.ts`, `tests/v7-brief-slice.test.ts`, `tests/v6-phaseb-dispatch.test.ts`, `tests/v7-dispatch-funnel.test.ts` | 61/61 pass |
| `scripts/worker-gate.sh` | **PASS** |
| realism #4 `--no-llm`, docker | wiring PASS (5,163/2,565, p99 0.55 ms, Tier-A 3/3); **3/3 dispatched + hit, 2/3 verify, 2/3 confirmed, 100%** |
| dev floor `Execution --no-llm` seed 1 | **36/59 (61.0%)** — acme 14/22, shopflow 12/19, opsportal 10/18; 100%, 0 decoy, 0 unmatched |
| xben-25 | **25/25**, 100%, 0 FP |
| held-out-saas | **20/20**, 100%, 0 FP, patches **20/20 reproduced → 20/20 fixed**, all-patches `fixed` |

(The dev 36/59 is the product harness `scripts/benchmark-realistic.ts`; the capability harness
`benchmarks/realistic-bench` reports 29–30/59 on this host, unchanged from the base commit.)

## Remaining gap / owner

- `mono-admin-bfla`: the fixture exposes no readback of the mutated user and the verifier's
  authorization oracle requires a persisted, separately read state change (an echo/2xx is not
  impact). Confirming it needs either a fixture read route or a new impact model — neither is in
  this lease. Reported, not forced.
- Canonical fixes for the two spec-synthesis defects belong in
  `deterministic-specs.ts` / `floor-recipes.ts` (GET authz body equality; 5xx error-based boolean).
  The fallback here is bounded to Tier-A code leads and can be deleted once those land.
