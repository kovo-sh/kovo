# Param discovery — Layer-2 structural assumption vs randomized surfaces

Branch `agents/param-discovery`, base `0f066b7`, merged with main through `9fb0395`
(including the store-level `runtime_confirmed` receipt invariant and the SQLi grounding merge).
Lease: `src/server/phase0-recon.ts`, `src/server/surface-engine.ts`,
`tests/v7-param-discovery.test.ts`, this file.

## 1. Re-verified state (corrected diagnosis)

Measured on the kept salted held-out cell (seed `1000042`, shopflow) **before** this stream:

| fact | value | evidence |
| --- | --- | --- |
| `GET /api/v1/search` endpoint | present (`openapi`) | `endpoints` row |
| `endpoint_params` for that route | **0** | `endpoint_params` join |
| concrete app param | `query` (seed-resolved from `searchQuery` vocab) | app exchanges |
| floor probes on the route | `mass_assignment POST` + xss on other routes only | `deterministic_engine.probe` events |
| sqli hypothesis formed? | yes, for inferred `q`/`query`/`term`/`keyword` | `enumerateHypotheses` replay |
| sqli hypothesis **selected**? | **no** | selection replay below |

The SQLi stream's “declared param (`searchQuery`)” is the *logical* spec key, not a persisted
`endpoint_params.name`: every kept held-out run (`heldout-lift-shop2`, `heldout-post-lane`,
`cut3a-final-salted`, `hfr-fix4-shop`) has **zero** rows for `/api/v1/search`. The generated OpenAPI
document for the seed declares `parameters: []` for that operation.

So this was **both** sub-problems, in this order:

- **(A) discovery gap** — no observed/inferred name was persisted. The engine's generic search
  vocabulary (`q, query, term, keyword`) was not ordered to put the real name first; with equal
  scores the alphabetical slice picked `keyword`/`q`, both ignored by the app.
- **(B) selection/eligibility gap** — even when the engine forms the search SQLi hypotheses, the
  per-class quota drops them. Exact predicate (read-only, `deterministic-engine.ts`, **not edited**):
  `enumerateHypotheses` → selection sort `intentPriority desc, risk desc, key asc`, with
  `sqli quota = max(10, ceil(10 · slots/baseMax)) = 17` at `maxRequests=1800`.
  Replaying the held-out surface off-line gave 17 higher-risk SQLi candidates (derived
  `catalog*` routes exploit `pathHasSearchHint` matching the substring `log` in “catalog”, plus
  `endpointRiskScore` id/url boosts); search SQLi ranked 18th at risk 102 and was never probed.

Proposed upstream diff (for the owner of `deterministic-engine.ts`; **not landed here**): either
rank `activeQueryParams` before the risk sort or reserve one quota slot per *sensitivity-checked*
reading param before generic inferred candidates. This stream instead raised the route's persisted
risk when a reading param passed a sensitivity check (risk scoring lives in `phase0-recon.ts`), which
lets the existing selection pick it without touching hypothesis code.

## 2. Provenance, noise filtering, and sensitivity (reviewer ruling)

Every persisted name carries an explicit tag in `endpoint_params.source`:

| tag | meaning |
| --- | --- |
| `observed[:detail]` | wire/declaration: link `?key=`, form field, redirect `Location` query, OpenAPI/route-map declaration, validation body hint |
| `inferred_bundle[:sensitive]` | visible in shipped client JS (URL literal / harnessed fetch) |
| `inferred_html[:sensitive]` | inferred from an HTML/JSON document field or route semantics |
| `inferred_ast[:sensitive]` | parsed request/AST shape (e.g. `filter.name` JSON body path) |

- `:sensitive` means a bounded **paired control-vs-probe** differential (`probeSurface` params mode,
  ≤12 requests, read-only) showed the target reads the name. It is still **inferred**, not observed.
- Obvious JS/UI noise literals are dropped (`undefined`, `constructor`, `addEventListener`,
  `textContent`, …). Dotted names are kept for JSON body fields and rejected for query locations.
- A dead inferred literal that fails the sensitivity check is **deleted** from `endpoint_params` so
  it cannot inflate probe queues. Names not yet checkable (budget/cap) stay inferred and plain.
- Inferred names can seed a hypothesis. They never create a claim: the finding in the validation
  run was produced by the existing floor differential + replay verification
  (`provenance=floor`, `verification_class=runtime_confirmed`). No confirmation path was changed;
  `verifyReceipt`/oracle-invariant proof remains the gate owned by the SQLi/verification streams.
- Metrics: one deterministic `phase0.param_discovery` event with per-endpoint
  `observed/inferred`, `byProvenance`, `bySource`, `sensitivityPassed`, plus totals and
  `sensitivity {checked, passed, dropped}`. No raw bodies or payload strings.

## 3. Determinism proof

- Candidate synthesis is pure: fixed vocabulary order, sources derived from evidence, no clock/random.
- `orderDiscoveredParams` sorts by provenance rank (`observed`, `inferred_bundle`,
  `inferred_html`, `inferred_ast`) then name/location/source; dedupe by `name|location`.
- URL query keys are sorted before insertion.
- `tests/v7-param-discovery.test.ts` runs recon twice with reversed link arrival order and compares
  the full `(endpoint, name, location, provenance)` sequence — equal.
- Metrics endpoints/bySource are emitted in sorted order.

## 4. Validation (post-merge, docker verifier)

Product floor (`Execution --no-llm`), dev seed 1, three runs:

| run | acme-saas | shopflow | opsportal | total | precision |
| --- | --- | --- | --- | --- | --- |
| 1 | 12/22 | 12/19 | 10/18 | **34/59** | 100% |
| 2 | 12/22 | 12/19 | 10/18 | **34/59** | 100% |
| 3 | 12/22 | 12/19 | 10/18 | **34/59** | 100% |

Spread 0; decoy FPs 0; unmatched FPs 0.

Salted held-out floor seed `1000042` (`GUARDIAN_RB_HELDOUT_SALT` from the owner-only file, never
printed), measured **after** merging the store-level `runtime_confirmed` receipt invariant:
**25/58**, precision 100% (previous 24/58). The search finding satisfies the invariant
(`provenance=floor`, `verification_class=runtime_confirmed`, `finding.verified`).

| app | confirmed/targets | recall | precision |
| --- | --- | --- | --- |
| acme-saas | 9/22 | 0.4091 | 100% |
| shopflow | **9/19** (was 8/19) | 0.4737 | 100% |
| opsportal | 7/17 | 0.4118 | 100% |

The +1 is `SQL injection differential · GET /api/v1/search` (shopflow), seeded by
`GET /api/v1/search query=query` with `source=inferred_html:sensitive`, confirmed by the existing
`sqli_boolean` differential and replay path as `floor/runtime_confirmed`.

Per-source counts (`phase0.param_discovery`, dev seed 1 run 3):

| app | observed | inferred_bundle | inferred_html | inferred_ast | sensitivity checked / passed / dead |
| --- | --- | --- | --- | --- | --- |
| acme-saas | 24 | 0 | 23 | 0 | 2 / 0 / 2 |
| shopflow | 34 | 0 | 5 | 0 | 1 / 1 / 0 |
| opsportal | 36 | 0 | 9 | 0 | 2 / 0 / 2 |

Held-out shopflow cell (`phase0.param_discovery`):

```json
{"observed":34,"inferred":5,"sensitivityPassed":1,
 "byProvenance":{"observed":34,"inferred_bundle":0,"inferred_html":5,"inferred_ast":0},
 "bySource":{"inferred_html":4,"inferred_html:sensitive":1,"openapi":22,"route_map":12}}
sensitivity: {"checked":1,"passed":1,"dropped":0}
```

- **Inferred params that passed sensitivity:** 1 (`query`, held-out shopflow and dev shopflow).
  The other `inferred_html` rows are response-field-derived JSON body fields for write targets;
  the three checked-but-dead query candidates on acme/ops were deleted.
- **Confirmations from an inferred param:** 1 in dev seed 1 and 1 in salted held-out — both after
  the normal differential/replay verification, never from the inferred name alone.
- No `inferred_bundle`/`inferred_ast` rows appeared in these three product cells (their JS had no
  request literals); both tags are covered by `tests/v7-param-discovery.test.ts`.

Capability suites:

| suite | result |
| --- | --- |
| xben-25 | **25/25**, 0 FP, precision 100% (re-run after the final merge) |
| held-out-saas | **20/20**, 0 FP, precision 100% (re-run after the final merge) |
| held-out-saas patches | **20/20 fixed, 20/20 reproduced-before** |

Regression caught during validation: the first noise filter rejected dotted names, which dropped
the `filter.name` JSON body field for the time-blind SQLi capability cell (held-out-saas 19/20,
`trigger_miss` on `hos-08`). Fixed with location-aware filtering (dots allowed for body fields,
rejected for query keys) and covered by a unit test; 20/20 restored.

## 5. Reviewer triage

| recommendation | decision | note |
| --- | --- | --- |
| explicit observed / inferred_bundle / inferred_html / inferred_ast preserved end-to-end | **accept** | tags in `source`; metrics by provenance; inferred never a static claim |
| filter UI/JS noise + require sensitivity check before confirmation use | **accept** | noise regex + paired control-vs-probe; dead inferences deleted |
| do not observed-gate the headline number | **accept** | the +1 came from `inferred_html:sensitive`; provenance stays visible, no observed-only filter |
| confirmation still requires verifyReceipt/oracle invariants | **accept / out of lease** | no verification code changed; the existing floor differential + replay gate produced `runtime_confirmed` |
| fix hypothesis selection directly | **defer** | `deterministic-engine.ts` outside lease; proposed diff recorded in §1; recon risk bump is the in-lease workaround |

## 6. Remaining blocker / next steps

The `catalog*` derived routes dominate the SQLi quota because `pathHasSearchHint` matches the
substring `log` inside “catalog”. That is a generic word-boundary defect in the engine's hint
predicate (outside this lease). Fixing it (or reserving one sensitivity-checked quota slot) should
make the recon risk bump unnecessary and may free budget for further held-out moves.
