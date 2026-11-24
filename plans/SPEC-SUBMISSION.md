# Spec submission: why 19 held-out route-hit targets never persisted a spec

Source artifacts (no raw logs): the clean held-out autopsy cells for seed **1000042** (grey-box,
K=6, salted), `guardian.sqlite` + `agent-sessions/*.sqlite` + the floor scorecards:

| app | kept dir | floor card |
| --- | --- | --- |
| acme-saas | `/tmp/heldout-lift-acme/data/acme-saas-seed1000042-grey-box` | `/tmp/hfr-final-held-on/acme-saas-seed1000042-grey-box.json` |
| shopflow | `/tmp/heldout-lift-shop2/data/shopflow-seed1000042-grey-box` | `/tmp/hfr-final-held-on/shopflow-seed1000042-grey-box.json` |
| opsportal | `/tmp/heldout-lift-ops/data/opsportal-seed1000042-grey-box` | `/tmp/hfr-final-held-on/opsportal-seed1000042-grey-box.json` |

Derivation is structured-only: assignments/exchanges/replay_specs/events from SQLite plus the
assistant text/tool-call parts of the kept session DBs. `mono-admin-bfla` has **no agentic artifact**
on this machine (only `--no-llm` realism-suite cells), so it is not in the table below.

## 1. The 19 rows

`wall` is assignment dispatch → last assignment event / the budget wall. `statuses` are the HTTP
status codes the agent received on the target route. `anomaly` = the trace text notes the target
anomaly (leak / cross-tenant / bypass / missing scoping) near a distinctive target-route noun.

| app | target | class | turns | wall (ms) | endReason | statuses | personas | last3 tools | anomaly |
| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| acme | `acme.member-role-privesc` | mass_assignment | 12/12 | 136712/85000 | turn_limit | 200,401,404 | 3 | verify_replay_spec>record_fact>verify_replay_spec | yes |
| acme | `acme.webhook-forgery` | webhook_forgery | 12/12 | 26010/85000 | turn_limit | 404 | 1 | record_fact>record_coverage>complete_intent | yes |
| acme | `acme.sso-open-redirect` | oauth | 12/12 | 144475/85000 | turn_limit | 302,401 | 0 | verify_replay_spec ×3 | yes |
| acme | `acme.seat-invariant` | business_logic | 12/12 | 94254/85000 | turn_limit | 200 | 1 | record_coverage ×3 | yes |
| acme | `acme.credit-double-spend` | race_condition | 12/12 | 94254/85000 | turn_limit | 200,409 | 1 | record_coverage ×3 | yes |
| acme | `acme.legacy-auth-bypass` | auth_bypass | 17/30 | 149716/160000 | wall_limit | 401 | 0 | record_fact>record_coverage>complete_intent | no |
| shopflow | `review-stored-xss` | xss_stored | 12/12 | 151800/85000 | turn_limit | 200,201,401 | 4 | record_fact>propose_chain_finding ×2 | yes |
| shopflow | `api-jwt-alg-none` | jwt | 10/12 | 56571/85000 | concluded_clean | 401 | 2 | record_coverage>record_fact>complete_intent | yes |
| shopflow | `storefront-cache-poison` | cache_poisoning | 12/30 | 92323/160000 | concluded_clean | 200 | 3 | record_coverage>board_post>complete_intent | yes |
| shopflow | `payment-webhook-forgery` | webhook_forgery | 12/12 | 59301/85000 | turn_limit | 400 | 1 | record_fact ×2>record_coverage | yes |
| shopflow | `product-feed-xxe` | xxe | 12/12 | 85081/85000 | turn_limit | 200 | 1 | record_fact>derive_evidence>verify_replay_spec | yes |
| shopflow | `coupon-reuse` | business_logic | 12/12 | 35903/85000 | turn_limit | 404 | 1 | record_fact>record_coverage ×2 | yes |
| opsportal | `og.graphql-account-bola` | graphql_bola | 12/12 | 64504/85000 | turn_limit | 200,401 | 4 | record_coverage ×3 | yes |
| opsportal | `og.account-bola-write` | idor | 12/12 | 92293/85000 | turn_limit | 200,401 | 3 | record_fact ×2>propose_chain_finding | yes |
| opsportal | `og.viewer-bfla` | bfla | 12/12 | 59557/85000 | turn_limit | 403 | 1 | propose_chain_finding ×3 | yes |
| opsportal | `og.job-csrf` | csrf | 12/12 | 59557/85000 | turn_limit | 200 | 1 | propose_chain_finding ×3 | yes |
| opsportal | `og.backup-webhook-forgery` | webhook_forgery | 11/12 | 59818/85000 | concluded_clean | 200 | 0 | record_fact>record_coverage>complete_intent | yes |
| opsportal | `og.ticket-assign-cross-write` | idor | 12/12 | 59557/85000 | turn_limit | 200 | 1 | propose_chain_finding ×3 | yes |
| opsportal | `og.integration-ssrf-direct` | ssrf | 12/30 | 0/160000 | claimed_in_text_only | 200 | 1 | request_http ×2>load_skill | yes |

## 2. Column tallies

| column | tally |
| --- | --- |
| `endReason` | **turn_limit 14**, wall_limit 1, concluded_clean 3, claimed_in_text_only 1, tool_error 0 |
| turn/wall limit while actively probing | **15/19 (78.9%)** (all 15 had 1–46 target-route requests) |
| `httpStatusesSeen` includes 2xx on the target route | 14/19; non-2xx-only 5/19 (404, 302/401, 401, 400, 403) |
| `personasTried` | 0: 3, 1: 10, 2: 1, 3: 3, 4: 2 |
| `anomalyNotedInTrace` | **yes 18/19** |
| last-3 tool shape | `record_coverage`/`record_fact`/`complete_intent` close-outs dominate; 5 rows end on repeated `propose_chain_finding`/`verify_replay_spec` repair |
| `targetVulnClass` | webhook_forgery 3; idor 2; business_logic 2; mass_assignment, oauth, race_condition, auth_bypass, xss_stored, jwt, cache_poisoning, xxe, graphql_bola, bfla, csrf, ssrf 1 each |

### Cause classification (from §1 + the assignment outcome text)

| primary cause | rows | classes |
| --- | ---: | --- |
| (a) turn/wall cap hit while still probing or repairing a spec | **12** | mass_assignment, oauth, xss_stored, jwt, cache_poisoning, xxe, idor ×2, bfla, csrf, webhook_forgery, race_condition |
| (b) settlement/revoked phase, `guardian_verify` still allowed but skipped | 5 | business_logic ×2, webhook_forgery ×2, race_condition |
| (c) leaning `complete_intent` accepted with no target spec | 0 primary (2 overlapping: acme webhook `[partial]`, shopflow xss `[partial]`) | — |
| (d) offline claim with no execution | 0 (every row had target-route requests) | — |
| (e) brief never stated a per-target spec obligation | **all 19** (cross-cutting; the N-2 nudge named proof tools but not the route or the mandatory spec) | — |

## 3. Decision rule

Pre-agreed rule applied to §2:

- **RULE 1 FIRED — mostly `turn_limit`/`wall_limit` while actively probing: 15/19 (78.9%).**
  Single-step work is capped at 12 turns / 80 s, and 7 of the 12 turn-limit rows were actively
  repairing a spec (`verify_replay_spec`/`propose_chain_finding`) when the cap hit. Raise the
  single-step budget **12 → 18 turns, 80 s → 120 s**, plus the reserved wrap-up verify turn.
- Rule 2 (mostly 400/401/422 + `concluded_clean`) did **not** fire: 3 `concluded_clean` rows, and
  14/19 saw a 2xx on the target route.
- Rule 3 signal is strong but secondary: `anomalyNotedInTrace=yes` 18/19 (94.7%) with only 3 clean
  conclusions — the proof-submission friction fix (wrap-up enforcement, route-specific directive,
  coded proof-gap path) is still required, which is why both fixes land.

### Fixes landed in this stream

- **Reserved wrap-up verify turn + route-specific obligation** (`src/server/agent-session.ts`):
  settlement pauses offline analysis while the most-probed route has no covering spec; the N-2
  nudge and 85% banner name `METHOD path param=…` and repeat `GUARDIAN_VERIFY_SPEC_SHAPE`;
  `complete_intent(proved|partial)` is rejected with the exact missing `proofGapReason` or spec.
- **Coded proof gaps** (`record_coverage` → `open_proof_gap`): `no_spec_shape`,
  `no_authenticated_persona`, `baseline_empty`, `no_control_path`, `runtime_unavailable`,
  `tier_blocked`, `out_of_scope`, `no_reproducible_signal`; free-text gaps are recorded but do not
  discharge the obligation.
- **Budget cap raise** (`src/server/execution.ts`, owned by the dispatch stream — exact patch in the
  stream report): `SINGLE_STEP_ASSIGNMENT_MAX_TURNS 12 → 18`,
  `SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS 80_000 → 120_000`; `settlementTurn` follows `maxTurns-2`
  automatically. Update `tests/v7-brief-slice.test.ts`’s single-step expectations in the same merge.

## 4. FP evidence capture

`scripts/benchmark-realistic.ts` now embeds a redacted `falsePositiveEvidence` block in the per-cell
`<slug>.json` and `<slug>.meta.json` whenever `unmatchedFindingIds` / `misclassifiedFindingIds` is
non-empty: `{ findingId, vulnClass, cwe, category, route{method,pathTemplate}, verificationClass,
provenance, oracleRulePassed, claimedDeltaSummary, exchangeSummaries[{stepId,method,status,rejectedBy}] }`.
Captured before temp dirs are removed; 0-FP artifacts are byte-identical (no key).
