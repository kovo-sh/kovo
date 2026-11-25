# Parity diff — procedural harness vs product `Execution --no-llm` (dev seed 1)

**Stream:** `parity-diff` (read-only measurement). **Base:** `main @ d71eb37`, branch `agents/parity-diff`.
**Scope:** classify every realistic-bench target that the **procedural deterministic harness** confirms but the
**product `Execution --no-llm`** misses, into `not_in_surface` / `not_probed_before_deadline` / `probed_no_signal` /
`signal_no_confirm`, and identify the dominant bucket. No source, test, harness or app file was modified.

## 0. Inputs (structured artifacts only)

| Leg | Command (abridged) | Result |
| --- | --- | --- |
| Procedural | `node benchmarks/realistic-bench/benchmark-realistic.ts --app <app> --seed 1 --mode grey-box --out-json /tmp/parity/proc-<app>.json` ×3 | **38/59 (64.4%)** — acme 13/22, shopflow 14/19, opsportal 11/18 |
| Product | `node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm --verifier docker --isolate-data-dir --concurrency 3` | **26/59 (44.1%)** — acme 13/22, shopflow 7/19, opsportal 6/18 |

Product per-cell funnel (grader): acme `22→17→16→14→13→13`, shopflow `19→11→8→8→7→7`,
opsportal `18→13→10→8→6→6` (targets→surface→hypothesis→signal→spec→confirmed).
Structural evidence read read-only from each cell's `kovo.sqlite` (`endpoints`, `endpoint_params`,
`broker_exchanges`, `facts`, `replay_specs`, `findings`, `events` of kind `deterministic_engine.*`) and from
`generateVariant(blueprint, 1)` for the runtime route map. No logs, bodies or payload strings were loaded.

**Set arithmetic.** |procedural| = 38, |product| = 26, intersection = 21 ⇒ **17 targets are procedural-only**
(the parity set below) and **5 are product-only** (§5). 16 further targets are missed by both (§2 totals, scope B).

## 1. Parity set — 17 targets the harness confirms and the product misses

| # | Target | App | Class | Procedural | Product | Bucket | Structural reason (one line) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `acme.member-role-privesc` | acme-saas | mass_assignment | confirmed | missed | `probed_no_signal` | `PATCH /api/people/:personId` only got an authz probe (`no_signal`, 18 req); the mass-assignment hypothesis is hard-wired to POST, so the `permission` field is never written. |
| 2 | `acme.invoice-write-bola` | acme-saas | bola | confirmed | missed | `signal_no_confirm` | `PATCH /api/invoices/:invoiceId` authz probe **signalled** (2× `unauthorized_access`) but `synthAuthz` emitted no candidate (`spec_skipped`), so no replay spec existed. |
| 3 | `acme.project-stored-xss` | acme-saas | xss_stored | confirmed | missed | `probed_no_signal` | `PATCH /api/spaces/:projectId` got an authz probe (`no_signal`, 20 req); there is no stored/second-order XSS intent (`xss_context` is reflected-only). |
| 4 | `acme.admin-bfla` | acme-saas | bfla | confirmed | missed | `not_in_surface` | `DELETE /api/admin/people/:personId`: DELETE is dropped in four places (stored-endpoint filter, derived method list, tolerant parser, authz hypothesis), so it can never be queued. |
| 5 | `shopflow.product-search-sqli` | shopflow | sqli | confirmed | missed | `signal_no_confirm` | `GET /api/v1/search` sqli probe **signalled**, but all 3 `sql_boolean_diff` candidates were dismissed: “did not hold across all 3 randomized rounds”. |
| 6 | `shopflow.checkout-open-redirect` | shopflow | open_redirect | confirmed | missed | `not_probed_before_deadline` | `GET /api/v1/checkout/return` is in the probe surface (conventional list) but the redirect intent cap (6) was consumed elsewhere — zero probe events. |
| 7 | `shopflow.order-mass-assignment` | shopflow | mass_assignment | confirmed | missed | `probed_no_signal` | `PATCH /api/v1/orders/:orderId` only authz-probed (`no_signal`, 12 req); mass-assignment is POST-only and has no privileged-field candidates. |
| 8 | `shopflow.checkout-workflow-skip` | shopflow | workflow_bypass | confirmed | missed | `not_probed_before_deadline` | `POST /api/v1/orders/:orderId/confirm` is in the surface (conventional list) but no workflow intent exists — zero probes. |
| 9 | `shopflow.inventory-oversell` | shopflow | race_condition | confirmed | missed | `not_probed_before_deadline` | `POST /api/v1/bags/:cartId/checkout` is a stored endpoint; no race intent/probe class exists (`race_burst` is a verifier kind only). |
| 10 | `shopflow.admin-impersonate-privesc` | shopflow | bfla | confirmed | missed | `not_in_surface` | `POST /api/v1/admin/impersonate` is discarded by `deriveDeterministicRouteTargets` (no id segment, and the imported OpenAPI carries path params only ⇒ no “injectable” param). |
| 11 | `shopflow.over-refund-chain` | shopflow | business_logic | confirmed | missed | `not_in_surface` | `POST /api/v1/refunds/lines` discarded by the same derive filter (body-only write route). |
| 12 | `og.report-ssti` | opsportal | ssti | confirmed | missed | `not_probed_before_deadline` | `POST /api/docs/render` is a stored endpoint; `ssti_math` exists in `probes/injection.ts` but is never enumerated by the engine. |
| 13 | `og.ticket-note-xss` | opsportal | xss_stored | confirmed | missed | `not_probed_before_deadline` | `POST /api/issues/:ticketId/notes` is in the surface; no register-then-render XSS lifecycle exists — zero probes. |
| 14 | `og.diag-cmdi` | opsportal | command_injection | confirmed | missed | `not_probed_before_deadline` | `POST /api/diagnostics/run` is a stored endpoint; `command_injection` exists as a probe class but is never enumerated. |
| 15 | `og.job-csrf` | opsportal | csrf | confirmed | missed | `probed_no_signal` | `POST /api/jobs/:jobId/trigger` csrf probe ran but returned `inconclusive` after 2 requests (state field / token discovery failed). |
| 16 | `og.integration-secret-disclosure` | opsportal | info_disclosure | confirmed | missed | `probed_no_signal` | `GET /api/links` got only an authz probe (`no_signal`, 8 req); `secret_disclosure` cap is 4 and no `secretScan` ran on this collection. |
| 17 | `og.job-workflow-skip` | opsportal | workflow_bypass | confirmed | missed | `probed_no_signal` | `POST /api/jobs/:jobId/complete` was csrf-probed (`inconclusive`); `workflow_invariant` is not enumerated, so the state-machine bypass is never tested. |

## 2. Bucket totals

**Scope A — the 17 parity targets (the question asked):**

| Bucket | Count | Share | Targets |
| --- | --- | --- | --- |
| `probed_no_signal` | 6 | 35.3% | 1, 3, 7, 15, 16, 17 |
| `not_probed_before_deadline` | 6 | 35.3% | 6, 8, 9, 12, 13, 14 |
| `not_in_surface` | 3 | 17.6% | 4, 10, 11 |
| `signal_no_confirm` | 2 | 11.8% | 2, 5 |

**Scope B — all 33 product misses** (adds the 16 both-missed targets): `not_probed_before_deadline` 16 (48.5%),
`probed_no_signal` 10 (30.3%), `not_in_surface` 4 (12.1%), `signal_no_confirm` 3 (9.1%).

**Dominant bucket: no bucket owns >50%.** `probed_no_signal` and `not_probed_before_deadline` tie at 6/17 (35%)
in the parity set; across all 33 misses `not_probed_before_deadline` leads at 16/33 (48.5%) but is still not a
majority. The honest read of the cause, not just the label:

- **14 of the 16 “not probed” targets are not deadline/budget casualties** — they have no probe port for their
  class at all (ssti, cmdi, jwt, race, workflow/business-logic, cache, auth-bypass, stored-XSS); the other 2 are
  intent-cap casualties (redirect, sqli). No miss in this run is a wall-clock (`stoppedReason: time`) cut.
- So the dominant *driver* is **class-coverage, not wall clock**: the engine enumerates 10 probe intents
  (`authz, csrf, graphql, mass_assignment, redirect, secret_disclosure, sqli, ssrf, traversal, xss`) while
  `src/server/probes/` already owns 8 more classes (`ssti_math`, `command_injection`, `auth_protocol_audit`,
  `cache_poison_deception`, `workflow_invariant`, `webhook_signature_bypass`, `sqli_time_diff`, `nosqli_type`)
  that the engine never asks for.
- If “missing probe port” is attributed to `probed_no_signal` (as the task's parenthetical allows), that bucket
  owns **24 of 33 misses (72.7%)** and 11 of 17 parity targets.

**Surface funnel evidence.** Briefing-route coverage of the engine's *effective* probe surface
(stored ∪ derived ∪ conventional): acme 52/67, shopflow 52/64, opsportal 57/65 — 35 briefing routes never reach
the engine, of which 6 are DELETE and 29 are body-only writes with no id segment. The product's own grader
funnel records `surface_miss` 5 / 8 / 5 = 18 targets, consistent with this route-level gap.

## 3. Per-class breakdown (product seed 1, all three apps)

| Class | Targets | Product confirmed | Parity-set misses | Bucket(s) |
| --- | --- | --- | --- | --- |
| mass_assignment | 4 | 1 | 2 | probed_no_signal ×2 |
| bola | 7 | 6 | 1 | signal_no_confirm |
| bfla | 3 | 0 | 2 | not_in_surface ×2 |
| sqli | 4 | 1 | 1 | signal_no_confirm |
| xss_stored | 2 | 0 | 2 | probed_no_signal, not_probed |
| workflow_bypass | 4 | 0 | 2 | not_probed, probed_no_signal |
| info_disclosure | 3 | 2 | 1 | probed_no_signal |
| csrf | 3 | 2 | 1 | probed_no_signal |
| open_redirect | 2 | 1 | 1 | not_probed |
| race_condition | 2 | 0 | 1 | not_probed |
| business_logic | 3 | 0 | 1 | not_in_surface |
| ssti | 2 | 0 | 1 | not_probed |
| command_injection | 1 | 0 | 1 | not_probed |
| **fully covered (no parity gap)** | jwt 0/2, cache 0/1, webhook 0/1, auth_bypass 0/1 | | 0 | product misses are shared with the harness |
| **no product gap at all** | ssrf 4/4, xxe 2/2, path_traversal 3/3, idor 2/2, graphql_bola 1/1 | | 0 | — |

Product seed-1 zero-recall classes: `bfla`, `business_logic`, `jwt`, `race_condition`, `ssti`,
`command_injection`, `workflow_bypass`, `xss_stored`, `cache_poisoning`, `webhook_forgery`, `auth_bypass`.

## 4. Top 5 fixes in `src/server/` (targets recovered per unit effort)

| # | Fix | Files / modules | Bucket closed | Parity targets | Effort |
| --- | --- | --- | --- | --- | --- |
| 1 | **Stop discarding briefing routes and DELETE.** Drop the `ep.method !== 'DELETE'` filters, add `delete` to the derived method list, and replace the `!hasInjectable && !deterministicIdPath` drop with “always queue a briefing/OpenAPI path, with a generic body-field candidate set”. | `src/server/execution.ts` (`runEngineInvestigation` stored-endpoint filter, `deriveDeterministicRouteTargets` method list + filter, `parseTolerantOpenApiTargets`), `src/server/deterministic-engine.ts` (authz hypothesis `method !== 'DELETE'`, DELETE→GET method mapping) | `not_in_surface` | 3 (4, 10, 11) + unblocks ~29 body-only routes per seed | **S** (~30 lines) |
| 2 | **Close the signal→spec gaps.** `synthAuthz`: emit a candidate for mutating hits that carry no concrete resource id, and stop requiring a 4xx bogus-id control on routes that 2xx unknown ids (use a cross-persona read-back assertion instead). `sql_boolean_diff`: accept 2-of-3 randomized rounds or a baseline-relative inequality for LIKE/OR-branch search. | `src/server/deterministic-specs.ts` (`synthAuthz`, `negativeControlJq`), `src/server/replay-verifier.ts` (boolean-differential rounds ~L1477–1530) | `signal_no_confirm` | 2 (2, 5) (+ `og.user-mass-assignment` in scope B) | **S** (~40 lines) |
| 3 | **Mass-assignment / privilege-field probe on PATCH/PUT.** Keep the route's real method instead of forcing POST; derive candidate fields from the harvested body schema plus a privileged vocabulary (`role, permission, status, owner, tenant_id, amount, price`); one read-back assertion proves the escalation. | `src/server/deterministic-engine.ts` (`enumerateHypotheses` mass_assignment, `buildProbeRequest` `case 'mass_assignment'`), `src/server/deterministic-specs.ts` (`synthMassAssignment`) | `probed_no_signal` | 2 (1, 7) | **M** (~60 lines) |
| 4 | **Wire the probe families the engine already ships.** Add intents/hypotheses + `buildProbeRequest` cases + converters for `ssti_math`, `command_injection`, `workflow_invariant` (and `cache_poison_deception`, `auth_protocol_audit` while in the file). Probe implementations and verifier kinds (`rce_proof`, `auth_protocol_proof`, `cache_differential`, `race_burst`) already exist; only enumeration + spec synthesis are missing. | `src/server/deterministic-engine.ts` (intent table + caps + `buildProbeRequest`), `src/server/deterministic-specs.ts` (new converters + `vulnClassOfSpec`), reuse `src/server/probes/{injection,workflow,cache,jwt}.ts` | `not_probed_before_deadline` | 4 (12, 14, 8, 17) | **M–L** (~200 lines) |
| 5 | **Stored/second-order XSS + secret scan on collections.** Add an `xss_stored` intent that writes a benign marker through the write route and renders it via the read/trigger route (same lifecycle as `probeSecondOrderSsrf`), and raise/route `secret_disclosure` (cap 4 → per-origin, `secretScan` on link/integration collections). | `src/server/deterministic-engine.ts` (new intent + cap), `src/server/deterministic-specs.ts` (`synthStoredXss`), `src/server/probes/xss.ts` | `probed_no_signal` / `not_probed` | 3 (3, 13, 16) | **M–L** (~150 lines) |

Ranking is targets-per-effort: #1 and #2 are near-mechanical and together recover 5/17; #3–#5 recover the
remaining 9. No fix here requires a new probe implementation for classes 12/14/15/16/17 — the ports exist and
are simply unreachable from the deterministic engine.

## 5. Where the procedural harness is weak (product confirmed, harness missed)

Five targets are confirmed by the product and missed by the harness — the product floor is **not** a subset of
the harness:

| Target | App | Class | Harness funnel evidence |
| --- | --- | --- | --- |
| `acme.project-mass-assign` | acme-saas | mass_assignment | harness reached 19/22 hypotheses but only 15/19 signals (probe did not fire) |
| `acme.reflected-search-xss` | acme-saas | xss_reflected | same signal-stage gap (product `xss_context` fired on 1 request) |
| `acme.settings-csrf` | acme-saas | csrf | same signal-stage gap |
| `acme.auditlog-secret` | acme-saas | info_disclosure | same signal-stage gap |
| `og.webhook-ssrf` | opsportal | ssrf | harness 13/18 signals, 11/13 specs — second-order SSRF lifecycle missed |

Harness-side residual losses on the same cells are spec-stage (`replay_spec_miss` 5/5/6) and budget
(`budget_exhausted` 3 on acme), so the two floors fail in different places: the harness loses at
signal→spec, the product loses at surface→signal.

## 6. What to measure next (one run, <10 min)

Apply fix #1 only, then:

```sh
KOVO_ALLOW_LOCAL_LAB=1 newgrp docker -c 'cd <worktree> && \
  node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm \
  --verifier docker --isolate-data-dir --concurrency 3 --max-duration-ms 600000 \
  --out-dir /tmp/parity/fix1'
```

Expected (~4–5 min wall clock, no agentic budget): total recall 26 → **28–29/59**; `surface_miss` 18 → 13–14;
and, per cell sqlite, `endpoints` gains the DELETE/body-only routes, with `deterministic_engine.probe` events for
`DELETE /api/admin/people/:personId`, `POST /api/v1/admin/impersonate` and `POST /api/v1/refunds/lines`.
Check exactly three structured signals: (a) the three probe events exist, (b) `acme.admin-bfla` flips to
confirmed, (c) precision stays 100% with 0 decoy/unmatched FP. If (a) passes but (b) does not, the next blocker is
the DELETE→GET method mapping in `deterministic-engine.ts`, not the surface filter.

**Caveat to carry into the next measurement.** Part of today's parity is supplied by
`expandConventionalSurfaceTargets`, a hard-coded route wordlist (`/api/seats`, `/api/enrollments/accept`,
`/api/issues/:ticketId/notes`, `/api/jobs/:jobId/trigger`, `/api/staff/:userId/role`, …) that happens to match
these three apps' nouns. Held-out seeds randomize nouns, so re-run the same diff on one salted held-out seed
after fix #1: expect the `not_in_surface` share to grow unless fix #1 removes the wordlist dependency.
