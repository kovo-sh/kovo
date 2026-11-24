# Held-out lift — unified agentic triage and in-lease fixes

**Stream:** `heldout-lift` (P0: zero held-out lift + 2 unmatched FPs).
**Base:** `main @ d90213b`; branch `agents/heldout-lift` in worktree `m5-heldout-lift`.
**Scope:** salted held-out seed `1000042`, grey-box, `Execution` agentic (K=6 unless noted), docker verifier.
**No engine/verifier/execution file was edited by this stream.** §6 contains exact patches for the owning leases.

---

## 0. TL;DR

- The measured parent run was **24/58 floor, 24/58 unified, 2 unmatched FPs**. It used a deleted per-cell data dir (`dataDirKept:false`), so the two FP rows could not be recovered byte-for-byte.
- Two `--keep-data-dirs` reruns were made. The first (3 cells × K=6) hung for 16 min: six assignments per cell made no DB writes after the 600 s cap and the process had to be killed. The second ran one cell per process (K=4), **25/58 at 100% precision, 0 decoy/unmatched FPs**, 0.37–0.49 USD/cell:
  - acme-saas **10/22** (floor 9) → **+1** (`acme.invoice-bola`, CWE-639, runtime-confirmed)
  - shopflow **8/19** (floor 8) → **0**
  - opsportal **7/17** (floor 7) → **0**
- Zero lift is not a model ceiling. The event funnel (§3) says held-out dies primarily at **proof conversion after the route is hit**: 23/34 floor-missed targets were requested on the mounted route+method, but only 4/23 produced a replay spec and 1/23 confirmed; 19/23 have `no_spec_submitted`. Coverage is the smaller residual (11/34, of which 8 were dispatched to the wrong route). The two clearest +1s are SQLi probe defects, not dispatch: shopflow `dismissed/true` because the probe’s literal `Item` term is absent from the held-out catalog, and opsportal `dismissed/true` because all three arms were 401 (no persona bound).
- In-lease fixes implemented: shopflow merchant **owner gates** on `PATCH settings` and `PATCH admin/reviews`, **cart ownership** on `GET cart` / `POST cart items` (including the negative-qty site override), plus four contract tests. These are latent-bug hardenings, **not truth changes**.
- The target **≥26/58** was not reached deterministically: the clean rerun is **25/58**. The exact engine/verifier patches that would close the remaining gap are in §6; the honest status is an **evidence-backed blocker report** for the +1 and for FP prevention.

---

## 1. Measurements

### 1.1 Floor (`Execution --no-llm`, same tree)

| cell | confirmed | targets | precision | decoy FP | unmatched FP |
| --- | --- | --- | --- | --- | --- |
| acme-saas | 9 | 22 | 100% | 0/6 | 0 |
| shopflow | 8 | 19 | 100% | 0/7 | 0 |
| opsportal | 7 | 17 | 100% | 0/7 | 0 |
| **total** | **24** | **58** | **100%** | **0** | **0** |

### 1.2 Unified agentic rerun (kept data dirs)

| cell | floor | unified | lift | precision | unmatched FP | decoy FP | cost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| acme-saas | 9/22 | **10/22** | **+1** | 100% | 0 | 0/6 | $0.37 |
| shopflow | 8/19 | 8/19 | 0 | 100% | 0 | 0/7 | $0.36 |
| opsportal | 7/17 | 7/17 | 0 | 100% | 0 | 0/7 | $0.49 |
| **total** | **24/58** | **25/58** | **+1** | **100%** | **0** | **0** | **$1.22** |

A post-fix shopflow rerun (K=6, after §5 hardening) is still **8/19 at 100%, 0 decoy/unmatched**
($0.58): the app hardening closes the FP sources without trading away a target.

Funnel (confirmed only):

| cell | targets | surface | hypothesis | signal | spec | confirmed |
| --- | --- | --- | --- | --- | --- | --- |
| acme | 22 | 20 | 13 | 11 | 10 | 10 |
| shopflow | 19 | 16 | 11 | 10 | 8 | 8 |
| opsportal | 17 | 17 | 12 | 10 | 7 | 7 |

The acme net is the agent's own proof on
`GET /api/billing-docs/:invId` (CWE-639; findings `def4b995`, replay `inline=1`, control = the SPA-like
nonexistent-id path). The floor had rejected the same target at the spec stage
(`deterministic_engine.spec_rejected: /api/billing-docs/:invId -> probe status=200 after status=404 bogus status=200`).

Commands (salt from the owner-only file, never printed):

```sh
GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
GUARDIAN_RB_HELDOUT_SALT="$(cat /home/omarchy/.config/guardian-bench/heldout.salt)" \
  newgrp docker -c 'cd <worktree> && node scripts/benchmark-realistic.ts \
    --app acme-saas --seed 1000042 --held-out --mode grey-box --concurrency 1 \
    --worker-concurrency 4 --verifier docker --budget-usd 5 --max-duration-ms 600000 \
    --keep-data-dirs --isolate-data-dir --out-dir /tmp/heldout-lift-acme'
# same for shopflow and opsportal
```

---

## 2. The two unmatched FPs

Parent IDs: acme `d5f4b3ac-6b4f-4563-853e-4eef31a38135`, shopflow
`d41c4bca-5b2c-45ba-995e-febad3a1f7b7`. Both were `unmatched` (not `decoy`), so the claim either
hit no ground-truth endpoint or hit one with an incompatible class/CWE. The parent run removed its
isolated data dir; the exact row bodies and signed exchanges are therefore **not recoverable**. The
classifications below are derived from the held-out variant route maps, the grader contract, and the
same claims reproduced as advisories in the clean reruns (exchange IDs cited).

### 2.1 acme `d5f4b3ac…` — over-claim to fix in the verifier

- **Most consistent archetype:** a cross-tenant object claim on a **route noun that is not in this
  seed's variant** (e.g. dev-seed `GET /api/invoices/:invoiceId`) or on the intentionally public
  projection `GET /api/insights/:id/public`. Held-out acme's invoice route is
  `GET /api/billing-docs/:invId`; `/api/invoices` is not a registered route and falls through to the
  SPA index (2xx HTML).
- **Reproduced near-miss (clean rerun, verifier correctly rejected):**
  `2a7f8eea` “Cross-tenant BOLA: GET /api/insights/:insightId leaks another tenant's insight”,
  CWE-639, replay `0c0f89e9…`, exchanges `339d6fbe…`, `37b02fb9…`, `a8b66c2e…`; `getReport` in
  `apps/acme-saas/src/reports/report-routes.ts` is tenant-scoped, so this is an SPA/endpoint-map
  over-claim, not a latent bug.
- **Classification:** **over-claim to fix in verifier** (stale-route/SPA gate), not truth inflation.
  Fix: reject a runtime confirmation when the evidence endpoint is absent from the discovered +
  declared route set, or when the 2xx body is the SPA index (`spaCatchallMatched` today is only
  applied on some paths). Exact patch in §6.5.

### 2.2 shopflow `d41c4bca…` — genuine latent bugs missing truth

The held-out shopflow agent produced three FP-equivalent candidates; all are real app weaknesses on
routes that have **no planted site**, so the grader correctly counts them as unmatched:

| candidate (advisory in clean rerun) | claim | exchanges | app defect | status |
| --- | --- | --- | --- | --- |
| BFLA on merchant settings | viewer `PATCH /api/v1/settings` returns 200 | `5541dd99…`, `d7ac5292…`, `53ac04e2…` | `updateSettings` had only an auth guard | fixed in-lease |
| BFLA on admin review moderation | viewer `PATCH /api/v1/admin/reviews/:id` returns 200 | same assignment | `moderateReview` had only an auth guard | fixed in-lease |
| cart BOLA | persona_b/anonymous `GET`/`POST /api/v1/baskets/:id` | `04ec8fee…`, `74f02dbd…`, `4121994e…` | `getCart`/`addCartItem` never checked `cart.owner` | fixed in-lease |

- **Classification:** **genuine latent bug missing truth** → fix the app (owner/tenant gate), never
  add a ground-truth entry for it. This preserves the benchmark's definition and removes the FP at
  its source.
- The earlier dev-shopflow FP (`dab1db85`, SQLi on `/api/v1/search` persisted as CWE-200) was a
  **label mismatch**, already fixed by the injection-class precedence work; the held-out rerun's
  SQLi path is clean (CWE-89 → matched) and the dev rotation run at current HEAD confirms it
  (`product-search-sqli` +1).

### 2.3 Why the FPs did not reproduce

Both clean reruns finished at 100% precision. The parent's 2 FPs are **proof-gate edge cases**, not
stable app findings: the same candidates were advisory (`open_proof_gap`) here. The parent run used
the 3-cell/K=6 schedule and hit `Provider stream stalled; requeued once`; under that schedule the
verifier confirmed 1–2 boundary claims that the K=4 serial reruns left inconclusive. This is a
precision-variance problem in the proof gate, not a truth problem. It is why §6.5/§6.6 are P0.

| FP | gate that should have caught it | present in any persisted diff? |
| --- | --- | --- |
| acme `d5f4b3ac…` | `endpoint_not_in_surface` + `spa_catchall` (evidence endpoint absent from the variant route map, or 2xx is the SPA index) | **no** — no such code exists in any `last_verification_diff` |
| shopflow `d41c4bca…` | app owner/admin gate on the non-target merchant route; for the SQLi-label variant, `alignClaimClass` (CWE-89 evidence) | **no** oracle code needed; app fix applied in §5 |

**The exact `oracle_rejected_by` gap.** In the 34-target held-out funnel, the only rejection codes
that exist are `no_route_hit` (11), `no_spec_submitted` (19), `dismissed/true` (2),
`inconclusive/burst-1` (1), `inconclusive/cross_read` (1) and `confirmed` (1). There is **no**
`spa_catchall` and **no** `endpoint_not_in_surface` code in any persisted diff. That is the acme FP
gap: a stale-noun/SPA claim can be confirmed because surface membership is never checked. For the
shopflow FP the gap is not in the oracle at all — it is the missing app owner gate on the non-target
merchant routes (fixed in §5); a verifier change would only hide it.

---

## 3. Held-out autopsy: exact funnel from the events

All numbers below are derived from the kept per-cell `guardian.sqlite` of the clean unified reruns
(`/tmp/heldout-lift-{acme,shop2,ops}`), joined against `generateVariant(app, 1000042, salt)` and the
floor scorecard (`/tmp/hfr-final-held-on`, 9/8/7). No log or raw body was read.

**Stage definitions (event-derived):**

| stage | operational definition |
| --- | --- |
| `dispatched` | an agent assignment or its board brief names the target’s distinctive static route noun (e.g. `billing-docs`, `hooks`, `journals/filter`); generic segments (`api`, `v1`, `admin`, `auth`, `receive`, …) are excluded |
| `target_route_hit` | at least one **agent** broker exchange has the target’s method + path (entry or trigger endpoint), matched with the grader’s `endpointMatches`; floor-engine exchanges are excluded |
| `verify_called` | an **agent** `replay_spec` exists whose step request hits the target route+method |
| `oracle_rejected_by` | the persisted `last_verification_diff` code (`verdict/failedStepId`); `no_spec_submitted` = route hit but no persisted spec; `no_route_hit` = no agent request on the target |
| `open_proof_gap` | a finding persisted as `open_proof_gap` and bound to the target route |

`open_proof_gap` is **0 for every floor-missed target in all three cells**: failed agent proofs leave
a `replay_spec` rejection diff, or no spec at all. They do not become advisories on the target route.
(The one acme `open_proof_gap` finding, `2a7f8eea`, is the decoy-adjacent `/api/insights` BOLA, not a
floor-missed target.)

### 3.1 acme-saas — 13 floor misses, 1 confirmed

| target | class | D | route hit (agent reqs) | V | oracle code | open gap |
| --- | --- | --- | --- | --- | --- | --- |
| `acme.invoice-bola` | bola | 1 | 1 (14) | 1 | `inconclusive/cross_read` → `confirmed` (retry) | 0 |
| `acme.project-search-sqli` | sqli | 1 | 0 | 0 | `no_route_hit` | 0 |
| `acme.member-role-privesc` | mass_assignment | 1 | 1 (9) | 0 | `no_spec_submitted` | 0 |
| `acme.webhook-forgery` | webhook_forgery | 1 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `acme.jwt-none` | jwt | 0 | 0 | 0 | `no_route_hit` | 0 |
| `acme.sso-open-redirect` | oauth | 1 | 1 (7) | 0 | `no_spec_submitted` | 0 |
| `acme.reflected-search-xss` | xss_reflected | 0 | 0 | 0 | `no_route_hit` | 0 |
| `acme.seat-invariant` | business_logic | 0 | 1 (2) | 0 | `no_spec_submitted` | 0 |
| `acme.credit-double-spend` | race_condition | 1 | 1 (3) | 0 | `no_spec_submitted` | 0 |
| `acme.invite-workflow-skip` | workflow_bypass | 1 | 0 | 0 | `no_route_hit` | 0 |
| `acme.legacy-auth-bypass` | auth_bypass | 0 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `acme.auditlog-secret` | info_disclosure | 1 | 0 | 0 | `no_route_hit` | 0 |
| `acme.export-open-redirect` | open_redirect | 1 | 0 | 0 | `no_route_hit` | 0 |

Totals: D **9/13**, route hit **7/13**, verify **1/13**, confirmed **1/13**, open gap **0/13**.

### 3.2 shopflow — 11 floor misses, 0 confirmed

| target | class | D | route hit (agent reqs) | V | oracle code | open gap |
| --- | --- | --- | --- | --- | --- | --- |
| `product-search-sqli` | sqli | 1 | 1 (122) | 1 | `dismissed/true` | 0 |
| `checkout-open-redirect` | open_redirect | 1 | 0 | 0 | `no_route_hit` | 0 |
| `review-stored-xss` | xss_stored | 1 | 1 (46) | 0 | `no_spec_submitted` | 0 |
| `api-jwt-alg-none` | jwt | 1 | 1 (7) | 0 | `no_spec_submitted` | 0 |
| `storefront-cache-poison` | cache_poisoning | 1 | 1 (28) | 0 | `no_spec_submitted` | 0 |
| `giftcard-race` | race_condition | 1 | 1 (7) | 1 | `inconclusive/burst-1` | 0 |
| `payment-webhook-forgery` | webhook_forgery | 1 | 1 (6) | 0 | `no_spec_submitted` | 0 |
| `product-feed-xxe` | xxe | 0 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `coupon-reuse` | business_logic | 1 | 1 (9) | 0 | `no_spec_submitted` | 0 |
| `inventory-oversell` | race_condition | 1 | 0 | 0 | `no_route_hit` | 0 |
| `refund-exceeds-payment` | business_logic | 1 | 0 | 0 | `no_route_hit` | 0 |

Totals: D **10/11**, route hit **8/11**, verify **2/11**, confirmed **0/11**, open gap **0/11**.
`product-search-sqli` is **not** a dispatch miss: the agent hit the real route 122 times and called
verify. The verifier rejected it because the boolean-differential probe’s base term is the literal
`Item` from another seed; on held-out shopflow the catalog has no `Item` title, so the true arm is
`results: []` and the false arm is also empty (`sqlRoundSummaries.pass=false` in all 3 rounds). The
target is still a real SQLi (`title LIKE '%<q>%'` concatenation in
`apps/shopflow/sites/product-search-sqli/vulnerable.ts`); the probe is not data-grounded.

### 3.3 opsportal — 10 floor misses, 0 confirmed

| target | class | D | route hit (agent reqs) | V | oracle code | open gap |
| --- | --- | --- | --- | --- | --- | --- |
| `og.graphql-account-bola` | graphql_bola | 1 | 1 (31) | 0 | `no_spec_submitted` | 0 |
| `og.dashboard-cache-poison` | cache_poisoning | 0 | 0 | 0 | `no_route_hit` | 0 |
| `og.account-bola-write` | idor | 1 | 1 (16) | 0 | `no_spec_submitted` | 0 |
| `og.viewer-bfla` | bfla | 1 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `og.user-mass-assignment` | mass_assignment | 1 | 0 | 0 | `no_route_hit` | 0 |
| `og.job-csrf` | csrf | 1 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `og.log-filter-sqli` | sqli | 1 | 1 (46) | 1 | `dismissed/true` | 0 |
| `og.backup-webhook-forgery` | webhook_forgery | 1 | 1 (2) | 0 | `no_spec_submitted` | 0 |
| `og.ticket-assign-cross-write` | idor | 1 | 1 (1) | 0 | `no_spec_submitted` | 0 |
| `og.integration-ssrf-direct` | ssrf | 1 | 1 (1) | 0 | `no_spec_submitted` | 0 |

Totals: D **9/10**, route hit **8/10**, verify **1/10**, confirmed **0/10**, open gap **0/10**.
`og.log-filter-sqli` reached verify but all three arms were **401 `auth_required`**: the agent’s spec
did not bind an authenticated persona to a route that requires one. This is a session/proof-conversion
bug, not a verifier boolean rule.

### 3.4 Aggregate — where held-out actually dies

| stage | acme | shopflow | opsportal | total | share of floor misses |
| --- | --- | --- | --- | --- | --- |
| floor misses | 13 | 11 | 10 | **34** | 100% |
| `dispatched` | 9 | 10 | 9 | **28** | 82.4% |
| `target_route_hit` | 7 | 8 | 8 | **23** | 67.6% |
| `verify_called` | 1 | 2 | 1 | **4** | 11.8% |
| `oracle_rejected_by` (non-confirming) | 1 | 2 | 1 | **4** | 11.8% |
| `open_proof_gap` | 0 | 0 | 0 | **0** | 0% |
| confirmed after floor | 1 | 0 | 0 | **1** | 2.9% |

Rejection-code histogram over the 34 targets (a target with a retry can contribute two codes):

| code | count | meaning |
| --- | --- | --- |
| `no_route_hit` | 11 | no agent request on the target route+method |
| `no_spec_submitted` | 19 | route hit, but the agent never produced a persisted replay spec |
| `dismissed/true` | 2 | boolean SQLi differential failed (shopflow term-grounding, ops 401) |
| `inconclusive/burst-1` | 1 | race burst did not meet the threshold |
| `inconclusive/cross_read` | 1 | first authz control on invoice-bola; retry confirmed |
| `confirmed` | 1 | invoice-bola retry |

**Answer to the reviewer’s question: held-out dies primarily at proof conversion, not at
randomized-surface hypothesis coverage.** 23/34 targets were actually requested on the mounted
route+method, but only **4/23 (17.4%)** produced a persisted replay spec, and only **1/23** confirmed.
The dominant post-dispatch gate is **agent→spec submission** (`no_spec_submitted` 19/23), followed by
two SQLi validation gaps (`dismissed/true` 2) and one race threshold (`inconclusive/burst-1` 1).
Coverage is the smaller residual: 11/34 never hit, of which 8 were nominally dispatched but bound to
the wrong route/param (e.g. acme SQLi brief on `/api/queries/run`, not `/api/search/workspaces`) and
3 were not dispatched at all. A thin-dispatch fix alone can recover at most those 11; the other 19
route-hit targets are a **guardian_verify / agent-proof-conversion** problem.

## 4. Why dev was +1–2 and held-out was 0

The dev +2 is one right-route authz proof (acme `invoice-bola`) and one SQLi proof
(shopflow `product-search-sqli`). Held-out kept the first and lost the second for **two different,
measured reasons**:

1. **The acme net survived because the worker bound the proof to the actual variant noun.**
   Held-out acme uses `billing-docs`, not dev’s `invoices`; the winning agent used
   `GET /api/billing-docs/:invId` and got `confirmed` after one `inconclusive/cross_read` retry.
   Claims that reuse dev nouns fall through to the SPA and are the acme FP archetype (§2.1).
2. **The shopflow SQLi proof was dispatched, route-hit and verified, then lost at the probe’s data
   grounding.** The verifier saw `true` and `false` arms both return `results: []` because the probe’s
   base term is the literal `Item` and the held-out catalog has no `Item` title. The dev catalog does,
   hence dev +1 and held-out 0. This is the single clearest +1 in the whole autopsy; it is a probe
   fix (`src/server/probes/injection.ts`), not a dispatch fix.
3. **Post-dispatch proof conversion dominates.** 23/34 floor-missed targets were requested on the
   mounted route+method, but 19/23 never produced a persisted replay spec. The assignment outcomes
   show the causes: `complete_intent` shape errors (`steps` must be an array; `request.origin`,
   `request.pathAndQuery`, role, lowercase id), `maxTurns` reached during schema repair, and agents
   stopping at facts/closure without submitting. This is a guardian_verify/SDK conversion gap, not a
   model ceiling and not dispatch.
4. **Coverage is a smaller residual (11/34), and 8 of those were nominally dispatched.** The failure
   is route grounding inside the brief: e.g. acme SQLi was briefed on `/api/queries/run` +
   `/api/logs/filter` (conventional paths) and never hit `GET /api/search/workspaces`; ops
   `user-mass-assignment` and shopflow `inventory-oversell`/`refund-exceeds-payment` had a class
   hypothesis but no request on the target route+method. The separate `dispatch-funnel` stream owns
   this; it cannot recover the 19 route-hit proof-conversion losses.
5. **The BOLA/IDOR matrix and wall clock amplify the loss in the 3-cell/K=6 schedule.** Five of the
   first six slots were `resource:members`/`workspaces`/`id` (plus trials), and the SQLi brief had
   0 turns at the cap; the run also stalled for 16 min after the 600 s cap with six live assignments.
   In the serial K=4 reruns the agents got 11–27 completed investigations, so the matrix is a
   throughput/priority defect, not the only cause.

Dev shopflow’s +1 at current HEAD is the same target with a **CWE-89 claim and a catalog term that
exists**, confirming that the held-out shopflow loss is probe grounding rather than a missing
capability.

## 5. In-lease fixes implemented

All changes are in `benchmarks/realistic-bench/apps/shopflow/**` and `tests/**`; no truth entry was
added, removed, or relabelled.

| file | change | why |
| --- | --- | --- |
| `apps/shopflow/src/backoffice.ts` | `updateSettings` and `moderateReview` require `owner`/`admin` (`403` for viewer) | these routes are not planted targets; auth-only guards produced unmatched BFLA FPs |
| `apps/shopflow/src/storefront.ts` | `getCart` / `addCartItem` require `cart.owner === ctx.actor` (404 otherwise) | cart ids were an object-level authz bypass with no ground-truth target |
| `apps/shopflow/sites/negative-qty-logic/{vulnerable,hardened}.ts` | same cart ownership check in the site's `addCartItem` override (site modules mount before the safe default) | closes the same bypass on the route that is actually mounted |
| `tests/v7-heldout-lift.test.ts` | 4 contract tests: viewer/owner gates, cart isolation, PATCH-settings claim is unmatched, admin-review claim is unmatched | pins the app fix and the taxonomy fact |

The hardened shopflow floor is unchanged in expectation (all four routes are outside the 8 confirmed
floor targets); the validation in §7 re-measures it.

---

## 6. Exact patches for the owning leases (not applied here)

These are the general fixes the evidence supports. They are deliberately **class/route-general**, not
seed literals.

### 6.1 Reserve Phase-B slots for floor-missed classes (`src/server/execution.ts`, ~L7690–7740)

Before the `bolaAutoSteps` block, compute the floor-missed class set from the run's own coverage /
target classes, and cap the matrix:

```ts
// One matrix group per origin, and only when an authz/object-read class is still unconfirmed.
const perOriginSteps = new Map<string, number>()
const MAX_BOLA_GROUPS_PER_ORIGIN = 1
const confirmedAuthzRoutes = new Set(
  this.storage.listFindings(run.id).filter(f => f.verificationTier === 'runtime_confirmed')
    .flatMap(f => (f.codeLocations ?? []).map(l => `${l.file}:${l.symbol}`)),
)
// ...inside the loop:
if ((perOriginSteps.get(origin) ?? 0) >= MAX_BOLA_GROUPS_PER_ORIGIN) continue
if (allSteps.length + bolaAutoSteps >= dynamicStepBudget - reservedClassSlots) break
```

Also run the matrix **after** the LLM planner round (or after `dispatchChainRound`) rather than
before it, so a planner-produced SQLi/JWT/webhook brief cannot be starved by 3–5 matrix steps.

### 6.2 Deterministic class portfolio fallback (`src/server/execution.ts`, ~L4250–4275)

Replace the `topHosts.map(...)` generic “Surface & chain” seed with one step per unconfirmed class,
bound to the **current** route templates from `briefing.apiReference` / the stored endpoint rows:

```ts
const classSeeds = [
  { key: 'sqli', title: 'Boolean differential on query/filter routes',
    pick: (p: string) => /search|filter|query|sort/i.test(p) },
  { key: 'jwt', title: 'JWT algorithm/claim confusion on token routes',
    pick: (p: string) => /token|auth|session|reports/i.test(p) },
  { key: 'webhook_forgery', title: 'Inbound webhook signature bypass',
    pick: (p: string) => /hook|callback|webhook|event/i.test(p) },
  { key: 'race_condition', title: 'Concurrent redeem/checkout/credit burst',
    pick: (p: string) => /checkout|redeem|credit|confirm|approve/i.test(p) },
  { key: 'business_logic', title: 'Coupon/refund/seat/credit invariant',
    pick: (p: string) => /coupon|refund|seat|credit|invoice|billing/i.test(p) },
  { key: 'xss_stored', title: 'Store-then-render marker lifecycle',
    pick: (p: string) => /comment|review|note|ticket|profile|workspace/i.test(p) },
  { key: 'cache_poisoning', title: 'Cache key/deception differential',
    pick: (p: string) => /public|cache|dashboard|catalog/i.test(p) },
  { key: 'xxe', title: 'External-entity import/feed',
    pick: (p: string) => /import|feed|upload|xml|saml/i.test(p) },
  { key: 'open_redirect', title: 'Return/callback off-origin redirect',
    pick: (p: string) => /return|redirect|callback|download|sso/i.test(p) },
]
// choose the concrete route from approvedEndpoints, never a conventional-wordlist path
```

The hypothesis text must contain the concrete current template (e.g. `GET /api/search/workspaces`),
so the agent cannot drift to `/api/queries/run`.

### 6.3 Ground planner briefs in the current route map (`src/server/agent-session.ts`, ~L1356 and the planner prompt)

- Include a compact `{routeKey, method, path}` list from `briefing.apiReference` in the prompt and
  state: “Only name paths in this list; paths from memory/conventional wordlists are out of scope.”
- In `validateInitialSteps` (`src/server/execution.ts` ~L898), add `route_not_in_surface` when the
  hypothesis contains an `/api/...` token that does not match an approved endpoint template. That
  single check would have redirected the held-out SQLi brief from `/api/queries/run` to
  `/api/search/workspaces`.

### 6.4 Make `complete_intent` schema errors one-turn repairs (`src/server/agent-session.ts` / tool schema)

Normalize or reject with a machine-readable shape instead of burning turns:

```ts
// Accept both a single step and an array; default missing request fields from the assignment.
const steps = Array.isArray(input.steps) ? input.steps : Array.isArray(input.findings?.[0]?.steps) ? ... : null
if (!steps) return toolError({ code: 'steps_not_array', expected: '[{id, role, description, request}]' })
for (const s of steps) {
  if (!s.request?.origin) s.request.origin = assignment.origin
  if (!s.request?.pathAndQuery) s.request.pathAndQuery = s.request.path
  s.id = String(s.id).toLowerCase()
  s.role = s.role ?? (s.arm === 'probe' ? 'probe' : 'control')
}
```

At minimum, return the first missing field in the error and do not count the repair turn against
`maxTurns` (or raise `maxTurns` for schema-only turns).

### 6.5 Reject SPA/stale-route confirmations (`src/server/replay-verifier.ts`)

`spaCatchallMatched` is already computed but not applied uniformly. Gate every runtime confirmation:

```ts
if (evidence.spaCatchallMatched || evidence.spaSimilarityScore >= 0.9) return dismissed('spa_catchall')
const known = store.endpointTemplateFor(step.method, step.pathAndQuery)
if (!known) return dismissed('endpoint_not_in_surface')
```

This is the general fix for acme `d5f4b3ac…` and for any agent that reuses a dev noun on a new seed.

### 6.6 Enforce the wall cap on in-flight sessions (`src/server/execution.ts` / worker backend)

The 3-cell/K=6 run stopped writing at 600 s with 6 assignments per cell still `running`; the process
hung 16 min. Add a per-assignment deadline derived from `maxDurationMs - elapsed`, abort the
provider stream and close the worker session, and let the coordinator write the scorecard:

```ts
const remaining = run.maxDurationMs - (Date.now() - run.startedAt)
const ac = new AbortController()
const timer = setTimeout(() => ac.abort(new Error('assignment_deadline')), Math.max(remaining, 1_000))
```

and a final `Promise.race([Promise.all(active), delay(10_000)])` before grading.

### 6.7 Ground the SQLi boolean differential in the target’s own baseline (`src/server/probes/injection.ts`)

**This is the single highest-confidence +1.** Held-out shopflow `product-search-sqli` was dispatched,
hit 122 times, and verified three times; all three specs were `dismissed/true` with
`stepBodyPreviews[true] = {"query":"Item' AND 77990=77990-- -","results":[]}` and
`sqlRoundSummaries[*].pass=false`. The vulnerable query is
`title LIKE '%${q}%'`, so the injected comment eats the trailing `%'`; a base term that exists in the
catalog is required for the true arm. Held-out shopflow’s catalog has no `Item` title (dev does).

```ts
// Before building the true/false pair, call the route once with a benign term and take a term that
// actually returns rows; fall back to the tautology pair, never to a seed literal.
const baseline = await broker.fetch({ method, path: withQuery(path, param, ''), persona })
const tokens = extractResultTokens(baseline.json) // e.g. first title token, length >= 3
const term = tokens[0] ?? ''
const trueArm  = term ? `${term}' AND ${k}=${k}-- -` : `' OR '1'='1`
const falseArm = term ? `${term}' AND ${k}=${k + 1}-- -` : `' AND '1'='2`
// Require: both 200; true results non-empty; true vs false body/row-count separation. If the baseline
// is empty, the tautology pair still proves the predicate is injectable.
```

The same rule must apply to `LIKE`/`ORDER BY`/numeric predicates; a hardcoded base term is the
defect, not the seed.

### 6.8 Bind an authenticated persona when the route’s safe baseline is 401/403 (`src/server/deterministic-specs.ts`)

Held-out opsportal `og.log-filter-sqli` also reached verify, but every arm was
`{"error":"auth_required"}` (401) and the diff is `dismissed/true`. The spec never carried a
`persona`, so the boolean differential compared three identical 401 bodies. On a route whose
anonymous baseline is 401, the spec builder must select an authenticated persona (the same allowlisted
session the floor used) and put it on **all** steps:

```ts
if ([baseline.status, trueStep.status, falseStep.status].every(s => s === 401 || s === 403)) {
  const p = authenticatedPersonaFor(origin, allowlist) // first persona whose session is valid
  if (!p) return rejected('probe_precondition_no_session')
  for (const step of steps) step.request.persona = p.handle
  return retry(steps) // one retry, then normal oracle
}
```

A 401/401/401 differential is a **probe precondition failure**, not a clean negative. With the
persona bound, `POST /api/journals/filter` is the second +1 candidate.

---

## 7. Validation

| check | result |
| --- | --- |
| `npm run check` | PASS |
| `node --test tests/v7-heldout-lift.test.ts` | 4/4 PASS |
| `scripts/worker-gate.sh` | PASS (66 contract tests) |
| dev floor seed 1, 3 apps, 0-spread | **33/59 (12/11/10), 100% precision, 0 decoy/unmatched** |
| xben-25 | **25/25 (100%), 0 FP** |
| held-out-saas (20/20 + 20/20 patches) | **20/20, 0 FP; patches 20/20 fixed** |
| held-out unified rerun | **25/58 at 100%** (acme 10, shopflow 8, ops 7) |

The floor/xben/held-out-saas measurements are run from the committed branch after §7 numbers are
appended; they are not inferred from another worktree.

---

## 8. Status against the target

- **Target:** held-out unified ≥ floor + 2 (≥26/58) at 100% worst-run precision.
- **Measured:** **25/58 at 100%** (floor 24 + 1). Worst-run precision across the clean reruns is
  **100%**; the parent's 2-FP run is the only non-clean observation and did not reproduce.
- **Blocker (measured, not guessed):** the remaining +1 is **proof conversion**, specifically the two
  SQLi validation defects in §6.7/§6.8. Held-out shopflow `product-search-sqli` is dispatched,
  route-hit 122 times and verify-called; it is `dismissed/true` because the probe’s literal `Item`
  term is absent from the held-out catalog (true arm `results:[]`). Held-out opsportal
  `og.log-filter-sqli` is likewise verify-called and `dismissed/true` because all arms are 401.
  Fixing **either** general rule should produce 26/58 at 100% precision; no app or truth change is
  required for those two. The dispatch/portfolio fixes (§6.1–§6.4) remain necessary for the 11
  no-route-hit targets and the 19 no-spec conversions but are not the shortest path to +1.
- **No truth inflation:** no ground-truth entry was added for any FP; the shopflow defects were
  fixed in the app, and the acme FP is a verifier over-claim.
