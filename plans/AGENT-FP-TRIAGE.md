# Agent-FP triage (held-out precision 83.3% / 87.5% → 100%)

**Stream:** `agent-fp-triage` · **Branch:** `agents/agent-fp-triage` · **Base:** `66be563`
**Cell under audit:** definitive held-out unified, seed `1000042`, 600 s, K=6, salt via
`GUARDIAN_RB_HELDOUT_SALT` (never printed). Kept dirs: `/tmp/heldout-unified-definitive`.

Baseline on that cell: 29/58 targets confirmed (50% recall), shopflow precision **83.3%**
(2 unmatched FPs), opsportal precision **87.5%** (1 unmatched + 1 misclassified).

Method: every ruling below comes from the fixture source and a **serial replay** of the recorded
exchanges (`startRealisticApp` / `bootApp` with one fresh order / one persona at a time), never from
the claim text. Raw bodies and candidate payloads are not reproduced here; probes are named by class.

---

## Rulings

| # | Claim | Bucket | Fixture change | Tier-0 archetype |
| :-- | :--- | :--- | :--- | :--- |
| 1 | opsportal `GET /api/me`, CWE-269 "viewer reassigns another tenant's case" | **Verifier FP (bucket 1)** — the behaviour is a real *planted* idor; the claim's route/label are wrong | **none** (hardening the route would delete the `og.ticket-assign-cross-write` target) | `anon-control-authz` |
| 2 | shopflow `POST /orders/:id/payments`, CWE-840 "non-idempotent double capture" | **Unintended, non-planted (bucket 2)** — reproduced serially, no concurrency needed | **harden** `src/orders.ts` capturePayment (one-shot ledger write) | — |
| 3 | shopflow `GET /stores/:storeId/catalog/:id`, CWE-639 "anon reads the loyalty note" | **Verifier FP (bucket 1)**, ruled by `agents/catalog-public` | none here (see that branch) | `catalog-canary-public-read` |
| 4 | opsportal `POST /journals/filter`, CWE-20 "unhandled 500" (also charged) | **Verifier FP (bucket 1)** — the 500 is the *planted* SQL interpolation choking on a non-numeric value | **none** (a 400 guard would neuter `og.log-filter-sqli`) | `error-status-only-injection` |

### 1 · opsportal cross-tenant ticket assign — verifier FP, not a fixture bug

Serial replay on the recorded plan (viewer in tenant `9ca676`, ticket owned by `6ea2e7`):

- `GET /api/me` (both personas) → 200; the *resource* tenant is a model-declared identity value.
- anonymous `POST /cases/:id/assign` → **401**.
- viewer `POST /cases/:id/assign` (no assignee → acting user) → **200**, and the owner's readback shows
  `assignee_id` changed: the foreign ticket really was mutated.

`og.ticket-assign-cross-write` is a *planted* target (`idor`, CWE-639) whose vulnerable twin omits the
target-ticket team check. So the app genuinely permits the action: this is **not** bucket 2, and
hardening it would drop recall. The claim is charged because (a) it declares the route `GET /api/me`
(first control step) instead of the mutating exchange, and (b) `CWE-269`/`bfla` is only a documented
*sibling* of `idor`, which is uncharged in loose `precision` but counted in `strictPrecision` and
`incompatibleClassCount`.

Two verifier fixes are needed (neither is in this stream's lease):

1. **Anonymous 401 is not an authorization reference.** In `src/server/oracle-invariants.ts`, the
   boundary control for an authenticated cross-tenant *write* must be a signed-in sibling; today
   `peerDenial()` returns `true` for a control with no tenant, so `anon=401` discharges the authz
   invariant by itself.

   ```diff
   --- a/src/server/oracle-invariants.ts
   +++ b/src/server/oracle-invariants.ts
   @@ export function assessAuthorizationImpact(input: ImpactInput): AuthorizationAssessment {
   +  // An anonymous 401 proves the route requires authentication, never that this actor lacks
   +  // authorization. For an authenticated cross-tenant write the boundary control must be a signed-in
   +  // sibling denied on the same route; otherwise every tenant bug is "confirmed" by anon=401.
   +  const signedIn = (step: ImpactStep): boolean => step.actor.handle !== null || step.actor.role !== null
   +  const crossTenantWrite = mutatingProbe !== null && declaredResourceTenant !== null &&
   +    probeTenant !== null && declaredResourceTenant !== probeTenant
      const peerDenial = (control: ImpactStep): boolean => {
        const tenant = control.actor.tenant ?? null
   +    if (crossTenantWrite && !signedIn(control)) return false
        if (tenant === null || probeTenant === null) return true
   ```

2. **Bind the finding route to the mutating step.** The persisted finding's `route`/`method` (and the
   claim title it seeds) currently come from `steps[0]`, which is a control read. In the replay
   verifier's verified-finding payload, derive `route`/`method` from the step that carries the delta
   (the mutating probe, else the first successful probe). `endpointsFromReplaySpec` already collects
   every step, so grading is unaffected; the *record* stops claiming `/api/me`.

**Operator decision (deferred, do not silently absorb):** `alignClaimClass` deliberately never
relabels an authorization claim, so `CWE-269` on a planted `idor` route can never earn recall. If we
want that label canonised to the evidence class (`idor`/CWE-639) it changes recall attribution
(opsportal 7/17 → 8/17) and must be an explicit, versioned decision — not part of an FP cleanup.
Left as-is; the claim stays uncharged for recall.

### 2 · shopflow capture — unintended, non-planted, hardened

`src/orders.ts` `capturePayment` only checked order ownership and then inserted a new captured
payment row on every POST. Serial replay, fresh order, one persona, no K=6 concurrency:

| | before | after |
| :--- | :--- | :--- |
| capture ×3 statuses | 200 / 200 / 200 | 200 / 409 / 409 |
| ledger rows for the order | 1 → 4 | 1 → 2 |
| second order still captures | 200 | 200 |

So this is **not** cross-worker interference and **not** "partial payments intended": the route takes
no amount (it always charges the order total), and no planted site or solver calls it. Recorded in
`benchmarks/CHANGELOG.md` as *unintended, non-planted, recall unchanged*. Recall cannot move because
`capturePayment` is not (and does not become) a ground-truth endpoint; the contract test pins that.

### 3 · shopflow catalog — ruled elsewhere

`agents/catalog-public` already ruled this family: catalog reads are intended public, the anonymous
fallback leaked a customer note canary, and their fixture change removes it. No change here and no
duplicate ruling; the evidence in `/tmp/heldout-unified-definitive` matches theirs.

### 4 · opsportal log filter 500 — verifier FP, planted SQLi symptom

Serial replay with the admin persona: an in-range threshold returns the caller's rows, an out-of-range
threshold returns none, a trailing boolean-tautology suffix defeats the threshold (the planted
`og.log-filter-sqli` is intact), and a **non-numeric** value makes the interpolated expression raise
an unhandled 500. The 500 is the planted vulnerability's symptom: a 400 guard for non-numeric input
would also reject the tautology payload and destroy the target. No fixture change.

The over-claim is accepted because `CWE-20` / `injection-input` classifies as `other`, and
`assessImpactEvidence` returns `satisfied: true` for unknown classes — so a spec whose only assertion
is `probe.status == 500` confirms. Needed fix (not in this stream's lease):

```diff
--- a/src/server/oracle-invariants.ts
+++ b/src/server/oracle-invariants.ts
@@ export function assessImpactEvidence(input: ImpactInput): ImpactAssessment {
     case 'markup':
       return assessMarkupImpact(input)
     default:
+      // A confirmation may never rest on a status-code divergence alone: a 5xx often just proves the
+      // server choked on the payload (the very interpolation under test). Unknown-class claims need a
+      // semantic signal or a declared oracle event.
+      if (input.steps.some(step => (step.status ?? 0) >= 500) &&
+          !hasOracle(input.oracleEvents, ['cross_tenant_read', 'boolean_differential', 'sql_error_echo', 'invariant_violation'])) {
+        return { required: true, satisfied: false,
+          reason: 'An unknown-class claim rested on a 5xx: error behaviour is not proof of impact.' }
+      }
       return { required: false, satisfied: true, reason: 'Not an authorization/impact claim.' }
```

Tier-0 archetypes to add with those diffs: `anon-control-authz` (anonymous 401 as the sole control
for an authenticated cross-tenant write) and `error-status-only-injection` (a 5xx divergence accepted
as injection/SQLi confirmation). Until they land, opsportal's two remaining charges are
verifier-side and **must not** be "fixed" by deflating the planted sites.

---

## Changes in this branch

- `benchmarks/realistic-bench/apps/shopflow/src/orders.ts` — capture is a one-shot ledger write
  (409 `already_captured` on a repeat; exactly one new payment row).
- `benchmarks/CHANGELOG.md` — the hardening entry (*unintended, non-planted, recall unchanged*).
- `tests/v7-agent-fp-triage.test.ts` — one contract test per ruling: serial double-capture refused;
  capture is not a target; the planted opsportal assign stays exploitable; `/api/me` is target-free and
  CWE-269 stays a sibling; the log-filter interpolation stays exploitable and a CWE-20 claim is not
  the sqli target.
- No truth/`siteId` was added, relabelled or removed. N stays 58.

## Measurements

Filled by the validation run on this branch (dev floor, xben, held-out-saas, held-out cell).
