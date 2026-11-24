# Realism #2 (wan-oob) — M1 async OOB diagnosis and engine patch

Status: probe-lane changes are committed on `agents/realism-oob`. The engine-lane patch below is
**not applied** on this branch (lease collision with `heldout-floor-regress`); it is the exact diff
measured below and is ready to land after that stream merges.

Base: `3d4cefb` (main).

## 1. Diagnosis — why the floor formed no async hypotheses

Measured on an unmodified tree (`/tmp/opencode/realism-base`, `--fixture wan-oob --no-llm
--verifier docker`, data dir retained):

- Engine summary: `hypothesesFormed=64`, `byClass=… ssrf:0/10 …` and **no `xxe` entry**.
- SSRF hypotheses *were* formed on `/v1/integrations/webhook-test` (`callbackUrl`, `url`), but both
  were routed through `probeSecondOrderSsrf`, not the generic probe. The trigger matcher accepts the
  endpoint as its own sibling trigger (`bare.startsWith(parent + '/')`), so `triggerPath` was set to
  the write route itself.
- Two `202` responses were accepted, 14 durable canaries were registered, and exactly one callback
  arrived 27 s later (`engine:ssrf:url`). The drain's `promoteReceiptOob` promoted it, but
  `convertOobPromotions` silently skipped it: the carrier lookup is
  `searchExchanges(runId, subscription.token)`, and the exchange store indexes
  path/response-preview/headers, **not request bodies**. The canary URL only appeared in the JSON
  request body, so there was no carrier and no finding.
- XXE formed zero hypotheses: eligibility required observed XML (`observedEvidence.xml`), a
  declared/observed XML body value, or an XML-named parameter. `/v1/import/preview` is POST-only
  with no declared body and returns JSON, so the generic import/upload route-family hint (already
  used as a ranking tie-breaker) never became an eligibility signal.

So the funnel failed at **selection (XXE)** and **attribution (SSRF)**, not at minting/registration.

## 2. Engine patch (exact diff, applies to `3d4cefb`)

```diff
diff --git a/src/server/deterministic-engine.ts b/src/server/deterministic-engine.ts
index adf1c79..ab41236 100644
--- a/src/server/deterministic-engine.ts
+++ b/src/server/deterministic-engine.ts
@@ -1754,21 +1754,26 @@ export function enumerateHypotheses(
 
     // --- SSRF -------------------------------------------------------------------------------
     // A URL-consuming *write* is the SSRF source. Eligibility is structural: a declared body
-    // parameter whose family or observed value is URL-shaped, or a collection response that
-    // already publishes URL values (the target itself fetches them). Trigger routes are paired as
-    // the second-order fetch step, never probed as if they accepted a URL body.
+    // parameter whose family or observed value is URL-shaped, a URL-shaped query value on a
+    // mutating route, or a collection response that already publishes URL values (the target
+    // itself fetches them). Trigger routes are paired as the second-order fetch step, never probed
+    // as if they accepted a URL body.
     const triggerShaped = hasDynamicIdSegment(bare) && /(?:ping|test|trigger|fetch|replay|send|deliver|run|execute|verify)$/i.test(lastSegment)
-    const urlBodyParams = rankedFor(param =>
-      (param.location === 'json' || param.location === 'form') &&
+    const urlShapedParams = rankedFor(param =>
+      (param.location === 'json' || param.location === 'form' || param.location === 'query') &&
       (paramNameShape(param.name) === 'url' || param.observedShape === 'url'))
+    const urlBodyParams = urlShapedParams.filter(item => item.param.location !== 'query')
     const collectionPublishesUrls = (observedEvidence.urlValues?.length ?? 0) > 0
     if ((method === 'POST' || method === 'PUT') && !triggerShaped &&
-        (urlBodyParams.length > 0 || collectionPublishesUrls)) {
-      const declared = urlBodyParams.slice(0, 3).map(item => item.param)
+        (urlShapedParams.length > 0 || collectionPublishesUrls)) {
+      const declared = urlShapedParams.slice(0, 3).map(item => item.param)
       const params = declared.length > 0
         ? declared
         : [inferredParam(urlParamNames(bare)[0] ?? 'url', 'json')]
-      // Second-order: a sibling trigger route for the same resource collection.
+      // Second-order: a sibling trigger route for the same resource collection, or the write route
+      // itself when its own last segment is a fetch verb (the write is the trigger). Route nouns
+      // only shape the parameter vocabulary; a webhook/receiver family is selected from the
+      // route-family hint, not from an app-specific path literal.
       const trigger = endpoints.find(candidate => {
         const candidateBare = candidate.pathTemplate.split('?')[0] || '/'
         if (candidate.method.toUpperCase() !== 'POST') return false
@@ -1777,6 +1782,7 @@ export function enumerateHypotheses(
         return parts.length >= 2 && /(?:ping|test|trigger|fetch|replay|send|deliver|run)/i.test(parts[parts.length - 1] ?? '') &&
           (parent === bare || parent.startsWith(`${bare}/`) || bare.startsWith(`${parent}/`))
       })
+      const selfTrigger = /(?:ping|test|trigger|fetch|replay|send|deliver|run|execute|verify)$/i.test(lastSegment)
       for (const param of params) {
         add({
           key: `ssrf_canary|${endpoint.id}|${param.name}`,
@@ -1790,8 +1796,8 @@ export function enumerateHypotheses(
           ownerPersona: picks.owner?.handle,
           jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name, coerceNumericBodies),
           ssrfParams: [param.name],
-          ...(trigger && method === 'POST'
-            ? { triggerPath: (trigger.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, '/{{id}}') }
+          ...((trigger || selfTrigger) && method === 'POST'
+            ? { triggerPath: (trigger?.pathTemplate.split('?')[0] || bare).replace(idSegmentRe, '/{{id}}') }
             : {}),
           risk: endpointRiskScore(endpoint) + 12,
         })
@@ -1799,14 +1805,16 @@ export function enumerateHypotheses(
     }
 
     // --- XXE --------------------------------------------------------------------------------
-    // Eligibility is wire-format evidence: the route serves XML, or a declared/observed body value
-    // is XML-shaped. The route noun is only a priority tie-breaker.
+    // Eligibility is wire-format/route-family evidence: the route serves XML, a declared/observed
+    // value is XML-shaped, or the route belongs to a generic XML-consuming family (import/upload/
+    // parse/feed/archive). The family hint is a structural fallback for XML sinks that do not
+    // declare their request body; the route literal is never consulted.
     const xmlBodyEvidence = Object.values(observedValues)
       .some(values => values.some(value => classifyValueShape(value) === 'xml'))
     const declaredXmlParam = inferred.some(param =>
       (param.location === 'json' || param.location === 'form') &&
       (paramNameShape(param.name) === 'xml' || param.observedShape === 'xml'))
-    if (method === 'POST' && (observedEvidence.xml === true || xmlBodyEvidence || declaredXmlParam)) {
+    if (method === 'POST' && (observedEvidence.xml === true || xmlBodyEvidence || declaredXmlParam || pathHasXmlHint(bare))) {
       add({
         key: `xxe_canary|${endpoint.id}`,
         endpoint,
@@ -3265,7 +3273,10 @@ async function probeSecondOrderSsrf(
   if (!info.running) info = await canaryBroker.startListener()
   const exchangeIds: string[] = []
   let requests = 0
-  const send = async (pathAndQuery: string, value: string): Promise<BrokerExchangeResult | null> => {
+  // A route whose own last segment is a trigger verb (`…/test`, `…/send`, `…/verify`) runs the
+  // fetch as part of the write, so the write exchange is the trigger and no second call is needed.
+  const triggerIsSelf = trigger.split('?')[0] === hyp.pathAndQuery.split('?')[0]
+  const send = async (pathAndQuery: string, value: string, traceId?: string): Promise<BrokerExchangeResult | null> => {
     const body = { ...stagingBody, [param.name]: value }
     try {
       const exchange = await input.broker.executeHttp({
@@ -3274,6 +3285,10 @@ async function probeSecondOrderSsrf(
         pathAndQuery,
         headers: { 'Content-Type': 'application/json', ...stagingHeaders },
         body: JSON.stringify(body),
+        // In a local lab the broker records this as `X-Guardian-Trace-Id`, so the exchange that
+        // carried the injected canary is identifiable when the callback arrives after the probe
+        // window (request bodies are not indexed, headers are).
+        ...(traceId ? { traceId } : {}),
         ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
         runId: input.runId,
         assignmentId: input.assignmentId,
@@ -3314,7 +3329,7 @@ async function probeSecondOrderSsrf(
 
   const control = await send(hyp.pathAndQuery, 'http://guardian-control.invalid/')
   const controlId = control ? extractCreatedId(control.body) : null
-  if (controlId) await triggerFetch(controlId)
+  if (controlId && !triggerIsSelf) await triggerFetch(controlId)
 
   const minted = canaryBroker.mintCanary(
     input.runId,
@@ -3322,9 +3337,9 @@ async function probeSecondOrderSsrf(
     hyp.endpoint.origin,
     input.storage ? { storage: input.storage, assignmentId: input.assignmentId } : undefined,
   )
-  const probe = await send(hyp.pathAndQuery, minted.httpUrl)
+  const probe = await send(hyp.pathAndQuery, minted.httpUrl, minted.token)
   const probeId = probe ? extractCreatedId(probe.body) : null
-  if (probeId) await triggerFetch(probeId)
+  if (probeId && !triggerIsSelf) await triggerFetch(probeId)
 
   const deadline = Date.now() + 3_000
   let hit = false
@@ -4108,6 +4123,23 @@ export function trackFloorCanarySubscriptions(
       anomaly.promoted = record.promoted
     }
 
+    // A hit is not the only admissible outcome: a hypothesis whose canary was minted and sent but
+    // whose callback has not arrived yet is a recorded *attempt*, not a silent miss. The durable
+    // subscription is the evidence that the run-level drain can still promote it; this record makes
+    // the attempt inspectable while it is pending.
+    const attempts = [...byToken.values()].filter(record => record.stage === 'pending' && !record.promoted)
+    for (const record of attempts) {
+      log('deterministic_engine.oob_attempt',
+        `Floor canary ${record.canaryId} was injected; durable subscription ${record.subscriptionId ?? 'none'} is still pending at probe finalize (no callback inside the probe window).`, {
+          canaryId: record.canaryId,
+          subscriptionId: record.subscriptionId,
+          label: record.label,
+          probeClass: result.probeClass,
+          endpoint: result.pathAndQuery,
+          verdict: result.verdict,
+        })
+    }
+
     const records = [...byToken.values()]
     const primary = records.find(record => record.stage === 'late')
       ?? records.find(record => record.stage === 'immediate')
@@ -4126,6 +4158,17 @@ export function trackFloorCanarySubscriptions(
       ...(primary ? { oobCanaryId: primary.canaryId } : {}),
       ...(primary ? { canaryProbeStage: primary.stage } : {}),
       promoted: records.some(record => record.promoted),
+      ...(attempts.length > 0
+        ? {
+            oobAttempts: attempts.map(record => ({
+              token: record.token,
+              canaryId: record.canaryId,
+              label: record.label,
+              subscriptionId: record.subscriptionId,
+              stage: record.stage,
+            })),
+          }
+        : {}),
     }
   }
 
@@ -4472,6 +4515,10 @@ export async function runDeterministicEngine(input: DeterministicEngineInput): P
       continue
     }
     canaryTracker?.finalize(probe)
+    const oobAttempts = Array.isArray(probe.details.oobAttempts) ? probe.details.oobAttempts.length : 0
+    if (oobAttempts > 0 && probe.verdict !== 'signal') {
+      report.notes.push(`${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}: ${oobAttempts} canary attempt(s) injected, durable OOB subscription pending (no callback inside the probe window).`)
+    }
     if (hyp.raceBurst) {
       const mode = typeof probe.details.raceMode === 'string' ? probe.details.raceMode : 'unmeasured'
       // Loud, structured transport note: a raced route that fell back to HTTP/1.1 must never look
```

The companion probe diff is already committed on this branch (`src/server/probes/{ssrf,xxe}.ts`):
each canary-carrying probe request sets `traceId` to the injected token, so the broker records
`X-Guardian-Trace-Id` in the local lab and the drain can find the carrier for a body-only injection.

## 3. Measured result with the patch applied

### Realism #2 (`--fixture wan-oob --no-llm --verifier docker`)

Artifacts: `/tmp/opencode/realism-1`.

- Engine: `hypothesesFormed=70`, `byClass=… xxe:0/6 ssrf:0/10 …`, 503 requests.
- **1 SSRF hypothesis** and **6 XXE hypotheses** reached the probe lane; 14+ canaries were minted
  before their sending request.
- **2 late callbacks** were promoted by the bounded drain and converted through ProofReceipt
  (`oob.receipt_confirmed` ×2):
  - `/v1/integrations/webhook-test` — CWE-918, `runtime_confirmed`, carrier exchange in
    `exchangeIds`;
  - `/v1/import/preview` — CWE-611, `runtime_confirmed`, carrier exchange in `exchangeIds`.
- The findings are present and confirmed (`vulnerabilityFindings=2`, `findingsSubmitted=2`), but the
  benchmark grades them as **unmatched false positives**.

### Exact remaining blocker (outside this stream's lease)

`receiptFindingTemplate` in `src/server/execution.ts` (≈ lines 1747–1773) persists the receipt
finding with the OWASP **category** strings `ssrf-redirects` / `injection-input`, while the realism
grader maps `finding.category` onto `vulnClass` (`scripts/benchmark-realism.ts:633`) and compares it
with the fixture truth (`ssrf`, `xxe`) via `classesCompatible`. The families do not overlap, so
`grade.reason = "no truth or decoy entry matches endpoint/method/class"`.

Minimal fix (engine-adjacent, one of):
1. `receiptFindingTemplate`: set `category: input.vulnClass` (`'ssrf'` / `'xxe'`) — the engine's own
   synthesized specs already use the canonical class as category (`detLeadCategory` + `baseFields`);
   or
2. the realism extractor: derive `vulnClass` from `cwe` (CWE-918→ssrf, CWE-611→xxe) before falling
   back to `category`.

With either change the same run should report `asyncSsrfConfirmed=true` and
`asyncXxeConfirmed=true`; no re-instrumentation is needed.

### Product floor (3-app, `Execution --no-llm`, seed 1)

Artifacts: `/tmp/opencode/floor-1`.

| Cell | Recall | Precision |
|---|---|---|
| acme-saas | 12/22 | 100% |
| shopflow | 11/19 | 100% |
| opsportal | 10/18 | 100% |
| **Total** | **33/59 (55.9%)** | **100%**, 0 decoy, 0 unmatched |

The two additional confirmations versus the 31/59 baseline are **XXE** (`acme` and `opsportal`
`xxe` targets, now 1/1 each): the route-family eligibility change converts previously-unreachable
XML sinks through their own synchronous replay. This is a recall gain, not a regression, but it is a
**floor move** and must be called out when landing (the 31/59 gate is a floor, not a cap).

Not yet re-measured with the patch (rerun when landing): held-out-saas 20/20 + 20/20 patches,
xben-25 25/25, salted held-out. The added hypotheses only extend the mutating XML/URL-query surface
and the trace header is local-lab-only, so the expected effect on those suites is neutral-to-positive,
but it is unmeasured.

## 4. Tests

Committed on this branch (`tests/v7-realism-oob.test.ts`, probe lane only):

- the SSRF probe sets `traceId` to each canary token it injects (http + dns), matching the durable
  `pending_oob` subscription tokens;
- the XXE probe does the same for general/parameter/SVG entity payloads and keeps
  `Content-Type: application/xml`;
- a recorded `x-guardian-trace-id` header makes the carrier exchange findable through
  `Store.searchExchanges`, which is the exact lookup the drain uses.

To restore with the engine patch (these were green in the patched tree, removed from the probe-only
commit because they depend on engine selection):

1. webhook/receiver write (`POST /svc/hooks/inbound`, empty harvest) forms SSRF hypotheses naming
   `url`/`callbackUrl`;
2. URL-shaped query param (`targetUri`) and observed URL body param (`destination`) select SSRF;
3. a fetch-verb route (`POST /svc/hooks/verify`) is its own second-order trigger (`triggerPath` =
   the write route);
4. XML-import families (`/svc/ingest/upload`, `/svc/batch/import`) form XXE, an unrelated write does
   not; observed XML evidence selects XXE on an opaque route;
5. `runDeterministicEngine` records the canary token as `traceId` on the carrying request and a
   pending attempt in `report.notes` when no callback arrives inside the window.

## 5. Re-run commands

```bash
# engine patch applied
GUARDIAN_ALLOW_LOCAL_LAB=1 newgrp docker -c \
  'node scripts/benchmark-realism.ts --fixture wan-oob --no-llm --verifier docker --out-dir /tmp/realism-oob --json'
GUARDIAN_ALLOW_LOCAL_LAB=1 newgrp docker -c \
  'node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm \
     --verifier docker --isolate-data-dir --concurrency 3 --budget-usd 2 \
     --max-duration-ms 600000 --out-dir /tmp/floor-oob'
```
