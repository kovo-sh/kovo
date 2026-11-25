# Multi-Hop Chain Playbook
Tags: multihop, multi-hop, chaining, chain, capability-ledger, composite-receipt, hop-checkpoint, derived-custody, async-pivot, hardened-twin
Summary: Verify 3-6 hop CompositeProofReceipt chains via ctx.seal_capability, ctx.hmac_sign/jwt_sign, ctx.await_async, and ctx.prove_composite.

## 1. Quick-Reference Contract
1. **Origin (No Collusion):** Use `verifiedHops`/`cap:hop_<id>:<slot>`. ALL probe hops run as ONE low-priv/anonymous/derived persona; NEVER `owner`/`admin`/target-tenant on probe arm.
2. **Seal & Continue (No Premature Filing):** NEVER stop at single-hop disclosure/handle/directory leaks -> `ctx.seal_capability` & run Hops 2-4 in SAME script; no Hop-2 stubs!
3. **Crypto:** `ctx.hmac_sign({ secretHandle, payload, alg })` | `ctx.jwt_sign({ secretHandle, claims, alg, slot })` -> `derived_crypto_binding`.
4. **Async:** `ctx.await_async({ pollRequest, matchPredicate, triggerExchangeId, correlationId })` -> `async_pivot_binding`.
5. **DAG/Twins:** `ctx.prove_composite` (`fresh_clean_replay`) + `ctx.result`; blocked -> `record_coverage(proofGapReason="invariant_enforced_hardened")`.

## 2. Working from a Pre-Hydrated `hopCheckpoint`
Your `AssignmentBrief` may include a bounded (`<= 2 KB`) `hopCheckpoint` object:
- `branchKey`, `depth`, `targetHop`, `mode` (`"pivot"` | `"fuse"` | `"discover"` | `"sweep"`): identifies the active frontier branch and the hop you must advance.
- `verifiedHops[]` and `capabilityHandles[]`: host-verified parent hops and their opaque `cap:hop_<id>:<slot>` handles.
- `nextGoal`: target surface (`http`, `graphql`, `ws`, `sse`, `browser`, `webhook`, `async_job`, `idp`, `cdn`, `storage`), service origin, endpoint, `hypothesisClass`, and `expectedBinding`.
- `prunedBranches[]`: surfaces already falsified by negative controls — do NOT re-probe pruned branches.
- `doNotRediscover: true`: spend Turn 1 advancing `targetHop` from the checkpoint instead of repeating earlier discovery steps.

## 3. Layer-1 Derived Capability Custody (`ctx.seal_capability`)
Whenever a host-signed HTTP exchange, GraphQL response, SSE event, browser trace, or async readback yields a reusable credential or authorization artifact (bearer token, API key, session cookie, signed URL, OIDC assertion, signing salt, or HMAC key):
1. Call `ctx.seal_capability` inside your `guardian_verify` script to seal the artifact in host-side `DerivedCapabilityVault` custody:
   - TS inputs: `{ exchange | exchangeId, slot, hopReceiptId?, hopId?, jsonPath | header | cookie | regex | value, kind?, ttlMs?, allowedOrigins?, defaultHeaderName?, defaultCookieName? }` (at least one extraction selector — `jsonPath`, `header`, `cookie`, `regex`, or `value` — is required).
   - Python inputs: `ctx.seal_capability(exchange_or_id, slot, hop_receipt_id=..., json_path=..., header=..., cookie=..., regex=..., value=..., kind=..., ttl_ms=..., default_header_name=..., default_cookie_name=..., allowed_origins=...)`.
   - Output: `{ handle, meta, exchangeId, sealExchangeId, scrubbedPreview }` where `handle` is opaque `cap:hop_<id>:<slot>` and `meta.sha256Prefix` holds the truncated digest (raw bytes remain host-side and are scrubbed from prompts/transcripts).
2. Inject the sealed capability into Hop `k+1` via Layer-1 request options: `ctx.http_send(target, { capability: "cap:hop_<id>:<slot>", capabilityTarget?: "bearer" | "header" | "cookie" | "url", capabilityHeaderName?, capabilityCookieName?, capabilityQueryParam?, role: "probe" })` (or `{ capability: { handle, target?, headerName?, cookieName?, queryParam? } }`).
3. Layer 1 performs the injection host-side and records `consumedCapabilityId` in the host-signed transcript, enabling deterministic `value_binding` verification.

## 4. Host-Side Cryptographic Derivation (`ctx.hmac_sign` / `ctx.jwt_sign`)
When a multi-hop workflow requires signing a webhook body, token, or request with a sealed `hmac_key` / `signing_salt` (`cap:hop_<id>:<slot>`), stay in the **same script** after sealing Hop 1–2 and execute Hops 3–5 directly:
- **HMAC signing (1-line pattern):** `const sig = await ctx.hmac_sign({ secretHandle: cap.handle, payload, alg: "sha256", encoding: "hex" })` (supports `sha256`/`sha384`/`sha512`, `hex`/`base64`/`base64url`; Python: `ctx.hmac_sign(secret_handle, payload, alg="sha256", encoding="hex")`). Returns `{ exchangeId, signature, handle, derivedHandle, attestation: { derivedFromCapabilityId, alg, encoding, payloadDigest, signatureDigest, sourceSecretDigest, runId, timestampMs } }`.
- **JWT signing (1-line pattern):** `const minted = await ctx.jwt_sign({ secretHandle: cap.handle, claims, alg: "HS256", hopReceiptId: "2", slot: "jwt" })` (optional `header`, `ttlMs`, `allowedOrigins`; supports `HS256`/`HS384`/`HS512`; Python: `ctx.jwt_sign(secret_handle, claims, alg="HS256", header=..., hop_receipt_id=..., slot=...)`). Returns `{ exchangeId, derivedHandle, handle, token, attestation: { derivedFromCapabilityId, derivedHandle, ... } }`, sealing the minted token as child `derivedHandle` (`cap:hop_<id>:<slot>`, aliased as `handle` / `token`).
- Both helpers emit a host-signed `derivedFromCapabilityId` attestation in the transcript so `derived_crypto_binding` verifies end-to-end lineage without exposing raw key bytes to the worker.
- For cryptographic scope-replay verification, always capture three host-signed observations:
  1. Tampered/invalid signature is rejected (`401`/`403`) — rules out signature-skip decoys.
  2. Valid signature/token is obtained legitimately under `(tenantB, scopeB)`.
  3. Replaying that valid signature/token under `(tenantA, scopeA)` is accepted across the boundary.

## 5. Bounded Async Worker Pivots (`ctx.await_async`)
For asynchronous cross-service hops (document/PDF renderers, webhook delivery logs, batch export workers, async queues, or simulated review-bot workflows) where side effects converge on an internal service rather than an external OOB collector:
- **Do NOT stop at Hop 2:** Obtaining a job/export ID, queued status, or signed URL is an intermediate capability — seal it with `ctx.seal_capability`, poll with `ctx.await_async` or fetch the derived URL in the **same script** to prove unauthorized foreign-tenant data exposure or privileged state mutation, and only then call `ctx.prove_composite`!
- Trigger the async action in Hop `i` and pass `triggerExchangeId: triggerEx.exchangeId` (or `tTriggerMs`) plus run-scoped `correlationId` / `entityId`.
- **1-line pattern:** `const pol = await ctx.await_async({ pollRequest, matchPredicate, profile: "fast_lab", triggerExchangeId: h1.exchangeId, correlationId: id })` (optional `timeoutMs`, `intervalMs`, `maxAttempts`, `tTriggerMs`, `correlationIds`, `entityId`; profiles `"fast_lab"` | `"wan"`; Python: `ctx.await_async(poll_request, match_predicate=..., profile=..., timeout_ms=..., interval_ms=..., trigger_exchange_id=..., correlation_id=..., entity_id=...)`):
  - `fast_lab`: default/max `5,000 ms` (`150 ms` interval).
  - `wan`: default/max `30,000 ms` (`500 ms` interval).
  - `matchPredicate` supports `{ status?, bodyContains?, bodyMatches?, jsonPath?, equals?, in?, matches?, header?: { name, equals?, matches? } }`.
- Returns `{ pollRecordId, converged, status, exchangeId, exchange, evidence }`. Layer 1 enforces strict monotonic ordering (`tTriggerMs <= tObservedMs`) and records an auditable `HostAsyncPollRecord` (`pollRecordId`) for `async_pivot_binding`.
- Never use unbounded sleep loops; if convergence times out cleanly, record the negative observation rather than fabricating state.

## 6. Submitting a `CompositeProofReceipt` DAG (`ctx.prove_composite`)
A multi-hop finding confirms ONLY when `ctx.prove_composite` verifies a complete `CompositeProofReceipt` DAG strictly over host-signed transcripts:

```ts
// Mode-A defensive verification shape (all IDs reference host-signed transcript records)
const preDenied = await ctx.http_send('/api/v1/terminal', { as: 'member_b', role: 'control' })
const ex1 = await ctx.http_send('/api/v1/resource-meta', { as: 'member_b', role: 'probe' })
const cap1 = await ctx.seal_capability({ exchange: ex1, hopReceiptId: '1', slot: 'scoped_tok', jsonPath: '$.token', kind: 'bearer_token' })
const postReadback = await ctx.http_send('/api/v1/terminal', { capability: cap1.handle, role: 'probe' })
await ctx.prove_composite({
  chainId: 'chain-authz-pivot-1',
  terminalVulnClass: 'dual_tenant_abac', // canonical terminal class
  replayMode: 'fresh_clean_replay',      // Mode A mandatory default
  hops: [
    {
      hopId: 'hop_1',
      surface: 'http',
      target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/resource-meta' },
      exchangeIds: [ex1.exchangeId],
      claimedDelta: 'Attacker persona obtains scoped capability handle from Hop 1.',
      producedCapabilities: [cap1.handle],
      consumedCapabilities: [],
    },
    {
      hopId: 'hop_2',
      surface: 'http',
      target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/terminal' },
      exchangeIds: [postReadback.exchangeId],
      claimedDelta: 'Attacker crosses terminal boundary using sealed Hop 1 capability.',
      producedCapabilities: [],
      consumedCapabilities: [cap1.handle],
    },
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap1.handle },
  ],
  terminalImpact: {
    terminalHopId: 'hop_2',
    claimedImpact: 'Unauthorized cross-tenant read/mutation confirmed on terminal resource.',
    preChainControlExchangeIds: [preDenied.exchangeId],
    postChainReadbackExchangeIds: [postReadback.exchangeId],
  },
})
return ctx.result({ title: 'Multi-hop cross-tenant capability pivot' })
```

### Copy-Pasteable 4-Hop Crypto + Async Recipe (`seal_capability` -> `hmac_sign`/`jwt_sign` + `await_async` -> `prove_composite`)
Use this exact pattern whenever a chain crosses signing, token-forgery, or background-job boundaries (all probe-arm hops run as ONE low-privilege starting persona `member_b`; never stop at the Hop 1 disclosure):

```ts
// Pre-chain denied control on the exact terminal route (401/403/404)
const preDenied = await ctx.http_send('/api/v1/exports/foreign-item', { as: 'member_b', role: 'control' })
// Hop 1: low-priv persona retrieves intermediate signing material (seal it; do NOT file as standalone CWE-200)
const h1 = await ctx.http_send('/api/v1/service-meta', { as: 'member_b', role: 'probe' })
const keyCap = await ctx.seal_capability({ exchange: h1, hopReceiptId: '1', slot: 'signing_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
// Hop 2: derive host-attested HMAC signature (or forged JWT via ctx.jwt_sign) and trigger async job
const payload = JSON.stringify({ action: 'export', tenant: 'target_org', correlationId: 'corr-1' })
const sig = await ctx.hmac_sign({ secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex' })
// For token forgery instead of HMAC:
// const minted = await ctx.jwt_sign({ secretHandle: keyCap.handle, claims: { sub: 'svc', role: 'admin' }, alg: 'HS256', hopReceiptId: '2', slot: 'forged_jwt' })
const h2 = await ctx.http_send('/api/v1/webhooks/trigger', {
  method: 'POST', as: 'member_b', role: 'probe',
  headers: { 'x-signature': sig.signature, 'content-type': 'application/json' },
  body: payload, correlationIds: ['corr-1'],
})
const jobCap = await ctx.seal_capability({ exchange: h2, hopReceiptId: '2', slot: 'job_id', jsonPath: '$.jobId' })
// Hop 3: bounded host-tracked async convergence (never unbounded sleeps; never stop at the job handle)
const pol = await ctx.await_async({
  pollRequest: { path: '/api/v1/jobs/status?corr=corr-1', as: 'member_b', role: 'probe' },
  matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
  triggerExchangeId: h2.exchangeId, correlationId: 'corr-1', profile: 'fast_lab',
})
const exportCap = await ctx.seal_capability({ exchange: pol.exchange, hopReceiptId: '3', slot: 'export_tok', jsonPath: '$.downloadToken', kind: 'bearer_token' })
// Hop 4: terminal cross-tenant readback via derived capability
const postReadback = await ctx.http_send('/api/v1/exports/foreign-item', { capability: exportCap.handle, role: 'probe' })
await ctx.prove_composite({
  chainId: 'chain-crypto-async-4hop',
  terminalVulnClass: 'cross_surface_pivot',
  replayMode: 'fresh_clean_replay',
  hops: [
    { hopId: 'hop_1', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/service-meta' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Low-priv persona obtains intermediate signing material.', producedCapabilities: [keyCap.handle], consumedCapabilities: [] },
    { hopId: 'hop_2', surface: 'webhook', target: { origin: ctx.targetOrigin, method: 'POST', pathAndQuery: '/api/v1/webhooks/trigger' }, exchangeIds: [sig.exchangeId, h2.exchangeId], claimedDelta: 'Host-attested HMAC signature triggers privileged async export job.', producedCapabilities: [jobCap.handle], consumedCapabilities: [keyCap.handle] },
    { hopId: 'hop_3', surface: 'async_job', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/jobs/status?corr=corr-1' }, exchangeIds: [pol.exchangeId], claimedDelta: 'Async worker converges and yields export capability.', producedCapabilities: [exportCap.handle], consumedCapabilities: [jobCap.handle] },
    { hopId: 'hop_4', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/exports/foreign-item' }, exchangeIds: [postReadback.exchangeId], claimedDelta: 'Terminal cross-tenant business record retrieved via derived capability.', producedCapabilities: [], consumedCapabilities: [exportCap.handle] },
  ],
  causalEdges: [
    { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap.handle, alg: 'sha256' },
    { kind: 'async_pivot_binding', fromHopId: 'hop_2', toHopId: 'hop_3', correlationId: 'corr-1', channel: 'poll_convergence', pollRecordId: pol.pollRecordId },
    { kind: 'value_binding', fromHopId: 'hop_3', toHopId: 'hop_4', capabilityHandle: exportCap.handle },
  ],
  terminalImpact: {
    terminalHopId: 'hop_4',
    claimedImpact: 'Unauthorized cross-tenant business record retrieved via 4-hop signing + async worker pivot.',
    preChainControlExchangeIds: [preDenied.exchangeId],
    postChainReadbackExchangeIds: [postReadback.exchangeId],
  },
})
return ctx.result({ title: '4-hop cross-service signing and async export pivot' })
```

### The 4 Typed Causal Edge Bindings
Every non-root hop must connect causally via host-signed transcript evidence:
1. **`value_binding`:** `{ kind: "value_binding", fromHopId, toHopId, capabilityHandle?, valueDigest?, sourceExchangeId?, targetExchangeId? }` — verbatim `cap:hop_<id>:<slot>` handle or `sha256(extractedValue)` observed in Hop `i` output and injected into Hop `j` request (`t_i <= t_j`).
2. **`derived_crypto_binding`:** `{ kind: "derived_crypto_binding", fromHopId, toHopId, sourceCapabilityId, derivedCapabilityId?, alg? }` — backed by a host-signed `derivedFromCapabilityId` attestation from `ctx.hmac_sign`, `ctx.jwt_sign`, or host-tracked token exchange.
3. **`state_transition_binding`:** `{ kind: "state_transition_binding", fromHopId, toHopId, entityId, ablationExchangeIds: [cleanAblation.exchangeId], mutationKind? }` — Hop `i` mutates shared entity/cache state without issuing a new token; **`ablationExchangeIds` is MANDATORY** and must prove in a clean session that running Hop `j` *without* Hop `i` fails cleanly (`401`/`403`/`404`/`409`/`412`/`422`), whereas `Hop i -> Hop j` succeeds.
4. **`async_pivot_binding`:** `{ kind: "async_pivot_binding", fromHopId, toHopId, correlationId, channel: "poll_convergence" | "oob_relay" | "browser_trace" | "async_job", pollRecordId? | oobEventId? | browserTraceId? }` — connects trigger Hop `i` to downstream effect Hop `j` with monotonic timestamps (`t_i <= t_j`) and run-scoped correlation.

### Attacker-Origin Provenance & Replay Mode Discipline
- **Attacker-Origin Provenance (Anti-Shortcutting & No Cross-Tenant Probe-Arm Collusion):** ALL probe-arm hops MUST execute strictly under a SINGLE starting low-privilege persona (e.g., `member_a`, `viewer_a`, `member_b`, `dual_member`, or `anonymous` / freshly derived credential), and every subsequent privileged step must use either that same starting persona or a capability derived inside the DAG. NEVER use a pre-seeded privileged/owner persona (`owner_a`, `admin`) or a target-tenant persona on the probe arm to mint handles or tokens for your starting persona — target-tenant personas may appear ONLY in baseline, negative-control, or independent readback checks.
- **No Premature Single-Hop Filing:** Never stop at an intermediate single-hop info-disclosure, handle, or directory leak when downstream cross-service, auth, or state-machine pivots are reachable — seal it with `ctx.seal_capability(...)` and continue through Hops 2–4 to `ctx.prove_composite(...)`.
- **Mode A (`fresh_clean_replay`, mandatory default):** Re-executes the full DAG plus ablation controls in a clean session with fresh nonces. Always design renewable setup/probes so Mode A passes deterministically.
- **Mode B (`one_shot_transcript`):** Fail-closed fallback permitted only on irreversible non-benchmark production states where Mode A hits a verified consumed-state conflict (`409`/`410`) AND the original signed transcript has pre-chain denied control + 100% unbroken edge bindings + post-chain readback.

### v8 Terminal Impact Oracle Families
Verify terminal impact against the applicable invariant family:
- `dual_tenant_abac`: cross-tenant / dual-org role matrix violations or partial-authz batch operations.
- `temporal_revocation`: revoked/demoted credential denied (`401`/`403`) on primary surface yet honored on a secondary surface (SSE, async export, stale invite).
- `economic_conservation`: host-verified baseline -> sequence -> readback conservation violation (excess balance, refund > paid, unauthorized discount).
- `cryptographic_scope_replay`: tampered signature denied, valid `(tenantB, scopeB)` signature accepted under `(tenantA, scopeA)`.
- `parser_cache_differential`: clean control denied, parser-differential or cache-primed sequence succeeds.
- `cross_surface_pivot`: multi-surface chain spanning API/GraphQL, browser/review-bot traces, webhook/worker SSRF, or IdP redirects.

## 7. Hardened-Twin Discipline & Clean Settlement
Realistic hardened applications often expose benign or low-impact Hops 1–2 (metadata, opaque IDs, guard asymmetries, non-privileged diagnostic tokens) while enforcing the true security boundary at Hop 3 or Hop 4:
- **Quarantine Rule:** `opaque_object_ref`, `policy_asymmetry`, `write_sink_handle`, count/existence signals, and non-privileged intermediate handles remain strictly `promotionStatus: "capability_only"`.
- **Zero Standalone `CWE-200` Emissions:** NEVER report a standalone `CWE-200` (or informational exposure) finding for a quarantined intermediate capability when the downstream pivot fails to achieve terminal impact.
- **Clean Settlement on Enforced Invariants:** When Hop 3/4 rejects the pivot with a verified control (strict tenant/audience check, proper output escaping, tenant-scoped cache key, live revocation enforcement, `401`/`403`/`422` denial):
  1. Stop retrying after at most 2 failed pivot attempts on the same `(branch, targetSurface)` pair so negative-edge pruning prevents dead-end waste (`<= 5%`).
  2. Settle explicitly via:
     - `record_coverage(status="needs_follow_up", route="<METHOD /path>", proofGapReason="invariant_enforced_hardened")` (when documenting that earlier capabilities exist but the terminal invariant is enforced), OR
     - `record_coverage(status="ruled_out", route="<METHOD /path>", enforcingControl="<exchangeId or file:line>")`.
  3. Call `complete_intent` cleanly with `status: "ruled_out"` or `"partial"` and a concise evidence summary.
