# Multi-Hop Chain Playbook
Tags: multihop, hop-checkpoint, composite-receipt, derived-custody, async-pivot
Summary: Verify N-hop CompositeProofReceipt chains via ctx.chain and prove_composite.

## 1. Quick-Reference Contract
1. **Origin/Control:** Low-priv attacker ONLY (no victim/owner/admin); controls pass `{arm:"control"}` on `ctx.http`; minted: `kind:"bearer_token"`, `{capability:{handle,target:"bearer"}}`, OMIT `as`.
2. **One Script:** `http_request`/`kovo_http` first; NEVER seal-only `kovo_verify` (blocked after 2x), own-tenant/handle-stub proofs, or standalone `prove_*` — chain to `terminalHopId` via `ctx.chain`/`ctx.prove_composite`.
3. **Tools:** `ctx.seal_capability` (`jsonPath`/`header`/`cookie`/`value`, no `regex`), `ctx.hmac_sign`/`ctx.jwt_sign`, `ctx.await_async`, `ctx.prove_race_burst`.
4. **Class/Econ:** Match `terminalVulnClass` (dual-tenant->`dual_tenant_abac`); ablation=SAME actor (`arm:"control"`); `economic_conservation`: `baselineReadbackExchangeId`+`finalReadbackExchangeId`.
5. **DAG/Twins:** Declare EVERY causal hop (Hop 1->terminal) in `hops[]`->`terminalHopId` via `causalEdges[]`; `fresh_clean_replay`+`ctx.result`; `invariant_enforced_hardened`.

## 2. Working from a Pre-Hydrated `hopCheckpoint`
Your `AssignmentBrief` may include a bounded (`<= 2 KB`) `hopCheckpoint` object:
- `branchKey`, `depth`, `targetHop`, `mode` (`"pivot"` | `"fuse"` | `"discover"` | `"sweep"`): identifies the active frontier branch and the hop you must advance.
- `verifiedHops[]` and `capabilityHandles[]`: host-verified parent hops and their opaque `cap:hop_<id>:<slot>` handles.
- `nextGoal`: target surface (`http`, `graphql`, `ws`, `sse`, `browser`, `webhook`, `async_job`, `idp`, `cdn`, `storage`), service origin, endpoint, `hypothesisClass`, and `expectedBinding`.
- `prunedBranches[]`: surfaces already falsified by negative controls — do NOT re-probe pruned branches.
- `doNotRediscover: true`: spend Turn 1 advancing `targetHop` from the checkpoint instead of repeating earlier discovery steps.

## 3. Layer-1 Derived Capability Custody (`ctx.seal_capability`)
Whenever a host-signed HTTP exchange, GraphQL response, SSE event, browser trace, or async readback yields a reusable credential or authorization artifact (bearer token, API key, session cookie, signed URL, OIDC assertion, signing salt, or HMAC key):
1. Call `ctx.seal_capability` ONLY inside your complete end-to-end `kovo_verify` proof script ending in `ctx.prove_composite(...)` / `ctx.chain(...).prove()` — **NEVER** call `kovo_verify` just to checkpoint or seal a single hop (use `http_request` for discovery; repeated checkpoint-only `kovo_verify` calls are hard-blocked). Strict `camelCase` option keys:
   - Inputs: `{ exchange | exchangeId, slot, hopReceiptId?, jsonPath | header | cookie | value, kind?, ttlMs?, allowedOrigins?, defaultHeaderName?, defaultCookieName? }` (at least one structured extraction selector — `jsonPath`, `header`, `cookie` [from `Set-Cookie`], or `value` — is required; **NEVER pass `regex`** — regex extraction is retired by R2-C-3 and fails closed).
   - **2xx Status Guard:** ALWAYS assert `res.status >= 200 && res.status < 300` before calling `ctx.seal_capability(...)` so 4xx `{ error }` JSON does not fail `jsonPath` extraction.
   - **SSE / Non-JSON Extraction:** For `text/event-stream` (SSE), `Set-Cookie`, or header-borne responses, seal with structured `header`, `cookie`, or visible `value` selectors (never `regex`).
   - Output: `{ handle, meta, exchangeId, sealExchangeId, scrubbedPreview }` where `handle` is opaque `cap:hop_<id>:<slot>` and `meta.sha256Prefix` holds the truncated digest (raw bytes remain host-side and are scrubbed from prompts/transcripts).
2. Inject the sealed capability into Hop `k+1` via Layer-1 request options: `ctx.http_send(target, { capability: "cap:hop_<id>:<slot>", capabilityTarget?: "bearer" | "header" | "cookie" | "url", capabilityHeaderName?, capabilityCookieName?, capabilityQueryParam?, role: "probe" })` (or `{ capability: { handle, target?, headerName?, cookieName?, queryParam? } }`). `HttpOptions.role` accepts **ONLY** `'setup' | 'control' | 'probe' | 'cleanup'` — never pass persona names or proof roles like `'control_denied'`.
3. **Derived Session Token Injection Rule:** Whenever Hop `k` mints or exchanges a session token or bearer credential, seal it with `kind: "bearer_token"` and send Hop `k+1` with `{ capability: { handle, target: "bearer" }, role: "probe" }` (or `{ headers: { Authorization: "Bearer " + handle }, role: "probe" }`) and **OMIT `as` / `persona`** so the derived session authenticates cleanly without being confused with or overwritten by a pre-seeded persona.
4. Layer 1 performs the injection host-side and records `consumedCapabilityId` in the host-signed transcript, enabling deterministic `value_binding` verification.

## 4. Host-Side Cryptographic Derivation (`ctx.hmac_sign` / `ctx.jwt_sign`)
When a multi-hop workflow requires signing a webhook body, token, or request with a sealed `hmac_key` / `signing_salt` (`cap:hop_<id>:<slot>`), stay in the **same script** after sealing Hop 1–2 and execute Hops 3–5 directly:
- **HMAC signing (1-line pattern):** `const sig = await ctx.hmac_sign({ secretHandle: cap.handle, payload, alg: "sha256", encoding: "hex" })` (supports `sha256`/`sha384`/`sha512`, `hex`/`base64`/`base64url`). Returns `{ exchangeId, signature, handle, derivedHandle, attestation: { derivedFromCapabilityId, alg, encoding, payloadDigest, signatureDigest, sourceSecretDigest, runId, timestampMs } }`.
- **JWT signing (1-line pattern):** `const minted = await ctx.jwt_sign({ secretHandle: cap.handle, claims, alg: "HS256", hopReceiptId: "2", slot: "jwt" })` (optional `header`, `ttlMs`, `allowedOrigins`; supports `HS256`/`HS384`/`HS512`). Returns `{ exchangeId, derivedHandle, handle, token, attestation: { derivedFromCapabilityId, derivedHandle, ... } }`, sealing the minted token as child `derivedHandle` (`cap:hop_<id>:<slot>`, aliased as `handle` / `token`).
- Both helpers emit a host-signed `derivedFromCapabilityId` attestation in the transcript so `derived_crypto_binding` (or a `value_binding` edge referencing `keyCap.handle` / `minted.derivedHandle`) verifies end-to-end lineage from the secret-extraction hop to the signed-request hop without exposing raw key bytes to the worker. Include `[sig.exchangeId, h2.exchangeId]` (or `[minted.exchangeId, h2.exchangeId]`) in the signed-request hop's `exchangeIds`.
- For cryptographic scope-replay verification, always capture three host-signed observations:
  1. Tampered/invalid signature is rejected (`401`/`403`) — rules out signature-skip decoys.
  2. Valid signature/token is obtained legitimately under `(tenantB, scopeB)`.
  3. Replaying that valid signature/token under `(tenantA, scopeA)` is accepted across the boundary.

## 5. Bounded Async Worker Pivots (`ctx.await_async`)
For asynchronous cross-service hops (document/PDF renderers, webhook delivery logs, batch export workers, async queues, or simulated review-bot workflows) where side effects converge on an internal service rather than an external OOB collector:
- **Do NOT stop at intermediate artifacts (Stage 2 stubs):** Creating an async job/export ID, priming a shared cache, or generating a link/token/signed URL is ONLY an intermediate capability — seal it with `ctx.seal_capability`, continue in the **same verification script** through `ctx.await_async`, `ctx.hmac_sign`/`ctx.jwt_sign`, or `ctx.prove_race_burst` to reach the final foreign-tenant data readback or persisted state change, and only then call `ctx.prove_composite`!
- Trigger the async action in Hop `i` and pass `triggerExchangeId: triggerEx.exchangeId` (or `tTriggerMs`) plus run-scoped `correlationId` / `entityId`.
- **1-line pattern:** `const pol = await ctx.await_async({ pollRequest, matchPredicate, timeoutMs: 5000, intervalMs: 150, triggerExchangeId: h1.exchangeId, correlationId: id })` (optional `profile: "wan"`, `timeoutMs`, `intervalMs`, `maxAttempts`, `tTriggerMs`, `correlationIds`, `entityId`):
  - Default local timing: `timeoutMs: 5000` (`150 ms` interval).
  - `wan`: default/max `30,000 ms` (`500 ms` interval).
  - `matchPredicate` supports `{ status?, bodyContains?, bodyMatches?, jsonPath?, equals?, in?, matches?, header?: { name, equals?, matches? } }`.
- **Read job/export ID before polling & follow the artifact URL:** Extract the job/export ID from the creation exchange (`const jobId = h.json?.id ?? h.json?.jobId`), seal it (`ctx.seal_capability`), pass it into `pollRequest` + `correlationId`, and once `pol.converged` is true, read the download/artifact URL or token from the converged response and fetch it in a subsequent hop (never stop at the job creation or readiness stub!).
- Returns a flat object `{ pollRecordId, converged, status, exchangeId, exchange, evidence }` where `pol.status` is the convergence state (`"converged"`/`"timeout"`), `pol.exchangeId` is the converged HTTP exchange ID, and `pol.exchange` is the hydrated HTTP response (`status`, `json`, `text`, `body`, `headers` — pass `exchange: pol.exchange` or `exchangeId: pol.exchangeId` to `ctx.seal_capability`). Layer 1 enforces strict monotonic ordering (`tTriggerMs <= tObservedMs`) and records an auditable `HostAsyncPollRecord` (`pollRecordId`) for `async_pivot_binding`.
- Never use unbounded sleep loops; if convergence times out cleanly, record the negative observation rather than fabricating state.

## 6. Submitting a `CompositeProofReceipt` DAG (`ctx.chain` / `ctx.prove_composite`)
A multi-hop finding confirms ONLY when `ctx.prove_composite` verifies a complete `CompositeProofReceipt` DAG strictly over host-signed transcripts. **Prefer `ctx.chain({ chainId, terminalVulnClass })`**: it auto-tracks `hops[]`, `target`, `exchangeIds`, `producedCapabilities`, `consumedCapabilities`, and auto-wires `value_binding`, `derived_crypto_binding`, and `async_pivot_binding` edges without manual mismatch errors!

```ts
// PREFERRED one-shot Mode-A multi-hop builder (`ctx.chain` auto-wires hops & edges)
// Explore with http_request/kovo_http first; NEVER call kovo_verify just to seal a single hop.
// Pick terminalVulnClass matching actual impact: broken_access_control | privilege_escalation | stale_privilege_use | cross_tenant_export | ledger_overcredit | forged_settlement (only use dual_tenant_abac for cross-tenant ABAC with a terminal denied control).
const actor = 'actor_low' // low-priv attacker persona; negative control MUST pass { arm: 'control' } as SAME actor as toHop
const chain = ctx.chain({ chainId: 'chain-authz-pivot-1', terminalVulnClass: 'broken_access_control' })
const preDenied = await ctx.http('/api/v1/terminal', { as: actor, arm: 'control' })
chain.control(preDenied)

const cap1 = await chain.hop('hop_1', { claimedDelta: 'Obtained scoped capability from Hop 1.' }, async () => {
  const ex1 = await ctx.http_send('/api/v1/resource-meta', { as: actor, role: 'probe' })
  if (!(ex1.status >= 200 && ex1.status < 300)) throw new Error(`Hop 1 failed: ${ex1.status}`)
  return ctx.seal_capability({ exchange: ex1, hopReceiptId: 'hop_1', slot: 'scoped_tok', jsonPath: '$.token', kind: 'bearer_token' })
})

const postReadback = await chain.hop('hop_2', { claimedDelta: 'Crossed terminal boundary using Hop 1 capability.' }, () =>
  ctx.http_send('/api/v1/terminal', { capability: { handle: cap1.handle, target: 'bearer' }, role: 'probe' }),
)
chain.readback(postReadback)
await chain.prove({ claimedImpact: 'Unauthorized cross-tenant read confirmed via derived token.' })
return ctx.result({ title: 'Multi-hop cross-tenant capability pivot' })
```

- **Mandatory `ctx.prove_composite` Rule (Single-Script Mode-A; Never Seal-Only `kovo_verify` or Standalone Helpers After Setup Hops):** NEVER call `kovo_verify` just to seal/checkpoint a single hop (repeated checkpoint-only scripts are hard-blocked) — explore routes/parameters with `http_request`/`kovo_http` first, then execute Hop 1 -> Hop N + `ctx.chain(...).prove()` (or `ctx.prove_composite`) inside **ONE single script**. Always pass `{ arm: 'control' }` on negative-control `ctx.http(...)` calls. **NEVER** call standalone `ctx.prove_race_burst`, `ctx.prove_access_boundary`, or `ctx.prove_persisted_mutation` as your final proof whenever your verification script executes prerequisite setup hops (e.g., disclosure/extraction, token/session acquisition, parser differential, cache prime, state rebind, or async job polling) before the terminal impact. Even when the terminal hop is a concurrent race burst, execute the race burst inside the chain and wrap ALL prerequisite setup hops plus the terminal race hop inside `ctx.prove_composite` (calling standalone `prove_race_burst` records `hopCount = 0` and fails multi-hop chain confirmation).
- **Terminal Class Matching Rule (Match Actual Impact & Dual-Tenant Base Persona Rule):** Set `terminalVulnClass` to the actual terminal impact class (e.g., `broken_access_control`, `privilege_escalation`, `stale_privilege_use`, `cross_tenant_export`, `ledger_overcredit`, `forged_settlement`, `economic_conservation`, `cryptographic_scope_replay`, `parser_cache_differential`, `cross_surface_pivot`); when a chain begins from a shared/dual-tenant member persona crossing tenant boundaries into its non-admin tenant, use the specific cross-tenant / ABAC class (`dual_tenant_abac`, with a terminal denied control) rather than generic `broken_access_control`.
- **Complete Causal Hop Declaration Rule (Hop 1 Through Terminal):** Declare **EVERY** causal hop your verification script executed — from Hop 1 (entry disclosure/extraction) through every intermediate pivot, token/invite resolve, parser differential, cache prime, state rebind, signing, or async-poll hop to the terminal hop — in `prove_composite.hops[]` and connect them end-to-end with `causalEdges[]`. Omitting Hop 1 or any intermediate setup hop yields an incomplete receipt even when all hops executed in the transcript.
- **Strict-CamelCase Inline Schema (`prove_composite`):**
  - `hops[]`: `{ hopId, surface?, target: { origin, method, pathAndQuery }, exchangeIds, claimedDelta, producedCapabilities?, consumedCapabilities? }` — **`target` MUST be `{ origin, method, pathAndQuery }`, NOT a bare string, and `claimedDelta` is required!**
  - `causalEdges[]` (valid `kind` enum: `value_binding | derived_crypto_binding | state_transition_binding | async_pivot_binding`):
    - `kind: 'value_binding'` requires `capabilityHandle` (or `valueDigest`);
    - `kind: 'state_transition_binding'` requires `entityId` AND `ablationExchangeIds` (baseline exchange proving target fails before the state-mutating hop, executed as the **SAME actor/persona as `toHop`** with `{ arm: 'control' }` without the upstream prerequisite/capability!);
    - `kind: 'derived_crypto_binding'` requires `sourceCapabilityId`;
    - `kind: 'async_pivot_binding'` requires `correlationId` + `channel`.
  - `terminalImpact`: `{ terminalHopId, claimedImpact, preChainControlExchangeIds, postChainReadbackExchangeIds, oracleInput? }`.

```ts
// Mode-A defensive verification shape (all IDs reference host-signed transcript records)
const actor = 'actor_low' // SAME low-priv attacker persona for control/ablation and root probe
const preDenied = await ctx.http('/api/v1/terminal', { as: actor, arm: 'control' })
const ex1 = await ctx.http_send('/api/v1/resource-meta', { as: actor, role: 'probe' })
if (!(ex1.status >= 200 && ex1.status < 300)) throw new Error(`Hop 1 failed: ${ex1.status}`)
const cap1 = await ctx.seal_capability({ exchange: ex1, hopReceiptId: '1', slot: 'scoped_tok', jsonPath: '$.token', kind: 'bearer_token' })
const postReadback = await ctx.http_send('/api/v1/terminal', { capability: cap1.handle, role: 'probe' })
await ctx.prove_composite({
  chainId: 'chain-authz-pivot-1',
  terminalVulnClass: 'broken_access_control', // match actual terminal impact (dual_tenant_abac ONLY for cross-tenant ABAC w/terminal denied control)
  replayMode: 'fresh_clean_replay',           // Mode A mandatory default
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
Use this exact pattern whenever a chain crosses signing, token-forgery, or background-job boundaries (all probe-arm hops run as ONE low-privilege starting persona `actor_low`; never stop at the Hop 1 disclosure):

```ts
// Pre-chain denied control on the exact terminal route (401/403/404) — always pass { arm: 'control' }
const preDenied = await ctx.http('/api/v1/exports/foreign-item', { as: 'actor_low', arm: 'control' })
// Hop 1: low-priv persona retrieves intermediate signing material (seal it; do NOT file as standalone CWE-200)
const h1 = await ctx.http_send('/api/v1/service-meta', { as: 'actor_low', role: 'probe' })
if (!(h1.status >= 200 && h1.status < 300)) throw new Error(`Hop 1 failed: ${h1.status}`)
const keyCap = await ctx.seal_capability({ exchange: h1, hopReceiptId: '1', slot: 'signing_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
// Hop 2: derive host-attested HMAC signature (or forged JWT via ctx.jwt_sign) and trigger async job
const payload = JSON.stringify({ action: 'export', tenant: 'target_org', correlationId: 'corr-1' })
const sig = await ctx.hmac_sign({ secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex' })
// For token forgery instead of HMAC:
// const minted = await ctx.jwt_sign({ secretHandle: keyCap.handle, claims: { sub: 'svc', role: 'admin' }, alg: 'HS256', hopReceiptId: '2', slot: 'forged_jwt' })
const h2 = await ctx.http_send('/api/v1/webhooks/trigger', {
  method: 'POST', as: 'actor_low', role: 'probe',
  headers: { 'x-signature': sig.signature, 'content-type': 'application/json' },
  body: payload, correlationIds: ['corr-1'],
})
if (!(h2.status >= 200 && h2.status < 300)) throw new Error(`Hop 2 failed: ${h2.status}`)
const jobCap = await ctx.seal_capability({ exchange: h2, hopReceiptId: '2', slot: 'job_id', jsonPath: '$.jobId' })
// Hop 3: bounded host-tracked async convergence (never unbounded sleeps; never stop at the job handle)
const pol = await ctx.await_async({
  pollRequest: { path: '/api/v1/jobs/status?corr=corr-1', as: 'actor_low', role: 'probe' },
  matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
  triggerExchangeId: h2.exchangeId, correlationId: 'corr-1', timeoutMs: 5000, intervalMs: 150,
})
if (!pol.exchange || !(pol.exchange.status >= 200 && pol.exchange.status < 300)) throw new Error('Hop 3 async poll did not yield 2xx')
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
    { hopId: 'hop_3', surface: 'async_job', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/v1/jobs/status?corr=corr-1' }, exchangeIds: [pol.exchange.exchangeId], claimedDelta: 'Async worker converges and yields export capability.', producedCapabilities: [exportCap.handle], consumedCapabilities: [jobCap.handle] },
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

### The 4 Typed Causal Edge Bindings & Connected-DAG Rule (`dag_topology`)
- **Connected-DAG Rule (`dag_topology`):** Every hop listed in `hops[]` MUST be connected by `causalEdges[]` on a directed path reaching `terminalImpact.terminalHopId`. NEVER include unused or orphan exploratory hops in `hops[]` — keep baseline reads, pre-chain controls, and ablation probes in `preChainControlExchangeIds`, `postChainReadbackExchangeIds`, `ablationExchangeIds`, or `terminalImpact.oracleInput` rather than listing disconnected hops in `hops[]`.
- Every non-root hop must connect causally via host-signed transcript evidence:
1. **`value_binding`:** `{ kind: "value_binding", fromHopId, toHopId, capabilityHandle?, valueDigest?, sourceExchangeId?, targetExchangeId? }` — **requires `capabilityHandle` (or `valueDigest`)**: verbatim `cap:hop_<id>:<slot>` handle or `sha256(extractedValue)` observed in Hop `i` output and injected into Hop `j` request (`t_i <= t_j`).
2. **`derived_crypto_binding`:** `{ kind: "derived_crypto_binding", fromHopId, toHopId, sourceCapabilityId, derivedCapabilityId?, alg? }` — backed by a host-signed `derivedFromCapabilityId` attestation from `ctx.hmac_sign`, `ctx.jwt_sign`, or host-tracked token exchange.
3. **`state_transition_binding`:** `{ kind: "state_transition_binding", fromHopId, toHopId, entityId, ablationExchangeIds: [cleanAblation.exchangeId], mutationKind? }` — Hop `i` mutates shared entity/cache state without issuing a new token; **requires `entityId` AND `ablationExchangeIds` (baseline exchange proving target fails before the state-mutating hop!)** in a clean session (`cleanSession=true`) (`401`/`403`/`404`/`409`/`412`/`422`), whereas `Hop i -> Hop j` succeeds. **Same-Actor & Clean-Control Order Rule:** The ablation control MUST run as the **SAME actor/persona as `toHop`** (without the upstream prerequisite/capability — never hardcode a different persona!), and ALWAYS execute `const cleanAblation = await ctx.http('/api/v1/target', { as: '<same_actor_as_toHop>', arm: 'control', entityId })` **BEFORE** Stage 1 mutates shared/cache state (or against a fresh untouched sibling entity with matching `entityId`) — running the control *after* Stage 1 marks the session dirty (`cleanSession=false`) and fails `state_transition_binding`.
4. **`async_pivot_binding`:** `{ kind: "async_pivot_binding", fromHopId, toHopId, correlationId, channel: "poll_convergence" | "oob_relay" | "browser_trace" | "async_job", pollRecordId? | oobEventId? | browserTraceId? }` — connects trigger Hop `i` to downstream effect Hop `j` with monotonic timestamps (`t_i <= t_j`) and run-scoped correlation.

### White-Box Single-Script Consolidation (N-Hop Causal Workflows)
- Once source routes across services are known from code-audit facts, do **not** burn 10–15 turns probing isolated stages one by one. Explore with `http_request`/`kovo_http` first, NEVER call `kovo_verify` just to seal/checkpoint a single hop, and write **ONE cohesive `kovo_verify` script** that runs:
  1. **Clean Baseline Control (`{ arm: "control" }`):** BEFORE Stage 1 mutates any entity/cache state (or on a fresh untouched sibling entity), record both `preChainControlExchangeIds` and any `state_transition_binding` `ablationExchangeIds` under the **SAME actor/persona as `toHop`** with `{ arm: "control" }`.
  2. **N-hop causal chain (Hop 1 -> ... -> terminal hop):** Seal each intermediate capability (`ctx.seal_capability`), bridge signing/token boundaries (`ctx.hmac_sign`/`ctx.jwt_sign`), poll async convergence (`ctx.await_async`), or test concurrent settlement bursts (`ctx.prove_race_burst`) in the same script.
  3. **Terminal Verification (`ctx.chain(...).prove` / `ctx.prove_composite`):** Fetch the final foreign-tenant business record or persisted state-mutation readback (`postChainReadbackExchangeIds`) — never stopping at job creation, cache priming, or token/link stubs — then call `ctx.chain(...).prove(...)` or `ctx.prove_composite` and `return ctx.result(...)`.

### Attacker-Origin Provenance & Replay Mode Discipline
- **Attacker-Origin Provenance (Anti-Shortcutting & Never Use Privileged Victim Personas):** Conduct ALL attack-chain discovery and proving strictly using low-privilege/attacker persona(s) ONLY (e.g., `actor_low`, `actor_dual` targeting its non-admin tenant, or `anonymous` / freshly derived credential), and every subsequent privileged step must use either that same starting persona or a capability derived inside the DAG. NEVER send exploratory or attack-hop requests using pre-seeded privileged/victim/owner/admin personas (`actor_victim`, `admin`) or target-tenant personas as shortcuts to mint handles or tokens — reserve owner/admin personas strictly for negative-control comparison (`{ arm: 'control' }`) when required, and use shared/dual-tenant personas **ONLY** for cross-tenant chains targeting their non-admin tenant (using `dual_tenant_abac` rather than generic `broken_access_control`).
- **Push to Terminal Impact (No Own-Tenant Reads or Premature Intermediate-Hop Filing):** NEVER submit a proof for reading your own tenant's resource or stopping at an intermediate invite/token/metadata/job/export-handle mint or intermediate role/config write as `broken_access_control` — seal the gained capability with `ctx.seal_capability(...)` and always chain forward in ONE script to confirm cross-tenant/unauthorized victim impact on the terminal action (privileged state mutation, financial/approval action, or sensitive foreign-tenant secret/record readback) as `terminalHopId`.
- **Mode A (`fresh_clean_replay`, mandatory default):** Re-executes the full DAG plus ablation controls in a clean session with fresh nonces. Always design renewable setup/probes so Mode A passes deterministically.
- **Mode B (`one_shot_transcript`):** Fail-closed fallback permitted only on irreversible non-benchmark production states where Mode A hits a verified consumed-state conflict (`409`/`410`) AND the original signed transcript has pre-chain denied control + 100% unbroken edge bindings + post-chain readback.

### v8 Terminal Impact Oracle Families
Verify terminal impact against the applicable invariant family:
- `dual_tenant_abac`: cross-tenant / dual-org role matrix violations or partial-authz batch operations.
- `temporal_revocation`: revoked/demoted credential denied (`401`/`403`) on primary surface yet honored on a secondary surface (SSE, async export, stale invite).
- `economic_conservation`: host-verified baseline -> sequence -> readback conservation violation (`balance_minting`, `over_refund`, `underpaid_fulfillment`, `ineligible_discount`). **Required 3-step Baseline + Final Readback Pattern:**
  1. Read baseline balance/state **BEFORE** the chain (`role: "control"`), citing its `exchangeId` in `preChainControlExchangeIds` and `terminalImpact.oracleInput.baselineReadbackExchangeId`.
  2. Execute the mutating or race hops (`ctx.http_send` / `ctx.prove_race_burst`), citing their `exchangeId`s in `oracleInput.actionExchangeIds`.
  3. Read final balance/state **AFTER** the chain, citing its `exchangeId` in `postChainReadbackExchangeIds` and `terminalImpact.oracleInput.finalReadbackExchangeId`, and pass `{ equation, balancesBefore/balancesAfter/authorizedDeposits` (or `paidAmount`/`refundedAmounts`, `paidAmount`/`fulfilledValue`/`fulfillmentState`, `subtotalAmount`/`requiredThreshold`/`discountApplied`), `baselineReadbackExchangeId, finalReadbackExchangeId, actionExchangeIds }` in `terminalImpact.oracleInput` — the host automatically hydrates the host-signed `HostSignedRecord` objects directly from those exchange IDs (never fabricate `hostSignature` in script code).

```ts
// Economic conservation pattern (balance_minting / over_refund / underpaid_fulfillment / ineligible_discount)
const base = await ctx.http('/api/v1/ledger/balance', { as: 'actor_low', arm: 'control' })
const act1 = await ctx.http_send('/api/v1/ledger/credit', { method: 'POST', as: 'actor_low', role: 'probe', body: { amount: 100 } })
const after = await ctx.http('/api/v1/ledger/balance', { as: 'actor_low', arm: 'control' })
await ctx.prove_composite({
  chainId: 'chain-econ-conservation-1',
  terminalVulnClass: 'economic_conservation',
  replayMode: 'fresh_clean_replay',
  hops: [
    { hopId: 'hop_1', surface: 'http', target: { origin: ctx.targetOrigin, method: 'POST', pathAndQuery: '/api/v1/ledger/credit' }, exchangeIds: [act1.exchangeId], claimedDelta: 'Unconserved credit/payout executed.', producedCapabilities: [], consumedCapabilities: [] },
  ],
  causalEdges: [],
  terminalImpact: {
    terminalHopId: 'hop_1',
    claimedImpact: 'Final balance exceeds baseline + authorizedDeposits.',
    preChainControlExchangeIds: [base.exchangeId],
    postChainReadbackExchangeIds: [after.exchangeId],
    oracleInput: {
      equation: 'balance_minting',
      balancesBefore: { acct: (base.json as { balance?: number } | null | undefined)?.balance ?? 0 },
      balancesAfter: { acct: (after.json as { balance?: number } | null | undefined)?.balance ?? 0 },
      authorizedDeposits: 0,
      baselineReadbackExchangeId: base.exchangeId,
      finalReadbackExchangeId: after.exchangeId,
      actionExchangeIds: [act1.exchangeId],
    },
  },
})
```
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
