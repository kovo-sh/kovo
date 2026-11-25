# Multi-Hop Causal Chain Verification Playbook
Tags: multihop, multi-hop, chaining, chain, capability-ledger, composite-receipt, hop-checkpoint, derived-custody, async-pivot, hardened-twin
Summary: Verify 3-6 hop chains via ctx.seal_capability, ctx.hmac_sign/ctx.jwt_sign, ctx.await_async, and CompositeProofReceipt DAGs (ctx.prove_composite) with zero-FP hardened-twin discipline.

## 1. Quick-Reference Contract
1. **Checkpoint (`doNotRediscover: true`):** Start from `verifiedHops` and `cap:hop_<id>:<slot>`; never rediscover Hop 1.
2. **Seal (`ctx.seal_capability`):** Never echo raw tokens/cookies/salts/signed URLs; seal to `cap:hop_<id>:<slot>`.
3. **Derive (`ctx.hmac_sign` / `ctx.jwt_sign`):** Sign host-side from handles for `derivedFromCapabilityId` attestations.
4. **Async (`ctx.await_async`):** Poll internal workers/relays with monotonic `t_trigger <= t_observed`.
5. **DAG (`ctx.prove_composite`):** Submit a `CompositeProofReceipt` (1–8 hops) with typed edges + attacker-origin provenance.
6. **Hardened Twins:** NEVER emit standalone `CWE-200` on `capability_only` intermediates; settle enforced Hop 3/4 with `record_coverage(proofGapReason="invariant_enforced_hardened")`.

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
   - Inputs: `{ hopReceiptId, slot, kind, fromExchangeId | rawValue, allowedOrigins?, defaultHeaderName?, defaultCookieName? }`
   - Output: opaque handle `cap:hop_<id>:<slot>` plus truncated `sha256Prefix` (raw bytes remain host-side and are scrubbed from prompts/transcripts).
2. Inject the sealed capability into Hop `k+1` via Layer-1 request options (`capability: "cap:hop_<id>:<slot>"` targeting `bearer`, `header`, `cookie`, or `url`).
3. Layer 1 performs the injection host-side and records `consumedCapabilityId` in the host-signed transcript, enabling deterministic `value_binding` verification.

## 4. Host-Side Cryptographic Derivation (`ctx.hmac_sign` / `ctx.jwt_sign`)
When a multi-hop workflow requires signing a webhook body, token, or request with sealed `signing_material` (`cap:hop_<id>:<slot>`):
- **HMAC signing:** Call `ctx.hmac_sign({ secretHandle: "cap:hop_<id>:<slot>", payload, alg: "sha256" | "sha384" | "sha512", encoding: "hex" | "base64" | "base64url" })`.
- **JWT signing:** Call `ctx.jwt_sign({ secretHandle: "cap:hop_<id>:<slot>", claims, header?, alg: "HS256" | "HS384" | "HS512", hopReceiptId?, slot? })`. This seals the newly minted token as a child `derivedHandle` (`cap:hop_<id>:<slot>`) linked to the parent handle.
- Both helpers emit a host-signed `derivedFromCapabilityId` attestation in the transcript so `derived_crypto_binding` verifies end-to-end lineage without exposing raw key bytes to the worker.
- For cryptographic scope-replay verification, always capture three host-signed observations:
  1. Tampered/invalid signature is rejected (`401`/`403`) — rules out signature-skip decoys.
  2. Valid signature/token is obtained legitimately under `(tenantB, scopeB)`.
  3. Replaying that valid signature/token under `(tenantA, scopeA)` is accepted across the boundary.

## 5. Bounded Async Worker Pivots (`ctx.await_async`)
For asynchronous cross-service hops (document/PDF renderers, webhook delivery logs, batch export workers, async queues, or simulated review-bot workflows) where side effects converge on an internal service rather than an external OOB collector:
- Trigger the async action in Hop `i` and record the trigger exchange timestamp (`tTriggerMs`) and run-scoped `correlationId` / `entityId`.
- Call `ctx.await_async({ pollRequest, matchPredicate, profile: "fast_lab" | "wan", timeoutMs?, intervalMs?, correlationId })`:
  - `fast_lab`: default/max `5,000 ms` (`150 ms` interval).
  - `wan`: default/max `30,000 ms` (`500 ms` interval).
- Layer 1 enforces strict monotonic ordering (`tTriggerMs <= tObservedMs`) and records an auditable `HostAsyncPollRecord` (`pollRecordId`) for `async_pivot_binding`.
- Never use unbounded sleep loops; if convergence times out cleanly, record the negative observation rather than fabricating state.

## 6. Submitting a `CompositeProofReceipt` DAG (`ctx.prove_composite`)
A multi-hop finding confirms ONLY when `ctx.prove_composite` verifies a complete `CompositeProofReceipt` DAG strictly over host-signed transcripts:

```ts
// Conceptual defensive verification shape (all IDs reference host-signed transcript records)
await ctx.prove_composite({
  chainId: 'chain-authz-pivot-1',
  terminalVulnClass: 'dual_tenant_abac', // canonical terminal class
  replayMode: 'fresh_clean_replay',      // Mode A mandatory default
  hops: [
    {
      hopId: 'hop-1',
      surface: 'http',
      target: { origin, method: 'GET', pathAndQuery: '/api/v1/resource-meta' },
      exchangeIds: [ex1.exchangeId],
      claimedDelta: 'Attacker persona obtains scoped capability handle from Hop 1.',
      producedCapabilities: ['cap:hop_1:scoped_tok'],
      consumedCapabilities: [],
    },
    // ... Hop 2 .. Hop N (1..8 hops, acyclic DAG)
  ],
  causalEdges: [
    // Link every dependent hop using one of the 4 typed bindings below
  ],
  terminalImpact: {
    terminalHopId: 'hop-n',
    claimedImpact: 'Unauthorized cross-tenant read/mutation confirmed on terminal resource.',
    preChainControlExchangeIds: [preDenied.exchangeId],
    postChainReadbackExchangeIds: [postReadback.exchangeId],
  },
})
```

### The 4 Typed Causal Edge Bindings
Every non-root hop must connect causally via host-signed transcript evidence:
1. **`value_binding`:** `{ kind: "value_binding", fromHopId, toHopId, capabilityHandle?, valueDigest?, sourceExchangeId?, targetExchangeId? }` — verbatim `cap:hop_<id>:<slot>` handle or `sha256(extractedValue)` observed in Hop `i` output and injected into Hop `j` request (`t_i <= t_j`).
2. **`derived_crypto_binding`:** `{ kind: "derived_crypto_binding", fromHopId, toHopId, sourceCapabilityId, derivedCapabilityId?, alg? }` — backed by a host-signed `derivedFromCapabilityId` attestation from `ctx.hmac_sign`, `ctx.jwt_sign`, or host-tracked token exchange.
3. **`state_transition_binding`:** `{ kind: "state_transition_binding", fromHopId, toHopId, entityId, ablationExchangeIds: [cleanAblation.exchangeId], mutationKind? }` — Hop `i` mutates shared entity/cache state without issuing a new token; **`ablationExchangeIds` is MANDATORY** and must prove in a clean session that running Hop `j` *without* Hop `i` fails cleanly (`401`/`403`/`404`/`409`/`412`/`422`), whereas `Hop i -> Hop j` succeeds.
4. **`async_pivot_binding`:** `{ kind: "async_pivot_binding", fromHopId, toHopId, correlationId, channel: "poll_convergence" | "oob_relay" | "browser_trace" | "async_job", pollRecordId? | oobEventId? | browserTraceId? }` — connects trigger Hop `i` to downstream effect Hop `j` with monotonic timestamps (`t_i <= t_j`) and run-scoped correlation.

### Attacker-Origin Provenance & Replay Mode Discipline
- **Attacker-Origin Provenance (Anti-Shortcutting):** Root hops MUST execute strictly under an attacker-eligible low-privilege persona (e.g., `member_a`, `viewer_a`, `member_b`, `dual_member`, `anonymous`), and every subsequent privileged step must use either that attacker persona or a capability derived inside the DAG. Pre-seeded privileged/owner personas (`owner_a`, `admin`) may appear ONLY in setup, negative-control, or victim arms — never as an execution shortcut.
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
