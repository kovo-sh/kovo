/**
 * v8 M0 — CompositeProofReceipt DAG verifier chaos & security suite.
 *
 * Covers:
 *  - All 4 causal edge bindings (pass + spoofed/tampered/out-of-order rejection)
 *  - DAG topology (cycles, self-loops, disconnected hops, 8-hop depth bound)
 *  - Host-signature tamper detection (HMAC-SHA256)
 *  - Attacker-origin provenance invariant (anti-shortcutting vs legitimate derived caps & control arms)
 *  - Strict Mode-A vs Mode-B enforcement (409/410/consumed-token vs benchmarkMode / 403 / 500 / missing controls)
 *  - Single-hop bridge parity (`singleReceiptToComposite`) with v7 `verifyReceipt`
 *  - LOC budget (<= 750) & anti-contamination lint (0 benchmark literals)
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  sha256Hex,
  signHostRecord,
  singleReceiptToComposite,
  verifyCompositeReceipt,
} from '../src/server/composite-receipt.ts'
import type {
  CompositeProofReceipt,
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostOobEvent,
  HostSignedTranscript,
  HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ImpactStep, ProofReceipt, ReceiptTranscript } from '../src/server/proof-receipt.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN_API = 'https://api.example.test'
const ORIGIN_IDP = 'https://idp.example.test'
const ORIGIN_APP = 'https://app.example.test'
const SIGNING_KEY = 'test-host-signing-key-v8-m0-composite'

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org-a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.secretMatches !== undefined ? { secretMatches: partial.secretMatches } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function makeEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  return {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
}

function signTranscript(transcript: HostSignedTranscript, key = SIGNING_KEY): HostSignedTranscript {
  return {
    entries: (transcript.entries ?? []).map(e => ({ ...e, hostSignature: signHostRecord(e, key) })),
    oobEvents: (transcript.oobEvents ?? []).map(o => ({ ...o, hostSignature: signHostRecord(o, key) })),
    browserTraces: (transcript.browserTraces ?? []).map(t => ({ ...t, hostSignature: signHostRecord(t, key) })),
    asyncPollRecords: (transcript.asyncPollRecords ?? []).map(p => ({ ...p, hostSignature: signHostRecord(p, key) })),
  }
}

// ============================================================================
// 0. LOC Budget & Anti-Contamination Lint
// ============================================================================

test('composite-receipt.ts meets <= 750 LOC budget and zero benchmark literals', () => {
  const src = readFileSync(join(repoRoot, 'src/server/composite-receipt.ts'), 'utf8')
  const lineCount = src.split('\n').length
  assert.ok(lineCount <= 750, `Expected <= 750 LOC, got ${lineCount}`)

  const forbidden = [
    /\bpaygrid\b/i,
    /\bshipforge\b/i,
    /\bnexusiam\b/i,
    /\bconnecthub\b/i,
    /\b(?:PG|SF|NX|CH)-C\d+\b/,
    /vault\.internal/i,
    /registry\.internal/i,
    /billing\.internal/i,
    /mh_fake_/i,
  ]
  for (const re of forbidden) {
    assert.equal(re.test(src), false, `Benchmark literal matched ${re} in src/server/composite-receipt.ts`)
  }
})

// ============================================================================
// 1. Edge Binding #1: value_binding
// ============================================================================

test('value_binding: passes on verbatim DerivedCapabilityHandle and rejects spoofed/out-of-order', () => {
  const cap = 'cap:hop_1:delegated_session'
  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-ctrl', makeStep({ id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/admin/export', json: { error: 'forbidden' } }), {
        timestampMs: 900,
        actorPersona: 'member_a',
      }),
      makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/preview', json: { preview: 'ok' } }), {
        timestampMs: 1000,
        actorPersona: 'member_a',
        emittedCapabilities: [cap],
      }),
      makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/export', json: { tenantId: 'org-b', records: [{ id: 'rec-1', amount: 4200 }] } }), {
        timestampMs: 1500,
        actorPersona: null,
        consumedCapabilities: [cap],
      }),
    ],
  }

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-vb-1',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/preview' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leaked delegated handle', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/admin/export' }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Used delegated handle for export', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Exported restricted tenant records', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const ok = verifyCompositeReceipt(receipt, signTranscript(transcript), {
    attackerPersonas: ['member_a'],
    signingKey: SIGNING_KEY,
  })
  assert.equal(ok.confirmed, true, ok.reason)
  assert.equal(ok.verifiedEdges.length, 1)
  assert.equal(ok.verifiedEdges[0]?.kind, 'value_binding')

  // Out-of-order timestamps (t_1 > t_2) MUST reject.
  const outOfOrder: HostSignedTranscript = {
    entries: [
      transcript.entries![0]!,
      { ...transcript.entries![1]!, timestampMs: 2000 },
      { ...transcript.entries![2]!, timestampMs: 1500 },
    ],
  }
  const badOrder = verifyCompositeReceipt(receipt, outOfOrder, { attackerPersonas: ['member_a'] })
  assert.equal(badOrder.confirmed, false)
  assert.equal(badOrder.failedStage, 'edge_binding')
  assert.match(badOrder.reason, /monotonic/i)

  // Spoofed capability handle not emitted in Hop 1 MUST reject.
  const spoofed: HostSignedTranscript = {
    entries: [
      transcript.entries![0]!,
      { ...transcript.entries![1]!, emittedCapabilities: [] },
      transcript.entries![2]!,
    ],
  }
  const badSpoof = verifyCompositeReceipt(receipt, spoofed, { attackerPersonas: ['member_a'] })
  assert.equal(badSpoof.confirmed, false)
  assert.equal(badSpoof.failedStage, 'edge_binding')
})

test('value_binding: passes on sha256(extractedValue) from response JSON -> Authorization Bearer header', () => {
  const syntheticToken = 'tok_synthetic_opaque_991122'
  const digest = sha256Hex(syntheticToken)
  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-ctrl', makeStep({ id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/admin/records', json: { error: 'forbidden' } }), {
        timestampMs: 1800,
        actorPersona: 'viewer_a',
      }),
      makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/token/preview', json: { issuedToken: syntheticToken } }), {
        timestampMs: 2000,
        actorPersona: 'viewer_a',
      }),
      makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/records', requestHeaders: { Authorization: `Bearer ${syntheticToken}` }, json: { records: [{ id: 'r1', balance: 9900 }] } }), {
        timestampMs: 2500,
        actorPersona: 'viewer_a',
      }),
    ],
  }
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-vb-digest',
    terminalVulnClass: 'bfla',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/token/preview' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Extracted token', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Replayed token', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', valueDigest: digest }],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Escalated access to restricted records', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  assert.equal(verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['viewer_a'] }).confirmed, true)

  // Tampered digest MUST reject.
  const wrongDigestReceipt = {
    ...receipt,
    causalEdges: [{ kind: 'value_binding' as const, fromHopId: 'h1', toHopId: 'h2', valueDigest: sha256Hex('different-value') }],
  }
  const res = verifyCompositeReceipt(wrongDigestReceipt, transcript, { attackerPersonas: ['viewer_a'] })
  assert.equal(res.confirmed, false)
  assert.equal(res.failedStage, 'edge_binding')
})

// ============================================================================
// 2. Edge Binding #2: derived_crypto_binding
// ============================================================================

test('derived_crypto_binding: verifies Layer-1 attestation and rejects missing/tampered/out-of-order', () => {
  const saltCap = 'cap:hop_1:signing_salt'
  const mintedJwtCap = 'cap:hop_2:forged_jwt'
  const payloadDigest = sha256Hex('{"sub":"service","scope":"settlement"}')

  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-ctrl', makeStep({ id: 'ex-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/settlement/execute', json: { error: 'forbidden' } }), {
        timestampMs: 900,
        actorPersona: 'member_a',
      }),
      makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/config/salt', json: { saltRef: 's1' } }), {
        timestampMs: 1000,
        actorPersona: 'member_a',
        emittedCapabilities: [saltCap],
      }),
      makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/idp/token', json: { token: 'minted' } }), {
        timestampMs: 1400,
        actorPersona: null,
        cryptoAttestations: [
          {
            derivedFromCapabilityId: saltCap,
            derivedCapabilityId: mintedJwtCap,
            alg: 'HS256',
            artifactDigest: payloadDigest,
            timestampMs: 1200,
          },
        ],
      }),
      makeEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/settlement/execute', json: { settlementId: 'stl-1', amountCents: 25000, status: 'settled' } }), {
        timestampMs: 1800,
        actorPersona: null,
        consumedCapabilities: [mintedJwtCap],
      }),
    ],
  }

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-crypto-1',
    terminalVulnClass: 'auth_bypass',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/config/salt' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leaked salt', producedCapabilities: [saltCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'idp', target: { origin: ORIGIN_IDP, pathAndQuery: '/idp/token' }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Signed JWT via Layer-1', producedCapabilities: [mintedJwtCap], consumedCapabilities: [] },
      { hopId: 'h3', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/settlement/execute' }, exchangeIds: ['ex-3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Executed privileged action with derived JWT', producedCapabilities: [], consumedCapabilities: [mintedJwtCap] },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: saltCap, derivedCapabilityId: mintedJwtCap, alg: 'HS256' },
      { kind: 'value_binding', fromHopId: 'h2', toHopId: 'h3', capabilityHandle: mintedJwtCap },
    ],
    terminalImpact: { terminalHopId: 'h3', claimedImpact: 'Forged service token accepted', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const ok = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['member_a'] })
  assert.equal(ok.confirmed, true, ok.reason)
  assert.equal(ok.verifiedEdges.length, 2)

  // Missing attestation MUST reject.
  const noAtt: HostSignedTranscript = {
    entries: [transcript.entries![0]!, transcript.entries![1]!, { ...transcript.entries![2]!, cryptoAttestations: [] }, transcript.entries![3]!],
  }
  assert.equal(verifyCompositeReceipt(receipt, noAtt, { attackerPersonas: ['member_a'] }).confirmed, false)

  // Out-of-order derivation timestamp (t_derive < t_source) MUST reject.
  const badDeriveTs: HostSignedTranscript = {
    entries: [
      transcript.entries![0]!,
      transcript.entries![1]!,
      {
        ...transcript.entries![2]!,
        cryptoAttestations: [{ ...transcript.entries![2]!.cryptoAttestations![0]!, timestampMs: 900 }],
      },
      transcript.entries![3]!,
    ],
  }
  const tsRes = verifyCompositeReceipt(receipt, badDeriveTs, { attackerPersonas: ['member_a'] })
  assert.equal(tsRes.confirmed, false)
  assert.equal(tsRes.failedStage, 'edge_binding')

  // Wrong algorithm MUST reject.
  const wrongAlg = {
    ...receipt,
    causalEdges: [
      { kind: 'derived_crypto_binding' as const, fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: saltCap, alg: 'HS512' },
      receipt.causalEdges[1]!,
    ],
  }
  assert.equal(verifyCompositeReceipt(wrongAlg, transcript, { attackerPersonas: ['member_a'] }).confirmed, false)
})

// ============================================================================
// 3. Edge Binding #3: state_transition_binding (Ablation Control)
// ============================================================================

test('state_transition_binding: passes on clean-session 403 ablation and rejects failing/spoofed ablation', () => {
  const entityId = 'draft-order-42'
  const makeTranscript = (ablationOverride: Partial<HostTranscriptEntry> = {}): HostSignedTranscript => ({
    entries: [
      makeEntry('ex-prime', makeStep({ id: 'ex-prime', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/orders/${entityId}` }), {
        timestampMs: 1000,
        actorPersona: 'member_a',
        entityId,
      }),
      makeEntry('ex-approve', makeStep({ id: 'ex-approve', arm: 'probe', method: 'POST', status: 200, pathAndQuery: `/api/orders/${entityId}/approve`, json: { id: entityId, status: 'approved', amountCents: 5000 } }), {
        timestampMs: 1500,
        actorPersona: 'member_a',
        entityId,
      }),
      makeEntry('ex-ablation', makeStep({ id: 'ex-ablation', arm: 'control', method: 'POST', status: 403, pathAndQuery: `/api/orders/${entityId}/approve` }), {
        timestampMs: 2000,
        actorPersona: 'member_a',
        entityId,
        cleanSession: true,
        replayAttempt: 'ablation_control',
        ...ablationOverride,
      }),
    ],
  })

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-state-1',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: `/api/orders/${entityId}` }, exchangeIds: ['ex-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Overwrote creator metadata', producedCapabilities: [], consumedCapabilities: [], entityId },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: `/api/orders/${entityId}/approve` }, exchangeIds: ['ex-approve'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Self-approved order', producedCapabilities: [], consumedCapabilities: [], entityId },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'h1', toHopId: 'h2', entityId, ablationExchangeIds: ['ex-ablation'] },
    ],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Maker-checker invariant bypassed', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  // Valid 403 ablation passes.
  assert.equal(verifyCompositeReceipt(receipt, makeTranscript(), { attackerPersonas: ['member_a'] }).confirmed, true)

  // Ablation returning 200 OK (Hop j works alone!) MUST reject.
  const ab200 = verifyCompositeReceipt(
    receipt,
    makeTranscript({ step: makeStep({ id: 'ex-ablation', arm: 'control', method: 'POST', status: 200, pathAndQuery: `/api/orders/${entityId}/approve` }) }),
    { attackerPersonas: ['member_a'] },
  )
  assert.equal(ab200.confirmed, false)
  assert.equal(ab200.failedStage, 'edge_binding')

  // Ablation returning 500 server error MUST reject.
  const ab500 = verifyCompositeReceipt(
    receipt,
    makeTranscript({ step: makeStep({ id: 'ex-ablation', arm: 'control', method: 'POST', status: 500, pathAndQuery: `/api/orders/${entityId}/approve` }) }),
    { attackerPersonas: ['member_a'] },
  )
  assert.equal(ab500.confirmed, false)

  // Ablation not in cleanSession MUST reject.
  const abDirty = verifyCompositeReceipt(receipt, makeTranscript({ cleanSession: false }), { attackerPersonas: ['member_a'] })
  assert.equal(abDirty.confirmed, false)

  // Ablation swapping actor persona (e.g. unauthenticated anon 401 masquerading for member_a) MUST reject.
  const abWrongActor = verifyCompositeReceipt(receipt, makeTranscript({ actorPersona: 'anon' }), { attackerPersonas: ['member_a', 'anon'] })
  assert.equal(abWrongActor.confirmed, false)
  assert.match(abWrongActor.reason, /actor/i)

  // Ablation reusing hop exchange ID MUST reject.
  const reuseReceipt = {
    ...receipt,
    causalEdges: [{ kind: 'state_transition_binding' as const, fromHopId: 'h1', toHopId: 'h2', entityId, ablationExchangeIds: ['ex-approve'] }],
  }
  assert.equal(verifyCompositeReceipt(reuseReceipt, makeTranscript(), { attackerPersonas: ['member_a'] }).confirmed, false)
})

// ============================================================================
// 4. Edge Binding #4: async_pivot_binding
// ============================================================================

test('async_pivot_binding: verifies poll_convergence, oob_relay, and browser_trace with monotonic checks', () => {
  const canary = 'canary-run-7741'
  const leakedCap = 'cap:hop_2:worker_token'
  const pollRec: HostAsyncPollRecord = {
    id: 'poll-1',
    triggerExchangeId: 'ex-trigger',
    tTriggerMs: 1000,
    tObservedMs: 2400,
    converged: true,
    correlationIds: [canary],
    emittedCapabilities: [leakedCap],
  }
  const oobRec: HostOobEvent = {
    id: 'oob-1',
    token: canary,
    delivered: true,
    receivedAtMs: 2200,
    correlationIds: [canary],
  }
  const traceRec: HostBrowserTrace = {
    id: 'trace-1',
    origin: ORIGIN_APP,
    sinks: ['dom_xss'],
    timestampMs: 2300,
    correlationIds: [canary],
  }

  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-trigger', makeStep({ id: 'ex-trigger', arm: 'probe', method: 'POST', status: 202, requestJson: { marker: canary } }), {
        timestampMs: 1000,
        actorPersona: 'member_a',
        correlationIds: [canary],
      }),
    ],
    oobEvents: [oobRec],
    browserTraces: [traceRec],
    asyncPollRecords: [pollRec],
  }

  // poll_convergence PASS
  const pollReceipt: CompositeProofReceipt = {
    chainId: 'chain-async-poll',
    terminalVulnClass: 'ssrf',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['ex-trigger'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Queued async export', producedCapabilities: [], consumedCapabilities: [], canaryToken: canary },
      { hopId: 'h2', surface: 'async_job', target: { origin: ORIGIN_API }, exchangeIds: [], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Worker converged with internal data', producedCapabilities: [leakedCap], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'h1', toHopId: 'h2', correlationId: canary, channel: 'poll_convergence', pollRecordId: 'poll-1' }],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Async worker fetched restricted resource', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }
  assert.equal(verifyCompositeReceipt(pollReceipt, transcript, { attackerPersonas: ['member_a'] }).confirmed, true)

  // oob_relay PASS
  const oobReceipt: CompositeProofReceipt = {
    ...pollReceipt,
    chainId: 'chain-async-oob',
    hops: [
      pollReceipt.hops[0]!,
      { hopId: 'h2', surface: 'webhook', target: { origin: ORIGIN_API }, exchangeIds: [], oobEventIds: ['oob-1'], browserTraceIds: [], claimedDelta: 'OOB callback received', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'h1', toHopId: 'h2', correlationId: canary, channel: 'oob_relay', oobEventId: 'oob-1' }],
  }
  assert.equal(verifyCompositeReceipt(oobReceipt, transcript, { attackerPersonas: ['member_a'] }).confirmed, true)

  // browser_trace PASS
  const browserReceipt: CompositeProofReceipt = {
    ...pollReceipt,
    chainId: 'chain-async-browser',
    hops: [
      pollReceipt.hops[0]!,
      { hopId: 'h2', surface: 'browser', target: { origin: ORIGIN_APP }, exchangeIds: [], oobEventIds: [], browserTraceIds: ['trace-1'], claimedDelta: 'Victim browser executed sink', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'h1', toHopId: 'h2', correlationId: canary, channel: 'browser_trace', browserTraceId: 'trace-1' }],
  }
  assert.equal(verifyCompositeReceipt(browserReceipt, transcript, { attackerPersonas: ['member_a'] }).confirmed, true)

  // Out-of-order OOB (receivedAtMs < trigger) MUST reject.
  const badOobTs: HostSignedTranscript = {
    ...transcript,
    oobEvents: [{ ...oobRec, receivedAtMs: 500 }],
  }
  const oobFail = verifyCompositeReceipt(oobReceipt, badOobTs, { attackerPersonas: ['member_a'] })
  assert.equal(oobFail.confirmed, false)
  assert.equal(oobFail.failedStage, 'edge_binding')

  // Unconverged poll MUST reject.
  const unconverged: HostSignedTranscript = {
    ...transcript,
    asyncPollRecords: [{ ...pollRec, converged: false }],
  }
  assert.equal(verifyCompositeReceipt(pollReceipt, unconverged, { attackerPersonas: ['member_a'] }).confirmed, false)
})

// ============================================================================
// 5. Attacker-Origin Provenance Invariant (Anti-Shortcutting)
// ============================================================================

test('attacker-origin provenance: rejects pre-seeded privileged persona shortcuts, allows control arms & derived caps', () => {
  const cap = 'cap:hop_1:escalated_token'
  const baseReceipt: CompositeProofReceipt = {
    chainId: 'chain-prov-1',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/token/mint' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/owner/vault' }, exchangeIds: ['ex-ctrl', 'ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read owner vault', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Escalated to owner vault', preChainControlExchangeIds: ['ex-pre-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  // Case A: Root is member_a, Hop 2 probe uses derived cap (actorPersona: null), owner_a ONLY in control arm -> PASS.
  const legitTranscript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-pre-ctrl', makeStep({ id: 'ex-pre-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/owner/vault', json: { error: 'forbidden' } }), { timestampMs: 900, actorPersona: 'member_a' }),
      makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/token/mint', json: { issued: true } }), { timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [cap] }),
      makeEntry('ex-ctrl', makeStep({ id: 'ex-ctrl', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/owner/vault', actor: { handle: 'owner_a', role: 'owner', tenant: 'org-a', auth: 'bearer', sameSite: null }, json: { vault: 'owner-secret' } }), { timestampMs: 1100, actorPersona: 'owner_a' }),
      makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/owner/vault', json: { vault: 'owner-secret', balanceCents: 99000 } }), { timestampMs: 1500, actorPersona: null, consumedCapabilities: [cap] }),
    ],
  }
  const legit = verifyCompositeReceipt(baseReceipt, legitTranscript, {
    attackerPersonas: ['member_a', 'viewer_a'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  })
  assert.equal(legit.confirmed, true, legit.reason)

  // Case B: Root starts as pre-seeded owner_a -> HARD REJECT.
  const rootShortcut: HostSignedTranscript = {
    entries: [
      legitTranscript.entries![0]!,
      { ...legitTranscript.entries![1]!, actorPersona: 'owner_a' },
      legitTranscript.entries![2]!,
      legitTranscript.entries![3]!,
    ],
  }
  const rRoot = verifyCompositeReceipt(baseReceipt, rootShortcut, {
    attackerPersonas: ['member_a', 'viewer_a'],
    forbiddenShortcutPersonas: ['owner_a'],
  })
  assert.equal(rRoot.confirmed, false)
  assert.equal(rRoot.failedStage, 'attacker_provenance')

  // Case C: Terminal probe shortcuts with pre-seeded owner_a EVEN WHILE carrying derived cap -> HARD REJECT.
  const termShortcut: HostSignedTranscript = {
    entries: [
      legitTranscript.entries![0]!,
      legitTranscript.entries![1]!,
      legitTranscript.entries![2]!,
      { ...legitTranscript.entries![3]!, actorPersona: 'owner_a' },
    ],
  }
  const rTerm = verifyCompositeReceipt(baseReceipt, termShortcut, {
    attackerPersonas: ['member_a', 'viewer_a'],
    forbiddenShortcutPersonas: ['owner_a'],
  })
  assert.equal(rTerm.confirmed, false)
  assert.equal(rTerm.failedStage, 'attacker_provenance')

  // Case D: Terminal probe executes with actorPersona: null and NO DAG-derived capability -> HARD REJECT.
  const noCapReceipt: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [
      baseReceipt.hops[0]!,
      { ...baseReceipt.hops[1]!, exchangeIds: ['ex-ctrl', 'ex-2', 'ex-3'] },
    ],
  }
  const noCapTranscript: HostSignedTranscript = {
    entries: [
      ...legitTranscript.entries!,
      makeEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'POST', status: 200 }), { timestampMs: 1600, actorPersona: null, consumedCapabilities: ['cap:foreign:unproven'] }),
    ],
  }
  const rNoCap = verifyCompositeReceipt(noCapReceipt, noCapTranscript, { attackerPersonas: ['member_a'] })
  assert.equal(rNoCap.confirmed, false)
  assert.equal(rNoCap.failedStage, 'attacker_provenance')
})

// ============================================================================
// 6. Strict Mode-A vs Mode-B Enforcement
// ============================================================================

test('Mode-B (one_shot_transcript): allowed on genuine 409/410/consumed-token, rejected in benchmarkMode or on 403/500', () => {
  const cap = 'cap:hop_1:invite_code'
  const buildModeB = (
    modeAStatus: number,
    modeABody?: string,
    opts?: { benchmarkModeReceipt?: boolean; dropPreControl?: boolean; dropReadback?: boolean },
  ) => {
    const transcript: HostSignedTranscript = {
      entries: [
        makeEntry('ex-pre-ctrl', makeStep({ id: 'ex-pre-ctrl', arm: 'control', method: 'GET', status: 403, route: '/api/org/roles', pathAndQuery: '/api/org/roles' }), {
          timestampMs: 900,
          actorPersona: 'member_a',
        }),
        makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/invites/pending' }), {
          timestampMs: 1000,
          actorPersona: 'member_a',
          emittedCapabilities: [cap],
        }),
        makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'POST', status: 200, route: '/api/org/roles', pathAndQuery: '/api/org/roles' }), {
          timestampMs: 1500,
          actorPersona: 'member_a',
          consumedCapabilities: [cap],
        }),
        makeEntry('ex-readback', makeStep({ id: 'ex-readback', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/org/roles', json: { role: 'admin' } }), {
          timestampMs: 1800,
          actorPersona: 'member_a',
        }),
        makeEntry('ex-modea-fail', makeStep({ id: 'ex-modea-fail', arm: 'probe', method: 'POST', status: modeAStatus, body: modeABody, pathAndQuery: '/api/org/roles' }), {
          timestampMs: 2200,
          actorPersona: 'member_a',
          cleanSession: true,
          replayAttempt: 'mode_a',
        }),
      ],
    }

    const receipt: CompositeProofReceipt = {
      chainId: 'chain-modeb',
      terminalVulnClass: 'privilege_escalation',
      hops: [
        { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/invites/pending' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Found one-time invite', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/api/org/roles' }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeemed one-time invite', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'h2',
        claimedImpact: 'Role upgraded via one-shot invite',
        preChainControlExchangeIds: opts?.dropPreControl ? [] : ['ex-pre-ctrl'],
        postChainReadbackExchangeIds: opts?.dropReadback ? [] : ['ex-readback'],
        modeAFailureExchangeId: 'ex-modea-fail',
      },
      replayMode: 'one_shot_transcript',
      ...(opts?.benchmarkModeReceipt !== undefined ? { benchmarkMode: opts.benchmarkModeReceipt } : {}),
    }
    return { receipt, transcript }
  }

  // Genuine 409 Conflict -> PASS
  const c409 = buildModeB(409)
  const r409 = verifyCompositeReceipt(c409.receipt, c409.transcript, { attackerPersonas: ['member_a'] })
  assert.equal(r409.confirmed, true, r409.reason)
  assert.equal(r409.modeBVerified, true)

  // Genuine 410 Gone -> PASS
  const c410 = buildModeB(410)
  assert.equal(verifyCompositeReceipt(c410.receipt, c410.transcript, { attackerPersonas: ['member_a'] }).confirmed, true)

  // Genuine 422 consumed-token error -> PASS
  const c422 = buildModeB(422, '{"error":"invite already redeemed"}')
  assert.equal(verifyCompositeReceipt(c422.receipt, c422.transcript, { attackerPersonas: ['member_a'] }).confirmed, true)

  // HARD REJECT in benchmarkMode (via receipt flag OR options flag) even with valid 409!
  const benchReceipt = buildModeB(409, undefined, { benchmarkModeReceipt: true })
  const rBench1 = verifyCompositeReceipt(benchReceipt.receipt, benchReceipt.transcript, { attackerPersonas: ['member_a'] })
  assert.equal(rBench1.confirmed, false)
  assert.equal(rBench1.failedStage, 'replay_mode')

  const rBench2 = verifyCompositeReceipt(c409.receipt, c409.transcript, { attackerPersonas: ['member_a'], benchmarkMode: true })
  assert.equal(rBench2.confirmed, false)
  assert.equal(rBench2.failedStage, 'replay_mode')

  // HARD REJECT on generic 403 or 500 (even if body mentions consumed!)
  for (const status of [403, 500, 404, 200]) {
    const bad = buildModeB(status, '{"error":"token_consumed"}')
    const r = verifyCompositeReceipt(bad.receipt, bad.transcript, { attackerPersonas: ['member_a'] })
    assert.equal(r.confirmed, false, `Status ${status} must not allow Mode B`)
    assert.equal(r.failedStage, 'replay_mode')
  }

  // HARD REJECT when pre-chain denied control or post-chain readback is missing.
  const noPre = buildModeB(409, undefined, { dropPreControl: true })
  assert.equal(verifyCompositeReceipt(noPre.receipt, noPre.transcript, { attackerPersonas: ['member_a'] }).failedStage, 'replay_mode')

  const noRead = buildModeB(409, undefined, { dropReadback: true })
  assert.equal(verifyCompositeReceipt(noRead.receipt, noRead.transcript, { attackerPersonas: ['member_a'] }).failedStage, 'replay_mode')
})

// ============================================================================
// 7. DAG Topology, Tamper Detection & 8-Hop Depth Bound
// ============================================================================

test('DAG topology & host-signature tamper detection fail closed', () => {
  const cap1 = 'cap:h1:tok'
  const cap2 = 'cap:h2:tok'
  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('e1', makeStep({ id: 'e1', arm: 'probe', method: 'GET', status: 200 }), { timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [cap1], consumedCapabilities: [cap2] }),
      makeEntry('e2', makeStep({ id: 'e2', arm: 'probe', method: 'GET', status: 200 }), { timestampMs: 1100, actorPersona: 'member_a', emittedCapabilities: [cap2], consumedCapabilities: [cap1] }),
    ],
  }

  // Cycle h1 -> h2 -> h1 MUST reject.
  const cyclic: CompositeProofReceipt = {
    chainId: 'chain-cycle',
    terminalVulnClass: 'bfla',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['e1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'hop 1', producedCapabilities: [cap1], consumedCapabilities: [cap2] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['e2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'hop 2', producedCapabilities: [cap2], consumedCapabilities: [cap1] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap1 },
      { kind: 'value_binding', fromHopId: 'h2', toHopId: 'h1', capabilityHandle: cap2 },
    ],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'cyclic', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }
  const cycRes = verifyCompositeReceipt(cyclic, transcript, { attackerPersonas: ['member_a'] })
  assert.equal(cycRes.confirmed, false)
  assert.equal(cycRes.failedStage, 'dag_topology')

  // Tampered hostSignature MUST reject.
  const signed = signTranscript(transcript)
  const tampered: HostSignedTranscript = {
    ...signed,
    entries: [
      { ...signed.entries![0]!, actorPersona: 'viewer_a' }, // mutated after signing!
      signed.entries![1]!,
    ],
  }
  const acyclic: CompositeProofReceipt = {
    ...cyclic,
    chainId: 'chain-tamper',
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap1 }],
  }
  const tampRes = verifyCompositeReceipt(acyclic, tampered, { attackerPersonas: ['member_a', 'viewer_a'], signingKey: SIGNING_KEY })
  assert.equal(tampRes.confirmed, false)
  assert.equal(tampRes.failedStage, 'transcript_integrity')
})

test('deep 8-hop DAG confirms while 9-hop receipt is rejected by schema', () => {
  const hops: CompositeProofReceipt['hops'] = []
  const edges: CompositeProofReceipt['causalEdges'] = []
  const entries: HostTranscriptEntry[] = [
    makeEntry('ex-ctrl', makeStep({ id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/vault/final', json: { error: 'forbidden' } }), {
      timestampMs: 900,
      actorPersona: 'member_a',
    }),
  ]

  for (let i = 1; i <= 8; i++) {
    const prevCap = i > 1 ? `cap:h${i - 1}:tok` : undefined
    const nextCap = i < 8 ? `cap:h${i}:tok` : undefined
    const pq = i === 8 ? '/api/vault/final' : `/api/step/${i}`
    entries.push(
      makeEntry(`ex-${i}`, makeStep({
        id: `ex-${i}`, arm: 'probe', method: 'GET', status: 200, pathAndQuery: pq,
        ...(i === 8 ? { json: { tenantId: 'org-b', records: [{ id: 'rec-8', balanceCents: 12000 }] } } : {}),
      }), {
        timestampMs: 1000 + i * 100,
        actorPersona: i === 1 ? 'member_a' : null,
        ...(prevCap ? { consumedCapabilities: [prevCap] } : {}),
        ...(nextCap ? { emittedCapabilities: [nextCap] } : {}),
      }),
    )
    hops.push({
      hopId: `h${i}`,
      surface: 'http',
      target: { origin: ORIGIN_API, pathAndQuery: pq },
      exchangeIds: [`ex-${i}`],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `Hop ${i}`,
      producedCapabilities: nextCap ? [nextCap] : [],
      consumedCapabilities: prevCap ? [prevCap] : [],
    })
    if (prevCap) {
      edges.push({ kind: 'value_binding', fromHopId: `h${i - 1}`, toHopId: `h${i}`, capabilityHandle: prevCap })
    }
  }

  const receipt8: CompositeProofReceipt = {
    chainId: 'chain-8hop',
    terminalVulnClass: 'cross_tenant_read',
    hops,
    causalEdges: edges,
    terminalImpact: { terminalHopId: 'h8', claimedImpact: '8-hop chain confirmed', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }
  const ok8 = verifyCompositeReceipt(receipt8, { entries }, { attackerPersonas: ['member_a'] })
  assert.equal(ok8.confirmed, true, ok8.reason)
  assert.equal(ok8.hopCount, 8)

  // 9 hops MUST fail schema validation.
  const receipt9 = { ...receipt8, hops: [...hops, { ...hops[7]!, hopId: 'h9' }] }
  const bad9 = verifyCompositeReceipt(receipt9, { entries })
  assert.equal(bad9.confirmed, false)
  assert.equal(bad9.failedStage, 'schema')
})

// ============================================================================
// 8. Single-Hop Bridge Parity (`singleReceiptToComposite`)
// ============================================================================

test('singleReceiptToComposite preserves exact confirmation parity with v7 verifyReceipt', () => {
  const validBolaReceipt: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/invoices/inv-900' },
    exchangeIds: ['ctrl-owner', 'probe-other'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Member from org-b read org-a private invoice',
    resourceTenant: 'org-a',
  }

  // Plain v7 ReceiptTranscript (no v8 timestampMs needed for 1-hop bridge!).
  const v7Transcript: ReceiptTranscript = {
    entries: [
      {
        exchangeId: 'ctrl-owner',
        step: makeStep({
          id: 'ctrl-owner',
          arm: 'control',
          method: 'GET',
          status: 200,
          route: '/api/invoices/:id',
          pathAndQuery: '/api/invoices/inv-900',
          actor: { handle: 'owner_a', role: 'owner', tenant: 'org-a', auth: 'bearer', sameSite: null },
          json: { id: 'inv-900', tenantId: 'org-a', ownerEmail: 'owner@org-a.test', amount: 4200 },
        }),
      },
      {
        exchangeId: 'probe-other',
        step: makeStep({
          id: 'probe-other',
          arm: 'probe',
          method: 'GET',
          status: 200,
          route: '/api/invoices/:id',
          pathAndQuery: '/api/invoices/inv-900',
          actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
          json: { id: 'inv-900', tenantId: 'org-a', ownerEmail: 'owner@org-a.test', amount: 4200 },
        }),
      },
    ],
  }

  const v7Pass = verifyReceipt(validBolaReceipt, v7Transcript)
  const composite = singleReceiptToComposite(validBolaReceipt)
  const v8Pass = verifyCompositeReceipt(composite, v7Transcript, {
    attackerPersonas: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a'],
  })
  assert.equal(v7Pass.confirmed, true, v7Pass.reason)
  assert.equal(v8Pass.confirmed, true, v8Pass.reason)
  assert.equal(v8Pass.hopCount, 1)
  assert.equal(v8Pass.terminalVerification?.confirmed, true)

  // Denied BOLA probe -> BOTH v7 verifyReceipt and v8 composite verifier reject!
  const deniedTranscript: ReceiptTranscript = {
    entries: [
      v7Transcript.entries![0]!,
      {
        exchangeId: 'probe-other',
        step: makeStep({
          id: 'probe-other',
          arm: 'probe',
          method: 'GET',
          status: 403,
          route: '/api/invoices/:id',
          pathAndQuery: '/api/invoices/inv-900',
          actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
          json: { error: 'forbidden' },
        }),
      },
    ],
  }
  const v7Deny = verifyReceipt(validBolaReceipt, deniedTranscript)
  const v8Deny = verifyCompositeReceipt(composite, deniedTranscript, { attackerPersonas: ['member_b'] })
  assert.equal(v7Deny.confirmed, false)
  assert.equal(v8Deny.confirmed, false)
  assert.equal(v8Deny.failedStage, 'terminal_impact')
  assert.equal(v8Deny.reason, v7Deny.reason)

  // Single-hop bridge still blocks attacker-origin shortcut (probe running as owner_a).
  const cheatedProbe: ReceiptTranscript = {
    entries: [
      v7Transcript.entries![0]!,
      {
        ...v7Transcript.entries![1]!,
        step: {
          ...v7Transcript.entries![1]!.step,
          actor: { handle: 'owner_a', role: 'owner', tenant: 'org-a', auth: 'bearer', sameSite: null },
        },
      },
    ],
  }
  const v8Cheat = verifyCompositeReceipt(composite, cheatedProbe, {
    attackerPersonas: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a'],
  })
  assert.equal(v8Cheat.confirmed, false)
  assert.equal(v8Cheat.failedStage, 'attacker_provenance')
})

// ============================================================================
// 9. Full 5-Hop Combined DAG (All 4 Edge Bindings + Signed Transcript + Oracle)
// ============================================================================

test('combined 5-hop signed DAG exercising all 4 edge bindings + custom terminal oracle + disconnected hop check', () => {
  const cap1 = 'cap:h1:preview_token'
  const cap2 = 'cap:h2:signed_assertion'
  const entityId = 'export-job-901'
  const canary = 'run-canary-5hop-88'

  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-1', makeStep({ id: 'ex-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/preview' }), {
        timestampMs: 1000, actorPersona: 'viewer_a', emittedCapabilities: [cap1],
      }),
      makeEntry('ex-2', makeStep({ id: 'ex-2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/idp/exchange' }), {
        timestampMs: 1300, actorPersona: null,
        cryptoAttestations: [{ derivedFromCapabilityId: cap1, derivedCapabilityId: cap2, alg: 'HS256', artifactDigest: sha256Hex('assertion'), timestampMs: 1200 }],
      }),
      makeEntry('ex-3', makeStep({ id: 'ex-3', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/jobs/${entityId}` }), {
        timestampMs: 1600, actorPersona: null, consumedCapabilities: [cap2], entityId,
      }),
      makeEntry('ex-4', makeStep({ id: 'ex-4', arm: 'probe', method: 'POST', status: 202, pathAndQuery: `/api/jobs/${entityId}/run`, requestJson: { canary } }), {
        timestampMs: 1900, actorPersona: null, consumedCapabilities: [cap2], entityId, correlationIds: [canary],
      }),
      makeEntry('ex-ablation', makeStep({ id: 'ex-ablation', arm: 'control', method: 'POST', status: 403, pathAndQuery: `/api/jobs/${entityId}/run` }), {
        timestampMs: 2500, actorPersona: 'viewer_a', entityId, cleanSession: true, replayAttempt: 'ablation_control',
      }),
    ],
    asyncPollRecords: [{
      id: 'poll-5hop', triggerExchangeId: 'ex-4', tTriggerMs: 1900, tObservedMs: 2400, converged: true, correlationIds: [canary],
    }],
  }

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-5hop-all-edges',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leaked preview signing handle', producedCapabilities: [cap1], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'idp', target: { origin: ORIGIN_IDP }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Derived assertion via Layer-1', producedCapabilities: [cap2], consumedCapabilities: [] },
      { hopId: 'h3', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['ex-3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed job state', producedCapabilities: [], consumedCapabilities: [cap2], entityId },
      { hopId: 'h4', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['ex-4'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Triggered async export', producedCapabilities: [], consumedCapabilities: [cap2], entityId, canaryToken: canary },
      { hopId: 'h5', surface: 'async_job', target: { origin: ORIGIN_API }, exchangeIds: [], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Async worker converged with cross-tenant output', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: cap1, derivedCapabilityId: cap2, alg: 'HS256' },
      { kind: 'value_binding', fromHopId: 'h2', toHopId: 'h3', capabilityHandle: cap2 },
      { kind: 'state_transition_binding', fromHopId: 'h3', toHopId: 'h4', entityId, ablationExchangeIds: ['ex-ablation'] },
      { kind: 'async_pivot_binding', fromHopId: 'h4', toHopId: 'h5', correlationId: canary, channel: 'poll_convergence', pollRecordId: 'poll-5hop' },
    ],
    terminalImpact: { terminalHopId: 'h5', claimedImpact: 'Cross-tenant export converged', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const signed = signTranscript(transcript)
  const ok = verifyCompositeReceipt(receipt, signed, {
    attackerPersonas: ['viewer_a'],
    forbiddenShortcutPersonas: ['owner_a'],
    signingKey: SIGNING_KEY,
    verifyTerminalImpact: () => ({ confirmed: true, reason: 'custom v8 oracle confirmed', family: 'cross_surface_pivot' }),
  })
  assert.equal(ok.confirmed, true, ok.reason)
  assert.equal(ok.verifiedEdges.length, 4)

  // Custom terminal oracle rejection fails closed.
  const oracleDeny = verifyCompositeReceipt(receipt, signed, {
    attackerPersonas: ['viewer_a'],
    signingKey: SIGNING_KEY,
    verifyTerminalImpact: () => ({ confirmed: false, reason: 'hardened twin preserved invariant' }),
  })
  assert.equal(oracleDeny.confirmed, false)
  assert.equal(oracleDeny.failedStage, 'terminal_impact')

  // Disconnected floating hop MUST reject at dag_topology.
  const withFloating: CompositeProofReceipt = {
    ...receipt,
    hops: [...receipt.hops, { hopId: 'h_float', surface: 'http', target: { origin: ORIGIN_API }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Unconnected hop', producedCapabilities: [], consumedCapabilities: [] }],
  }
  const floatRes = verifyCompositeReceipt(withFloating, signed, { attackerPersonas: ['viewer_a'], signingKey: SIGNING_KEY })
  assert.equal(floatRes.confirmed, false)
  assert.equal(floatRes.failedStage, 'dag_topology')

  // Mode A explicit cleanSession: false on probe MUST reject at replay_mode.
  const dirtyModeA = signTranscript({
    ...transcript,
    entries: [{ ...transcript.entries![0]!, cleanSession: false }, ...transcript.entries!.slice(1)],
  })
  const dirtyRes = verifyCompositeReceipt(receipt, dirtyModeA, { attackerPersonas: ['viewer_a'], signingKey: SIGNING_KEY })
  assert.equal(dirtyRes.confirmed, false)
  assert.equal(dirtyRes.failedStage, 'replay_mode')
})
